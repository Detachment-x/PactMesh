use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::Context;
use rand::{Rng, seq::SliceRandom};
use tokio::{net::UdpSocket, sync::RwLock};
use tokio_util::task::AbortOnDropHandle;
use tracing::Level;

use crate::{
    common::{PeerId, global_ctx::ArcGlobalCtx, stun::StunInfoCollectorTrait, upnp},
    connector::udp_hole_punch::{
        common::{
            HOLE_PUNCH_PACKET_BODY_LEN, send_symmetric_hole_punch_packet, try_connect_with_socket,
        },
        handle_rpc_result,
    },
    defer,
    peers::peer_manager::PeerManager,
    proto::{
        peer_rpc::{
            SelectPunchListenerRequest, SendPunchPacketEasySymRequest,
            SendPunchPacketHardSymRequest, SendPunchPacketHardSymResponse, UdpHolePunchRpc,
            UdpHolePunchRpcClientFactory,
        },
        rpc_types::{self, controller::BaseController},
    },
    tunnel::{Tunnel, udp::new_hole_punch_packet},
};

use super::common::{PunchHoleServerCommon, UdpNatType, UdpSocketArray};

const UDP_ARRAY_SIZE_FOR_HARD_SYM: usize = 84;
const MAX_EASY_SYM_MAPPING_PROBES: usize = 32;
const EASY_SYM_MAPPING_TIMEOUT_MS: u64 = 2500;
const PUNCH_RESULT_GRACE_MS: u128 = 2000;

// ZeroTier-parity stable-socket punch: only attempted when our NAT keeps a
// near-stable per-destination mapping (observed STUN port spread within this
// bound), so one reused socket's mapped port is enough for the peer to target.
const STABLE_PUNCH_SPREAD_MAX: u32 = 64;
// Use a wider centered spray than the STUN-observed spread: some symmetric NATs
// shift the mapped port further when the destination changes from STUN to peer.
const STABLE_PUNCH_WINDOW: u32 = 4096;
const STABLE_PUNCH_WAIT_MS: u128 = 3000;

const HARD_SYM_RANDOM_PASSES: usize = 2;
const HARD_SYM_RANDOM_PORTS_PER_PASS_MIN: u32 = 2048;
const HARD_SYM_RANDOM_PORTS_PER_PASS_MAX: u32 = 3072;

fn easy_sym_predict_window(observed_span: u32) -> u32 {
    observed_span
        .saturating_add((UDP_ARRAY_SIZE_FOR_HARD_SYM as u32) * 16)
        .saturating_add(512)
        .clamp(1024, 4096)
}

fn port_range_to_vec(start: u32, end: u32) -> Vec<u16> {
    let start = start.max(1);
    let end = end.min(u16::MAX as u32);
    if end < start {
        return Vec::new();
    }

    (start..=end).map(|port| port as u16).collect()
}

fn easy_sym_target_ports(base_port_num: u32, max_port_num: u32, is_incremental: bool) -> Vec<u16> {
    let max_port_num = max_port_num.max(1);
    if is_incremental {
        port_range_to_vec(
            base_port_num.saturating_add(1),
            base_port_num.saturating_add(max_port_num),
        )
    } else {
        port_range_to_vec(
            base_port_num.saturating_sub(max_port_num),
            base_port_num.saturating_sub(1),
        )
    }
}

pub(crate) struct PunchSymToConeHoleServer {
    common: Arc<PunchHoleServerCommon>,

    shuffled_port_vec: Arc<Vec<u16>>,
}

impl PunchSymToConeHoleServer {
    pub(crate) fn new(common: Arc<PunchHoleServerCommon>) -> Self {
        let mut shuffled_port_vec: Vec<u16> = (1..=65535).collect();
        shuffled_port_vec.shuffle(&mut rand::thread_rng());

        Self {
            common,
            shuffled_port_vec: Arc::new(shuffled_port_vec),
        }
    }

    // hard sym means public port is random and cannot be predicted
    #[tracing::instrument(skip(self), ret)]
    pub(crate) async fn send_punch_packet_easy_sym(
        &self,
        request: SendPunchPacketEasySymRequest,
    ) -> Result<(), rpc_types::error::Error> {
        tracing::info!("send_punch_packet_easy_sym start");

        let listener_addr = request.listener_mapped_addr.ok_or(anyhow::anyhow!(
            "send_punch_packet_easy_sym request missing listener_addr"
        ))?;
        let listener_addr = std::net::SocketAddr::from(listener_addr);
        let listener = self
            .common
            .find_listener(&listener_addr)
            .await
            .ok_or(anyhow::anyhow!(
                "send_punch_packet_easy_sym failed to find listener"
            ))?;

        let public_ips = request
            .public_ips
            .into_iter()
            .map(std::net::Ipv4Addr::from)
            .collect::<Vec<_>>();
        if public_ips.is_empty() {
            tracing::warn!("send_punch_packet_easy_sym got zero len public ip");
            return Err(
                anyhow::anyhow!("send_punch_packet_easy_sym got zero len public ip").into(),
            );
        }

        let transaction_id = request.transaction_id;
        let base_port_num = request.base_port_num;
        let max_port_num = request.max_port_num.max(1);
        let is_incremental = request.is_incremental;

        let ports = easy_sym_target_ports(base_port_num, max_port_num, is_incremental);
        if ports.is_empty() {
            return Err(anyhow::anyhow!("send_punch_packet_easy_sym invalid port range").into());
        }

        let port_start = ports.first().copied().unwrap();
        let port_end = ports.last().copied().unwrap();
        tracing::debug!(
            port_start,
            port_end,
            port_count = ports.len(),
            ?public_ips,
            "send_punch_packet_easy_sym send to ports"
        );

        for _ in 0..2 {
            send_symmetric_hole_punch_packet(
                &ports,
                listener.clone(),
                transaction_id,
                &public_ips,
                0,
                ports.len(),
            )
            .await
            .with_context(|| "failed to send symmetric hole punch packet")?;
        }

        Ok(())
    }

    // hard sym means public port is random and cannot be predicted
    #[tracing::instrument(skip(self))]
    pub(crate) async fn send_punch_packet_hard_sym(
        &self,
        request: SendPunchPacketHardSymRequest,
    ) -> Result<SendPunchPacketHardSymResponse, rpc_types::error::Error> {
        tracing::info!("try_punch_symmetric start");

        let listener_addr = request.listener_mapped_addr.ok_or(anyhow::anyhow!(
            "try_punch_symmetric request missing listener_addr"
        ))?;
        let listener_addr = std::net::SocketAddr::from(listener_addr);
        let listener = self
            .common
            .find_listener(&listener_addr)
            .await
            .ok_or(anyhow::anyhow!(
                "send_punch_packet_for_cone failed to find listener"
            ))?;

        let public_ips = request
            .public_ips
            .into_iter()
            .map(std::net::Ipv4Addr::from)
            .collect::<Vec<_>>();
        if public_ips.is_empty() {
            tracing::warn!("try_punch_symmetric got zero len public ip");
            return Err(anyhow::anyhow!("try_punch_symmetric got zero len public ip").into());
        }

        let transaction_id = request.transaction_id;
        let last_port_index = request.port_index as usize;

        let round = std::cmp::max(request.round, 1);

        let ports_per_pass = rand::thread_rng()
            .gen_range(HARD_SYM_RANDOM_PORTS_PER_PASS_MIN..=HARD_SYM_RANDOM_PORTS_PER_PASS_MAX);

        let mut next_port_index = last_port_index;
        for pass in 0..HARD_SYM_RANDOM_PASSES {
            tracing::debug!(
                pass,
                round,
                port_start_idx = next_port_index,
                ports_per_pass,
                "send hard symmetric random port pass"
            );
            next_port_index = send_symmetric_hole_punch_packet(
                &self.shuffled_port_vec,
                listener.clone(),
                transaction_id,
                &public_ips,
                next_port_index,
                ports_per_pass as usize,
            )
            .await
            .with_context(|| "failed to send symmetric hole punch packet randomly")?;
        }

        return Ok(SendPunchPacketHardSymResponse {
            next_port_index: next_port_index as u32,
        });
    }
}

pub(crate) struct PunchSymToConeHoleClient {
    peer_mgr: Arc<PeerManager>,
    udp_array: RwLock<Option<Arc<UdpSocketArray>>>,
    try_direct_connect: AtomicBool,
    punch_predicablely: AtomicBool,
    punch_randomly: AtomicBool,
    blacklist: Arc<timedmap::TimedMap<PeerId, ()>>,
}

impl PunchSymToConeHoleClient {
    pub(crate) fn new(
        peer_mgr: Arc<PeerManager>,
        blacklist: Arc<timedmap::TimedMap<PeerId, ()>>,
    ) -> Self {
        Self {
            peer_mgr,
            udp_array: RwLock::new(None),
            try_direct_connect: AtomicBool::new(true),
            punch_predicablely: AtomicBool::new(true),
            punch_randomly: AtomicBool::new(true),
            blacklist,
        }
    }

    // ZeroTier-parity punch: use ONE socket, hand the cone peer its exact mapped
    // port, and have the peer spray only a tight band around it. Works whenever our
    // NAT's per-destination mapping is near-stable, regardless of the inc/dec/hard
    // subtype, so it also rescues "hard" NATs whose per-socket randomness misled
    // the legacy 84-socket prediction. A fresh single-socket array per attempt
    // (like the cone path): the recv loop consumes its socket on the first punch.
    async fn try_stable_socket_punch(
        &self,
        dst_peer_id: PeerId,
        remote_mapped_addr: crate::proto::common::SocketAddr,
        public_ips: &[Ipv4Addr],
    ) -> Result<Option<Box<dyn Tunnel>>, anyhow::Error> {
        let global_ctx = self.peer_mgr.get_global_ctx();

        // Resolve the public addr BEFORE the socket joins the array: the array's
        // recv loop would otherwise steal the STUN responses. Resolving via upnp
        // also pins a gateway port mapping (NAT-PMP/IGD) when available, yielding a
        // truly stable external port — the same lever ZeroTier relies on.
        let socket = {
            let _g = global_ctx.net_ns.guard();
            Arc::new(UdpSocket::bind("0.0.0.0:0").await?)
        };
        let local_port = socket.local_addr()?.port();
        let local_listener: url::Url = format!("udp://0.0.0.0:{local_port}").parse().unwrap();
        let (my_mapped, _port_mapping_lease) = match upnp::resolve_udp_public_addr(
            global_ctx.clone(),
            &local_listener,
            socket.clone(),
        )
        .await
        {
            Ok(ret) => ret,
            Err(e) => {
                tracing::warn!(?e, "stable punch: failed to resolve stable socket addr");
                return Ok(None);
            }
        };

        let array = Arc::new(UdpSocketArray::new(1, global_ctx.net_ns.clone()));
        array.add_new_socket(socket).await?;

        let tid: u32 = rand::thread_rng().r#gen();
        let packet = new_hole_punch_packet(tid, HOLE_PUNCH_PACKET_BODY_LEN).into_bytes();
        array.add_intreast_tid(tid);
        defer! { array.remove_intreast_tid(tid); }

        // Open our own mapping toward the peer before asking it to spray back.
        array
            .send_with_all(&packet, remote_mapped_addr.into())
            .await?;

        let margin = STABLE_PUNCH_WINDOW / 2;
        let base_port_num = (my_mapped.port() as u32).saturating_sub(margin);
        let proto_ips = public_ips.iter().map(|x| (*x).into()).collect();
        let rpc_stub = self.get_rpc_stub(dst_peer_id).await;
        let punch_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let req = SendPunchPacketEasySymRequest {
                listener_mapped_addr: remote_mapped_addr.into(),
                public_ips: proto_ips,
                transaction_id: tid,
                base_port_num,
                max_port_num: STABLE_PUNCH_WINDOW,
                is_incremental: true,
            };
            if let Err(e) = rpc_stub
                .send_punch_packet_easy_sym(
                    BaseController {
                        timeout_ms: 8000,
                        trace_id: 0,
                        ..Default::default()
                    },
                    req,
                )
                .await
            {
                tracing::warn!(?e, "stable punch: remote easy-sym spray failed");
            }
        }));

        let start = Instant::now();
        let mut tunnel = None;
        while start.elapsed().as_millis() < STABLE_PUNCH_WAIT_MS {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let Some(punched) = array.try_fetch_punched_socket(tid) else {
                array
                    .send_with_all(&packet, remote_mapped_addr.into())
                    .await?;
                continue;
            };
            for _ in 0..2 {
                match try_connect_with_socket(
                    global_ctx.clone(),
                    punched.socket.clone(),
                    remote_mapped_addr.into(),
                )
                .await
                {
                    Ok(t) => {
                        tunnel = Some(t);
                        break;
                    }
                    Err(e) => tracing::warn!(?e, "stable punch: connect failed"),
                }
            }
            break;
        }

        let _ = punch_task.await;
        Ok(tunnel)
    }

    async fn prepare_udp_array(&self) -> Result<Arc<UdpSocketArray>, anyhow::Error> {
        let rlocked = self.udp_array.read().await;
        if let Some(udp_array) = rlocked.clone() {
            return Ok(udp_array);
        }

        drop(rlocked);
        let mut wlocked = self.udp_array.write().await;
        if let Some(udp_array) = wlocked.clone() {
            return Ok(udp_array);
        }

        let udp_array = Arc::new(UdpSocketArray::new(
            UDP_ARRAY_SIZE_FOR_HARD_SYM,
            self.peer_mgr.get_global_ctx().net_ns.clone(),
        ));
        udp_array.start().await?;
        wlocked.replace(udp_array.clone());
        Ok(udp_array)
    }

    pub(crate) async fn clear_udp_array(&self) {
        let mut wlocked = self.udp_array.write().await;
        wlocked.take();
    }

    async fn get_base_port_for_easy_sym(
        &self,
        my_nat_info: UdpNatType,
        udp_array: &UdpSocketArray,
    ) -> Option<(u16, u32)> {
        if !my_nat_info.is_easy_sym() {
            return None;
        }

        let inc = my_nat_info.get_inc_of_easy_sym().unwrap_or(true);
        let stun_collector = self.peer_mgr.get_global_ctx().get_stun_info_collector();
        let mut mapped_ports = Vec::new();

        for socket in udp_array
            .sockets()
            .into_iter()
            .take(MAX_EASY_SYM_MAPPING_PROBES)
        {
            match stun_collector
                .get_udp_port_mapping_with_socket(socket)
                .await
            {
                Ok(addr) => mapped_ports.push(addr.port()),
                ret => tracing::warn!(?ret, "failed to map udp array socket for easy sym"),
            }
        }

        if mapped_ports.is_empty() {
            match stun_collector.get_udp_port_mapping(0).await {
                Ok(addr) => mapped_ports.push(addr.port()),
                ret => {
                    tracing::warn!(?ret, "failed to get fallback udp port mapping for easy sym");
                    return None;
                }
            }
        }

        mapped_ports.sort_unstable();
        let first = *mapped_ports.first().unwrap();
        let last = *mapped_ports.last().unwrap();
        let base_port = if inc { first } else { last };
        let observed_span = last.saturating_sub(first) as u32;
        let max_port_num = easy_sym_predict_window(observed_span);

        tracing::info!(
            ?mapped_ports,
            ?base_port,
            ?max_port_num,
            ?inc,
            "easy symmetric nat prediction based on udp array sockets"
        );

        Some((base_port, max_port_num))
    }

    async fn remote_send_hole_punch_packet_predicable<
        S: UdpHolePunchRpc<Controller = BaseController>,
    >(
        rpc_stub: S,
        base_port_for_easy_sym: Option<(u16, u32)>,
        my_nat_info: UdpNatType,
        remote_mapped_addr: crate::proto::common::SocketAddr,
        public_ips: Vec<Ipv4Addr>,
        tid: u32,
    ) {
        let Some(inc) = my_nat_info.get_inc_of_easy_sym() else {
            tracing::debug!(
                ?my_nat_info,
                "skip predictable punch for non-easy-symmetric NAT"
            );
            return;
        };
        let Some((base_port_num, max_port_num)) = base_port_for_easy_sym else {
            tracing::debug!(
                ?my_nat_info,
                "skip predictable punch without easy-symmetric port mapping"
            );
            return;
        };
        let req = SendPunchPacketEasySymRequest {
            listener_mapped_addr: remote_mapped_addr.into(),
            public_ips: public_ips.clone().into_iter().map(|x| x.into()).collect(),
            transaction_id: tid,
            base_port_num: base_port_num as u32,
            max_port_num,
            is_incremental: inc,
        };
        tracing::debug!(?req, "send punch packet for easy sym start");
        let ret = rpc_stub
            .send_punch_packet_easy_sym(
                BaseController {
                    timeout_ms: 12000,
                    trace_id: 0,
                    ..Default::default()
                },
                req,
            )
            .await;
        tracing::info!(?ret, "send punch packet for easy sym return");
    }

    async fn remote_send_hole_punch_packet_random<
        S: UdpHolePunchRpc<Controller = BaseController>,
    >(
        rpc_stub: S,
        remote_mapped_addr: crate::proto::common::SocketAddr,
        public_ips: Vec<Ipv4Addr>,
        tid: u32,
        round: u32,
        port_index: u32,
    ) -> Option<u32> {
        let req = SendPunchPacketHardSymRequest {
            listener_mapped_addr: remote_mapped_addr.into(),
            public_ips: public_ips.clone().into_iter().map(|x| x.into()).collect(),
            transaction_id: tid,
            round,
            port_index,
        };
        tracing::info!(?req, "send punch packet for hard sym start");
        match rpc_stub
            .send_punch_packet_hard_sym(
                BaseController {
                    timeout_ms: 12000,
                    trace_id: 0,
                    ..Default::default()
                },
                req,
            )
            .await
        {
            Err(e) => {
                tracing::error!(?e, "failed to send punch packet for hard sym");
                None
            }
            Ok(resp) => {
                tracing::info!(?resp, "send punch packet for hard sym return");
                Some(resp.next_port_index)
            }
        }
    }

    async fn get_rpc_stub(
        &self,
        dst_peer_id: PeerId,
    ) -> Box<dyn UdpHolePunchRpc<Controller = BaseController> + std::marker::Send + Sync + 'static>
    {
        self.peer_mgr
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<UdpHolePunchRpcClientFactory<BaseController>>(
                self.peer_mgr.my_peer_id(),
                dst_peer_id,
                self.peer_mgr.get_global_ctx().get_network_name(),
            )
    }

    async fn check_hole_punch_result<T>(
        global_ctx: ArcGlobalCtx,
        udp_array: &Arc<UdpSocketArray>,
        packet: &[u8],
        tid: u32,
        remote_mapped_addr: crate::proto::common::SocketAddr,
        punch_task: &AbortOnDropHandle<T>,
    ) -> Result<Option<Box<dyn Tunnel>>, anyhow::Error> {
        // no matter what the result is, we should check if we received any hole punching packet
        let mut ret_tunnel: Option<Box<dyn Tunnel>> = None;
        let mut finish_time: Option<Instant> = None;
        while finish_time.is_none()
            || finish_time.as_ref().unwrap().elapsed().as_millis() < PUNCH_RESULT_GRACE_MS
        {
            udp_array
                .send_with_all(packet, remote_mapped_addr.into())
                .await?;

            tokio::time::sleep(Duration::from_millis(200)).await;

            if finish_time.is_none() && punch_task.is_finished() {
                finish_time = Some(Instant::now());
            }

            let Some(socket) = udp_array.try_fetch_punched_socket(tid) else {
                tracing::debug!("no punched socket found, wait for more time");
                continue;
            };

            // if hole punched but tunnel creation failed, need to retry entire process.
            match try_connect_with_socket(
                global_ctx.clone(),
                socket.socket.clone(),
                remote_mapped_addr.into(),
            )
            .await
            {
                Ok(tunnel) => {
                    ret_tunnel.replace(tunnel);
                    break;
                }
                Err(e) => {
                    tracing::error!(?e, "failed to connect with socket");
                    udp_array.add_new_socket(socket.socket).await?;
                    continue;
                }
            }
        }

        Ok(ret_tunnel)
    }

    #[tracing::instrument(err(level = Level::ERROR), skip(self))]
    pub(crate) async fn do_hole_punching(
        &self,
        dst_peer_id: PeerId,
        round: u32,
        last_port_idx: &mut usize,
        my_nat_info: UdpNatType,
    ) -> Result<Option<Box<dyn Tunnel>>, anyhow::Error> {
        // Check if peer is blacklisted
        if self.blacklist.contains(&dst_peer_id) {
            tracing::debug!(?dst_peer_id, "peer is blacklisted, skipping hole punching");
            return Ok(None);
        }

        let udp_array = self.prepare_udp_array().await?;
        let global_ctx = self.peer_mgr.get_global_ctx();

        let rpc_stub = self
            .peer_mgr
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<UdpHolePunchRpcClientFactory<BaseController>>(
                self.peer_mgr.my_peer_id(),
                dst_peer_id,
                global_ctx.get_network_name(),
            );

        let resp = rpc_stub
            .select_punch_listener(
                BaseController::default(),
                SelectPunchListenerRequest {
                    // Symmetric NAT attempts are sensitive to stale mapped listener ports.
                    // Use a fresh remote listener each round when possible so the follow-up
                    // RPC cannot target a listener that has already aged out or been rotated.
                    force_new: round > 0,
                    prefer_port_mapping: true,
                },
            )
            .await;

        let resp = handle_rpc_result(resp, dst_peer_id, &self.blacklist)?;

        let remote_mapped_addr = resp.listener_mapped_addr.ok_or(anyhow::anyhow!(
            "select_punch_listener response missing listener_mapped_addr"
        ))?;

        // try direct connect first
        if self.try_direct_connect.load(Ordering::Relaxed)
            && let Ok(tunnel) = try_connect_with_socket(
                global_ctx.clone(),
                Arc::new(UdpSocket::bind("0.0.0.0:0").await?),
                remote_mapped_addr.into(),
            )
            .await
        {
            return Ok(Some(tunnel));
        }

        let stun_info = global_ctx.get_stun_info_collector().get_stun_info();
        let public_ips: Vec<Ipv4Addr> = stun_info
            .public_ip
            .iter()
            .filter_map(|x| x.parse().ok())
            .collect();
        if public_ips.is_empty() {
            return Err(anyhow::anyhow!("failed to get public ips"));
        }

        // ZeroTier-parity: if our NAT keeps a near-stable per-destination mapping,
        // punch from one reused socket whose exact mapped port the peer targets,
        // instead of scattering 84 random sockets across a 4k prediction window.
        let observed_spread = stun_info.max_port.saturating_sub(stun_info.min_port);
        if self.punch_predicablely.load(Ordering::Relaxed)
            && observed_spread <= STABLE_PUNCH_SPREAD_MAX
            && let Some(tunnel) = self
                .try_stable_socket_punch(dst_peer_id, remote_mapped_addr, &public_ips)
                .await?
        {
            return Ok(Some(tunnel));
        }

        let tid = rand::thread_rng().r#gen();
        let packet = new_hole_punch_packet(tid, HOLE_PUNCH_PACKET_BODY_LEN).into_bytes();
        udp_array.add_intreast_tid(tid);
        defer! { udp_array.remove_intreast_tid(tid);}

        let port_index = *last_port_idx as u32;
        let base_port_for_easy_sym = tokio::time::timeout(
            Duration::from_millis(EASY_SYM_MAPPING_TIMEOUT_MS),
            self.get_base_port_for_easy_sym(my_nat_info, &udp_array),
        )
        .await
        .unwrap_or_else(|_| {
            tracing::warn!(
                timeout_ms = EASY_SYM_MAPPING_TIMEOUT_MS,
                "easy symmetric port mapping timed out; falling back to random punch"
            );
            None
        });
        udp_array
            .send_with_all(&packet, remote_mapped_addr.into())
            .await?;

        if self.punch_predicablely.load(Ordering::Relaxed) && base_port_for_easy_sym.is_some() {
            let rpc_stub = self.get_rpc_stub(dst_peer_id).await;
            let punch_task = AbortOnDropHandle::new(tokio::spawn(
                Self::remote_send_hole_punch_packet_predicable(
                    rpc_stub,
                    base_port_for_easy_sym,
                    my_nat_info,
                    remote_mapped_addr,
                    public_ips.clone(),
                    tid,
                ),
            ));
            let ret_tunnel = Self::check_hole_punch_result(
                global_ctx.clone(),
                &udp_array,
                &packet,
                tid,
                remote_mapped_addr,
                &punch_task,
            )
            .await?;

            let task_ret = punch_task.await;
            tracing::info!(?ret_tunnel, ?task_ret, "predictable punch task got result");
            if let Some(tunnel) = ret_tunnel {
                return Ok(Some(tunnel));
            }
        }

        if !self.punch_randomly.load(Ordering::Relaxed) {
            tracing::debug!("skip random symmetric punch because punch_randomly=false");
            return Ok(None);
        }

        let rpc_stub = self.get_rpc_stub(dst_peer_id).await;
        let punch_task =
            AbortOnDropHandle::new(tokio::spawn(Self::remote_send_hole_punch_packet_random(
                rpc_stub,
                remote_mapped_addr,
                public_ips.clone(),
                tid,
                round,
                port_index,
            )));
        let ret_tunnel = Self::check_hole_punch_result(
            global_ctx,
            &udp_array,
            &packet,
            tid,
            remote_mapped_addr,
            &punch_task,
        )
        .await?;

        let punch_task_result = punch_task.await;
        tracing::info!(?punch_task_result, ?ret_tunnel, "punch task got result");

        if let Ok(Some(next_port_idx)) = punch_task_result {
            *last_port_idx = next_port_idx as usize;
        } else {
            *last_port_idx = rand::random();
        }

        Ok(ret_tunnel)
    }
}

#[cfg(test)]
pub mod tests {
    use std::{
        sync::{Arc, atomic::AtomicU32},
        time::Duration,
    };

    use tokio::net::UdpSocket;

    use crate::{
        connector::udp_hole_punch::{
            RUN_TESTING, UdpHolePunchConnector, tests::create_mock_peer_manager_with_mock_stun,
        },
        peers::tests::{connect_peer_manager, wait_route_appear, wait_route_appear_with_cost},
        proto::common::NatType,
        tunnel::common::tests::wait_for_condition,
    };

    #[test]
    fn easy_sym_predict_window_is_wide_enough_for_real_nat_jitter() {
        assert_eq!(super::easy_sym_predict_window(0), 1856);
        assert_eq!(super::easy_sym_predict_window(53), 1909);
        assert_eq!(super::easy_sym_predict_window(554), 2410);
        assert_eq!(super::easy_sym_predict_window(10_000), 4096);
    }

    #[test]
    fn easy_sym_target_ports_clamp_without_wrapping() {
        let ports = super::easy_sym_target_ports(32_335, 256, true);
        assert_eq!(ports.first().copied(), Some(32_336));
        assert_eq!(ports.last().copied(), Some(32_591));
        assert_eq!(ports.len(), 256);

        let ports = super::easy_sym_target_ports(65_000, 4096, true);
        assert_eq!(ports.first().copied(), Some(65_001));
        assert_eq!(ports.last().copied(), Some(u16::MAX));
        assert!(!ports.contains(&0));

        let ports = super::easy_sym_target_ports(100, 4096, false);
        assert_eq!(ports.first().copied(), Some(1));
        assert_eq!(ports.last().copied(), Some(99));
        assert!(!ports.contains(&0));
    }

    #[tokio::test]
    #[serial_test::serial]
    #[serial_test::serial(hole_punch)]
    async fn hole_punching_symmetric_only_random() {
        RUN_TESTING.store(true, std::sync::atomic::Ordering::Relaxed);

        let p_a = create_mock_peer_manager_with_mock_stun(NatType::Symmetric).await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_c = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        let mut hole_punching_a = UdpHolePunchConnector::new(p_a.clone());
        let mut hole_punching_c = UdpHolePunchConnector::new(p_c.clone());

        hole_punching_a
            .client
            .data()
            .sym_to_cone_client
            .try_direct_connect
            .store(false, std::sync::atomic::Ordering::Relaxed);

        hole_punching_a
            .client
            .data()
            .sym_to_cone_client
            .punch_predicablely
            .store(false, std::sync::atomic::Ordering::Relaxed);

        hole_punching_a.run().await.unwrap();
        hole_punching_c.run().await.unwrap();

        hole_punching_a.client.run_immediately().await;

        wait_for_condition(
            || async {
                hole_punching_a
                    .client
                    .data()
                    .sym_to_cone_client
                    .udp_array
                    .read()
                    .await
                    .is_some()
            },
            Duration::from_secs(5),
        )
        .await;

        println!("start punching {:?}", p_a.list_routes().await);

        wait_for_condition(
            || async {
                wait_route_appear_with_cost(p_a.clone(), p_c.my_peer_id(), Some(1))
                    .await
                    .is_ok()
            },
            Duration::from_secs(60),
        )
        .await;
        println!("{:?}", p_a.list_routes().await);

        wait_for_condition(
            || async {
                hole_punching_a
                    .client
                    .data()
                    .sym_to_cone_client
                    .udp_array
                    .read()
                    .await
                    .is_none()
            },
            Duration::from_secs(10),
        )
        .await;
    }

    #[rstest::rstest]
    #[tokio::test]
    #[serial_test::serial(hole_punch)]
    async fn hole_punching_symmetric_only_predict(#[values("true", "false")] is_inc: bool) {
        use tokio_util::task::AbortOnDropHandle;

        RUN_TESTING.store(true, std::sync::atomic::Ordering::Relaxed);

        let p_a = create_mock_peer_manager_with_mock_stun(if is_inc {
            NatType::SymmetricEasyInc
        } else {
            NatType::SymmetricEasyDec
        })
        .await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_c = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        let mut hole_punching_a = UdpHolePunchConnector::new(p_a.clone());
        let mut hole_punching_c = UdpHolePunchConnector::new(p_c.clone());

        hole_punching_a
            .client
            .data()
            .sym_to_cone_client
            .try_direct_connect
            .store(false, std::sync::atomic::Ordering::Relaxed);

        hole_punching_a
            .client
            .data()
            .sym_to_cone_client
            .punch_randomly
            .store(false, std::sync::atomic::Ordering::Relaxed);

        hole_punching_a.run().await.unwrap();
        hole_punching_c.run().await.unwrap();

        let udps = if is_inc {
            let udp1 = Arc::new(UdpSocket::bind("0.0.0.0:40147").await.unwrap());
            let udp2 = Arc::new(UdpSocket::bind("0.0.0.0:40194").await.unwrap());
            vec![udp1, udp2]
        } else {
            let udp1 = Arc::new(UdpSocket::bind("0.0.0.0:40141").await.unwrap());
            let udp2 = Arc::new(UdpSocket::bind("0.0.0.0:40100").await.unwrap());
            vec![udp1, udp2]
        };
        // let udp_dec = Arc::new(UdpSocket::bind("0.0.0.0:40140").await.unwrap());
        // let udp_dec2 = Arc::new(UdpSocket::bind("0.0.0.0:40050").await.unwrap());

        let counter = Arc::new(AtomicU32::new(0));

        let mut tasks: Vec<AbortOnDropHandle<()>> = vec![];

        // all these sockets should receive hole punching packet
        for udp in udps.iter().map(Arc::clone) {
            let counter = counter.clone();
            tasks.push(AbortOnDropHandle::new(tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let (len, addr) = udp.recv_from(&mut buf).await.unwrap();
                println!(
                    "got predictable punch packet, {:?} {:?} {:?}",
                    len,
                    addr,
                    udp.local_addr()
                );
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            })));
        }

        hole_punching_a.client.run_immediately().await;

        let udp_len = udps.len();
        wait_for_condition(
            || async { counter.load(std::sync::atomic::Ordering::Relaxed) == udp_len as u32 },
            Duration::from_secs(30),
        )
        .await;
    }
}
