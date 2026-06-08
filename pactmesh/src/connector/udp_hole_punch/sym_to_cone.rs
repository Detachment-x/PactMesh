use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    pin::Pin,
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
        common::NatType,
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
const PREDICTABLE_PUNCH_RPC_TIMEOUT_MS: i32 = 30_000;
const RANDOM_PUNCH_RPC_TIMEOUT_MS: i32 = 12_000;
const EASY_SYM_PREDICT_WINDOW: u32 = 8192;
const EASY_SYM_SPRAY_CHUNK_SIZE: usize = 512;
const EASY_SYM_SPRAY_CHUNK_PAUSE_MS: u64 = 20;
const EASY_SYM_SPRAY_PASSES: usize = 2;

// ZeroTier-parity stable-socket punch: only attempted when our NAT keeps a
// near-stable per-destination mapping (observed STUN port spread within this
// bound), so one reused socket's mapped port is enough for the peer to target.
const STABLE_PUNCH_SPREAD_MAX: u32 = 64;
// Use a wider centered spray than the STUN-observed spread: some symmetric NATs
// shift the mapped port further when the destination changes from STUN to peer.
const STABLE_PUNCH_WINDOW: u32 = 4096;
const STABLE_PUNCH_WINDOWS: [u32; 3] = [4096, 8192, 16384];
const HARD_SYM_PREDICT_WINDOW: u32 = 32768;
const STABLE_PUNCH_WAIT_MS: u128 = 5000;

const HARD_SYM_RANDOM_PASSES: usize = 2;
const HARD_SYM_RANDOM_PORTS_PER_PASS_MIN: u32 = 2048;
const HARD_SYM_RANDOM_PORTS_PER_PASS_MAX: u32 = 3072;
const HARD_SYM_PREDICT_MIN_SAMPLES: usize = 3;
const REMOTE_SYM_SCAN_PORTS_PER_TICK: usize = 32;
const REMOTE_HARD_SYM_SCAN_PORTS_PER_TICK: usize = 128;
const REMOTE_SYM_SCAN_WINDOW: u16 = 4096;
const REMOTE_SYM_SCAN_SOCKET_LIMIT: usize = 16;

type UdpHolePunchRpcStub =
    Box<dyn UdpHolePunchRpc<Controller = BaseController> + std::marker::Send + Sync + 'static>;

fn easy_sym_predict_window(_observed_span: u32) -> u32 {
    EASY_SYM_PREDICT_WINDOW
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PredictablePortWindow {
    base_port_num: u16,
    max_port_num: u32,
    is_incremental: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimePortPrediction {
    predictable_port_window: Option<PredictablePortWindow>,
    mapped_ports: Vec<u16>,
}

impl RuntimePortPrediction {
    fn observed_port_spread(&self) -> u32 {
        let Some(min_port) = self.mapped_ports.iter().min() else {
            return 0;
        };
        let Some(max_port) = self.mapped_ports.iter().max() else {
            return 0;
        };

        max_port.saturating_sub(*min_port) as u32
    }

    fn should_try_stable_socket_punch(&self) -> bool {
        self.predictable_port_window.is_some()
            && self.observed_port_spread() <= STABLE_PUNCH_SPREAD_MAX
    }
}

fn infer_ordered_port_direction(mapped_ports: &[u16]) -> Option<bool> {
    if mapped_ports.len() < HARD_SYM_PREDICT_MIN_SAMPLES {
        return None;
    }

    if mapped_ports.windows(2).all(|w| w[1] > w[0]) {
        Some(true)
    } else if mapped_ports.windows(2).all(|w| w[1] < w[0]) {
        Some(false)
    } else {
        None
    }
}

fn centered_predictable_port_window(first: u16, last: u16, window: u32) -> PredictablePortWindow {
    let min_window = last.saturating_sub(first) as u32 + 1;
    let window = window.max(min_window).min(u16::MAX as u32);
    let first = first as u32;
    let last = last as u32;
    let center = first + (last.saturating_sub(first) / 2);

    let mut start = center.saturating_sub(window / 2).max(1);
    let end = start
        .saturating_add(window.saturating_sub(1))
        .min(u16::MAX as u32);
    if end.saturating_sub(start).saturating_add(1) < window {
        start = end.saturating_sub(window.saturating_sub(1)).max(1);
    }

    PredictablePortWindow {
        base_port_num: start.saturating_sub(1) as u16,
        max_port_num: end.saturating_sub(start).saturating_add(1),
        is_incremental: true,
    }
}

fn hard_sym_centered_port_window(first: u16, last: u16) -> PredictablePortWindow {
    centered_predictable_port_window(first, last, HARD_SYM_PREDICT_WINDOW)
}

fn stable_predictable_port_window(mapped_ports: &[u16]) -> Option<PredictablePortWindow> {
    stable_predictable_port_window_with_width(mapped_ports, STABLE_PUNCH_WINDOW)
}

fn stable_predictable_port_window_with_width(
    mapped_ports: &[u16],
    window: u32,
) -> Option<PredictablePortWindow> {
    let first = *mapped_ports.iter().min()?;
    let last = *mapped_ports.iter().max()?;
    Some(centered_predictable_port_window(first, last, window))
}

fn nat_info_for_port_prediction(my_nat_info: UdpNatType) -> Option<UdpNatType> {
    if my_nat_info.is_sym() {
        Some(my_nat_info)
    } else if my_nat_info.is_unknown() {
        Some(UdpNatType::HardSymmetric(NatType::Symmetric))
    } else {
        None
    }
}

fn predictable_port_window_from_samples(
    my_nat_info: UdpNatType,
    mapped_ports: &[u16],
) -> Option<PredictablePortWindow> {
    if mapped_ports.is_empty() {
        return None;
    }

    let known_inc = my_nat_info.get_inc_of_easy_sym();
    let mut sorted_ports = mapped_ports.to_vec();
    sorted_ports.sort_unstable();
    let first = *sorted_ports.first().unwrap();
    let last = *sorted_ports.last().unwrap();
    let observed_span = last.saturating_sub(first) as u32;

    let Some(is_incremental) = known_inc else {
        infer_ordered_port_direction(mapped_ports)?;
        if observed_span > STABLE_PUNCH_WINDOW {
            return None;
        }
        return Some(hard_sym_centered_port_window(first, last));
    };

    let base_port_num = if is_incremental { last } else { first };
    Some(PredictablePortWindow {
        base_port_num,
        max_port_num: easy_sym_predict_window(observed_span),
        is_incremental,
    })
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemotePortScanKind {
    Centered,
    CenteredThenRandom,
}

struct RemotePortScanPlan {
    public_ip: Ipv4Addr,
    ports: Vec<u16>,
    next_idx: usize,
    ports_per_tick: usize,
    socket_limit: usize,
    kind: RemotePortScanKind,
}

fn centered_ports_around(base_port: u16, window: u16) -> Vec<u16> {
    let mut ports = Vec::with_capacity((window as usize) * 2 + 1);
    ports.push(base_port);
    for offset in 1..=window {
        if let Some(port) = base_port.checked_add(offset) {
            ports.push(port);
        }
        if let Some(port) = base_port.checked_sub(offset)
            && port > 0
        {
            ports.push(port);
        }
    }
    ports
}

impl RemotePortScanPlan {
    fn new(remote_addr: SocketAddr, peer_nat_info: UdpNatType) -> Option<Self> {
        let remote_addr = match remote_addr {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => return None,
        };
        let public_ip = *remote_addr.ip();
        let base_port = remote_addr.port();
        let centered_ports = centered_ports_around(base_port, REMOTE_SYM_SCAN_WINDOW);

        if peer_nat_info.is_unknown() || peer_nat_info.is_hard_sym() {
            let mut included = vec![false; u16::MAX as usize + 1];
            for port in centered_ports.iter().copied() {
                included[port as usize] = true;
            }

            let mut remaining_ports = Vec::with_capacity(u16::MAX as usize - centered_ports.len());
            for port in 1..=u16::MAX {
                if !included[port as usize] {
                    remaining_ports.push(port);
                }
            }
            remaining_ports.shuffle(&mut rand::thread_rng());

            let mut ports = centered_ports;
            ports.extend(remaining_ports);
            return Some(Self {
                public_ip,
                ports,
                next_idx: 0,
                ports_per_tick: REMOTE_HARD_SYM_SCAN_PORTS_PER_TICK,
                socket_limit: REMOTE_SYM_SCAN_SOCKET_LIMIT,
                kind: RemotePortScanKind::CenteredThenRandom,
            });
        }

        Some(Self {
            public_ip,
            ports: centered_ports,
            next_idx: 0,
            ports_per_tick: REMOTE_SYM_SCAN_PORTS_PER_TICK,
            socket_limit: usize::MAX,
            kind: RemotePortScanKind::Centered,
        })
    }

    fn kind(&self) -> RemotePortScanKind {
        self.kind
    }

    fn port_count(&self) -> usize {
        self.ports.len()
    }

    async fn send_next(
        &mut self,
        udp_array: &Arc<UdpSocketArray>,
        packet: &[u8],
    ) -> Result<(), anyhow::Error> {
        let sockets = udp_array.sockets();
        if sockets.is_empty() {
            return Ok(());
        }

        let socket_count = self.socket_limit.min(sockets.len());
        for _ in 0..self.ports_per_tick {
            let port = self.ports[self.next_idx % self.ports.len()];
            self.next_idx = (self.next_idx + 1) % self.ports.len();
            let addr = SocketAddr::V4(SocketAddrV4::new(self.public_ip, port));
            for socket in sockets.iter().take(socket_count) {
                for _ in 0..3 {
                    socket.send_to(packet, addr).await?;
                }
            }
        }
        Ok(())
    }
}

fn runtime_nat_info_for_punch(my_nat_info: UdpNatType, observed_port_spread: u32) -> UdpNatType {
    if !my_nat_info.is_unknown() {
        return my_nat_info;
    }

    if observed_port_spread > STABLE_PUNCH_SPREAD_MAX {
        UdpNatType::HardSymmetric(NatType::Symmetric)
    } else {
        my_nat_info
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

        for pass in 0..EASY_SYM_SPRAY_PASSES {
            let mut next_port_index = 0;
            let mut sent_in_pass = 0;
            while sent_in_pass < ports.len() {
                let packets_this_chunk = EASY_SYM_SPRAY_CHUNK_SIZE.min(ports.len() - sent_in_pass);
                tracing::trace!(
                    pass,
                    port_start_idx = next_port_index,
                    packets_this_chunk,
                    "send easy symmetric port chunk"
                );
                next_port_index = send_symmetric_hole_punch_packet(
                    &ports,
                    listener.clone(),
                    transaction_id,
                    &public_ips,
                    next_port_index,
                    packets_this_chunk,
                )
                .await
                .with_context(|| "failed to send symmetric hole punch packet")?;
                sent_in_pass += packets_this_chunk;

                if sent_in_pass < ports.len() || pass + 1 < EASY_SYM_SPRAY_PASSES {
                    tokio::time::sleep(Duration::from_millis(EASY_SYM_SPRAY_CHUNK_PAUSE_MS)).await;
                }
            }
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
    udp_array_predictable_port_window: RwLock<Option<PredictablePortWindow>>,
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
            udp_array_predictable_port_window: RwLock::new(None),
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

        let margin = EASY_SYM_PREDICT_WINDOW / 2;
        let base_port_num = (my_mapped.port() as u32).saturating_sub(margin);
        let proto_ips = public_ips.iter().map(|x| (*x).into()).collect();
        let rpc_stub = self.get_rpc_stub(dst_peer_id).await;
        let punch_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let req = SendPunchPacketEasySymRequest {
                listener_mapped_addr: remote_mapped_addr.into(),
                public_ips: proto_ips,
                transaction_id: tid,
                base_port_num,
                max_port_num: EASY_SYM_PREDICT_WINDOW,
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
                    punched.remote_addr,
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

    async fn try_runtime_stable_socket_punch(
        &self,
        dst_peer_id: PeerId,
        udp_array: &Arc<UdpSocketArray>,
        remote_mapped_addr: crate::proto::common::SocketAddr,
        public_ips: &[Ipv4Addr],
        peer_nat_info: UdpNatType,
        mapped_ports: &[u16],
    ) -> Result<Option<Box<dyn Tunnel>>, anyhow::Error> {
        let global_ctx = self.peer_mgr.get_global_ctx();
        let remote_addr: SocketAddr = remote_mapped_addr.into();

        for window in STABLE_PUNCH_WINDOWS {
            let Some(port_window) = stable_predictable_port_window_with_width(mapped_ports, window)
            else {
                continue;
            };

            let tid: u32 = rand::thread_rng().r#gen();
            let packet = new_hole_punch_packet(tid, HOLE_PUNCH_PACKET_BODY_LEN).into_bytes();
            udp_array.add_intreast_tid(tid);
            defer! { udp_array.remove_intreast_tid(tid); }

            udp_array.send_with_all(&packet, remote_addr).await?;

            let proto_ips = public_ips.iter().map(|x| (*x).into()).collect();
            let mapped_ports_for_rpc = mapped_ports.to_vec();
            let rpc_stub = self.get_rpc_stub(dst_peer_id).await;
            let punch_task = AbortOnDropHandle::new(tokio::spawn(async move {
                let req = SendPunchPacketEasySymRequest {
                    listener_mapped_addr: remote_mapped_addr.into(),
                    public_ips: proto_ips,
                    transaction_id: tid,
                    base_port_num: port_window.base_port_num as u32,
                    max_port_num: port_window.max_port_num,
                    is_incremental: port_window.is_incremental,
                };
                tracing::info!(
                    ?req,
                    ?mapped_ports_for_rpc,
                    window,
                    "runtime stable punch: ask peer to target sampled mapped ports"
                );
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
                    tracing::warn!(
                        ?e,
                        window,
                        "runtime stable punch: remote easy-sym spray failed"
                    );
                }
            }));

            let mut remote_scan = if peer_nat_info.is_unknown() || peer_nat_info.is_sym() {
                let plan = RemotePortScanPlan::new(remote_addr, peer_nat_info);
                if let Some(plan) = plan.as_ref() {
                    tracing::info!(
                        ?remote_addr,
                        ?peer_nat_info,
                        window,
                        scan_kind = ?plan.kind(),
                        ports_per_tick = plan.ports_per_tick,
                        socket_limit = plan.socket_limit,
                        port_count = plan.port_count(),
                        scan_window = REMOTE_SYM_SCAN_WINDOW,
                        "runtime stable punch: enable remote symmetric port scan"
                    );
                }
                plan
            } else {
                None
            };

            let tunnel = Self::check_hole_punch_result(
                global_ctx.clone(),
                udp_array,
                &packet,
                tid,
                remote_mapped_addr,
                &punch_task,
                remote_scan.as_mut(),
            )
            .await?;
            let _ = punch_task.await;

            if tunnel.is_some() {
                return Ok(tunnel);
            }

            tracing::info!(
                window,
                ?mapped_ports,
                "runtime stable punch window finished without direct path"
            );
        }

        Ok(None)
    }

    async fn prepare_udp_array(
        &self,
    ) -> Result<(Arc<UdpSocketArray>, Option<Vec<Arc<UdpSocket>>>), anyhow::Error> {
        let rlocked = self.udp_array.read().await;
        if let Some(udp_array) = rlocked.clone() {
            return Ok((udp_array, None));
        }

        drop(rlocked);
        let wlocked = self.udp_array.write().await;
        if let Some(udp_array) = wlocked.clone() {
            return Ok((udp_array, None));
        }
        drop(wlocked);

        let udp_array = Arc::new(UdpSocketArray::new(
            UDP_ARRAY_SIZE_FOR_HARD_SYM,
            self.peer_mgr.get_global_ctx().net_ns.clone(),
        ));
        let sockets = udp_array.bind_sockets().await?;
        Ok((udp_array, Some(sockets)))
    }

    async fn publish_udp_array(&self, udp_array: Arc<UdpSocketArray>) {
        let mut wlocked = self.udp_array.write().await;
        if wlocked.is_none() {
            wlocked.replace(udp_array);
        }
    }

    async fn cache_predictable_port_window(&self, prediction: Option<PredictablePortWindow>) {
        if let Some(prediction) = prediction {
            let mut wlocked = self.udp_array_predictable_port_window.write().await;
            wlocked.replace(prediction);
        }
    }

    pub(crate) async fn clear_udp_array(&self) {
        let mut wlocked = self.udp_array.write().await;
        wlocked.take();
        let mut prediction = self.udp_array_predictable_port_window.write().await;
        prediction.take();
    }

    async fn sample_runtime_port_prediction(
        &self,
        my_nat_info: UdpNatType,
        prediction_sockets: Option<&[Arc<UdpSocket>]>,
    ) -> Option<RuntimePortPrediction> {
        let prediction_nat_info = nat_info_for_port_prediction(my_nat_info)?;

        let global_ctx = self.peer_mgr.get_global_ctx();
        let stun_collector = global_ctx.get_stun_info_collector();
        let mut mapped_ports = Vec::new();
        let target_samples = if prediction_nat_info.get_inc_of_easy_sym().is_some() {
            1
        } else {
            HARD_SYM_PREDICT_MIN_SAMPLES
        };

        if let Some(prediction_sockets) = prediction_sockets {
            for socket in prediction_sockets.iter().take(MAX_EASY_SYM_MAPPING_PROBES) {
                match stun_collector
                    .get_udp_port_mapping_with_socket(socket.clone())
                    .await
                {
                    Ok(addr) => {
                        mapped_ports.push(addr.port());
                        if mapped_ports.len() >= target_samples {
                            break;
                        }
                    }
                    ret => {
                        tracing::warn!(?ret, "failed to map udp array socket for sym prediction")
                    }
                }
            }

            if mapped_ports.is_empty() {
                tracing::warn!("failed to sample any udp array sockets for sym prediction");
                return None;
            }
        } else {
            for _ in 0..MAX_EASY_SYM_MAPPING_PROBES {
                let socket = {
                    let _g = global_ctx.net_ns.guard();
                    match UdpSocket::bind("0.0.0.0:0").await {
                        Ok(socket) => Arc::new(socket),
                        Err(e) => {
                            tracing::warn!(?e, "failed to bind udp socket for sym prediction");
                            continue;
                        }
                    }
                };

                match stun_collector
                    .get_udp_port_mapping_with_socket(socket)
                    .await
                {
                    Ok(addr) => {
                        mapped_ports.push(addr.port());
                        if mapped_ports.len() >= target_samples {
                            break;
                        }
                    }
                    ret => tracing::warn!(
                        ?ret,
                        "failed to map temporary udp socket for sym prediction"
                    ),
                }
            }

            if mapped_ports.is_empty() {
                match stun_collector.get_udp_port_mapping(0).await {
                    Ok(addr) => mapped_ports.push(addr.port()),
                    ret => {
                        tracing::warn!(
                            ?ret,
                            "failed to get fallback udp port mapping for sym prediction"
                        );
                        return None;
                    }
                }
            }
        }

        let prediction = predictable_port_window_from_samples(prediction_nat_info, &mapped_ports);
        let runtime_prediction = RuntimePortPrediction {
            predictable_port_window: prediction,
            mapped_ports,
        };
        tracing::info!(
            mapped_ports = ?runtime_prediction.mapped_ports,
            observed_spread = runtime_prediction.observed_port_spread(),
            prediction = ?runtime_prediction.predictable_port_window,
            ?my_nat_info,
            ?prediction_nat_info,
            target_samples,
            from_udp_array = prediction_sockets.is_some(),
            "symmetric nat prediction based on sampled udp sockets"
        );

        Some(runtime_prediction)
    }

    async fn remote_send_hole_punch_packet_predicable<
        S: UdpHolePunchRpc<Controller = BaseController>,
    >(
        rpc_stub: S,
        predictable_port_window: Option<PredictablePortWindow>,
        my_nat_info: UdpNatType,
        remote_mapped_addr: crate::proto::common::SocketAddr,
        public_ips: Vec<Ipv4Addr>,
        tid: u32,
    ) {
        let Some(port_window) = predictable_port_window else {
            tracing::debug!(
                ?my_nat_info,
                "skip predictable punch without usable symmetric port mapping"
            );
            return;
        };
        let req = SendPunchPacketEasySymRequest {
            listener_mapped_addr: remote_mapped_addr.into(),
            public_ips: public_ips.clone().into_iter().map(|x| x.into()).collect(),
            transaction_id: tid,
            base_port_num: port_window.base_port_num as u32,
            max_port_num: port_window.max_port_num,
            is_incremental: port_window.is_incremental,
        };
        tracing::debug!(?req, "send punch packet for easy sym start");
        let ret = rpc_stub
            .send_punch_packet_easy_sym(
                BaseController {
                    timeout_ms: PREDICTABLE_PUNCH_RPC_TIMEOUT_MS,
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
                    timeout_ms: RANDOM_PUNCH_RPC_TIMEOUT_MS,
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

    async fn get_rpc_stub(&self, dst_peer_id: PeerId) -> UdpHolePunchRpcStub {
        self.peer_mgr
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<UdpHolePunchRpcClientFactory<BaseController>>(
                self.peer_mgr.my_peer_id(),
                dst_peer_id,
                self.peer_mgr.get_global_ctx().get_network_name(),
            )
    }

    async fn remote_send_hole_punch_packets(
        predictable_rpc_stub: Option<UdpHolePunchRpcStub>,
        random_rpc_stub: Option<UdpHolePunchRpcStub>,
        predictable_port_window: Option<PredictablePortWindow>,
        my_nat_info: UdpNatType,
        remote_mapped_addr: crate::proto::common::SocketAddr,
        public_ips: Vec<Ipv4Addr>,
        tid: u32,
        round: u32,
        port_index: u32,
    ) -> Option<u32> {
        let predictable_public_ips = public_ips.clone();
        let predictable_fut: Pin<Box<dyn Future<Output = ()> + Send>> =
            if let Some(rpc_stub) = predictable_rpc_stub {
                Box::pin(Self::remote_send_hole_punch_packet_predicable(
                    rpc_stub,
                    predictable_port_window,
                    my_nat_info,
                    remote_mapped_addr,
                    predictable_public_ips,
                    tid,
                ))
            } else {
                Box::pin(async {})
            };

        let random_fut: Pin<Box<dyn Future<Output = Option<u32>> + Send>> =
            if let Some(rpc_stub) = random_rpc_stub {
                Box::pin(Self::remote_send_hole_punch_packet_random(
                    rpc_stub,
                    remote_mapped_addr,
                    public_ips,
                    tid,
                    round,
                    port_index,
                ))
            } else {
                Box::pin(async { None })
            };

        let (_, next_port_index) = tokio::join!(predictable_fut, random_fut);
        next_port_index
    }

    async fn check_hole_punch_result<T>(
        global_ctx: ArcGlobalCtx,
        udp_array: &Arc<UdpSocketArray>,
        packet: &[u8],
        tid: u32,
        remote_mapped_addr: crate::proto::common::SocketAddr,
        punch_task: &AbortOnDropHandle<T>,
        mut remote_scan: Option<&mut RemotePortScanPlan>,
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
            if let Some(remote_scan) = remote_scan.as_deref_mut() {
                remote_scan.send_next(udp_array, packet).await?;
            }

            tokio::time::sleep(Duration::from_millis(200)).await;

            if finish_time.is_none() && punch_task.is_finished() {
                finish_time = Some(Instant::now());
            }

            let Some(punched) = udp_array.try_fetch_punched_socket(tid) else {
                tracing::debug!("no punched socket found, wait for more time");
                continue;
            };

            // if hole punched but tunnel creation failed, need to retry entire process.
            match try_connect_with_socket(
                global_ctx.clone(),
                punched.socket.clone(),
                punched.remote_addr,
            )
            .await
            {
                Ok(tunnel) => {
                    ret_tunnel.replace(tunnel);
                    break;
                }
                Err(e) => {
                    tracing::error!(?e, remote_addr = ?punched.remote_addr, "failed to connect with socket");
                    udp_array.add_new_socket(punched.socket).await?;
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
        peer_nat_info: UdpNatType,
    ) -> Result<Option<Box<dyn Tunnel>>, anyhow::Error> {
        // Check if peer is blacklisted
        if self.blacklist.contains(&dst_peer_id) {
            tracing::debug!(?dst_peer_id, "peer is blacklisted, skipping hole punching");
            return Ok(None);
        }

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
        let runtime_my_nat_info = runtime_nat_info_for_punch(my_nat_info, observed_spread);
        if runtime_my_nat_info != my_nat_info {
            tracing::info!(
                ?my_nat_info,
                ?runtime_my_nat_info,
                observed_spread,
                "override unknown udp nat type from runtime STUN spread"
            );
        }

        let punch_predictably = self.punch_predicablely.load(Ordering::Relaxed);
        let attempted_global_stable_punch =
            punch_predictably && observed_spread <= STABLE_PUNCH_SPREAD_MAX;
        if attempted_global_stable_punch
            && let Some(tunnel) = self
                .try_stable_socket_punch(dst_peer_id, remote_mapped_addr, &public_ips)
                .await?
        {
            return Ok(Some(tunnel));
        }

        let port_index = *last_port_idx as u32;
        let (udp_array, prediction_sockets) = self.prepare_udp_array().await?;
        let runtime_port_prediction = if punch_predictably {
            if let Some(prediction_sockets) = prediction_sockets.as_deref() {
                tokio::time::timeout(
                    Duration::from_millis(EASY_SYM_MAPPING_TIMEOUT_MS),
                    self.sample_runtime_port_prediction(
                        runtime_my_nat_info,
                        Some(prediction_sockets),
                    ),
                )
                .await
                .unwrap_or_else(|_| {
                    tracing::warn!(
                        timeout_ms = EASY_SYM_MAPPING_TIMEOUT_MS,
                        "symmetric port prediction timed out; falling back to random punch"
                    );
                    None
                })
            } else {
                None
            }
        } else {
            None
        };
        let predictable_port_window = if punch_predictably {
            let prediction = runtime_port_prediction
                .as_ref()
                .and_then(|prediction| prediction.predictable_port_window)
                .or(*self.udp_array_predictable_port_window.read().await);
            self.cache_predictable_port_window(prediction).await;
            prediction
        } else {
            None
        };

        if let Some(sockets) = prediction_sockets {
            udp_array.start_with_sockets(sockets).await?;
            self.publish_udp_array(udp_array.clone()).await;
        }

        if punch_predictably
            && let Some(runtime_port_prediction) = runtime_port_prediction.as_ref()
            && runtime_port_prediction.should_try_stable_socket_punch()
        {
            tracing::info!(
                mapped_ports = ?runtime_port_prediction.mapped_ports,
                observed_spread = runtime_port_prediction.observed_port_spread(),
                "runtime udp array samples qualify for stable-socket punch"
            );
            if let Some(tunnel) = self
                .try_runtime_stable_socket_punch(
                    dst_peer_id,
                    &udp_array,
                    remote_mapped_addr,
                    &public_ips,
                    peer_nat_info,
                    &runtime_port_prediction.mapped_ports,
                )
                .await?
            {
                return Ok(Some(tunnel));
            }
        }
        let mut remote_scan = if peer_nat_info.is_unknown() || peer_nat_info.is_sym() {
            let remote_addr: SocketAddr = remote_mapped_addr.into();
            let plan = RemotePortScanPlan::new(remote_addr, peer_nat_info);
            if let Some(plan) = plan.as_ref() {
                tracing::info!(
                    ?remote_addr,
                    ?peer_nat_info,
                    scan_kind = ?plan.kind(),
                    ports_per_tick = plan.ports_per_tick,
                    socket_limit = plan.socket_limit,
                    port_count = plan.port_count(),
                    scan_window = REMOTE_SYM_SCAN_WINDOW,
                    "enable remote symmetric port scan while punching"
                );
            }
            plan
        } else {
            None
        };

        let tid = rand::thread_rng().r#gen();
        let packet = new_hole_punch_packet(tid, HOLE_PUNCH_PACKET_BODY_LEN).into_bytes();
        udp_array.add_intreast_tid(tid);
        defer! { udp_array.remove_intreast_tid(tid);}
        udp_array
            .send_with_all(&packet, remote_mapped_addr.into())
            .await?;

        let punch_predictably = predictable_port_window.is_some();
        let punch_randomly = self.punch_randomly.load(Ordering::Relaxed);
        if !punch_predictably {
            tracing::debug!("skip predictable symmetric punch without usable port window");
        }
        if !punch_randomly {
            tracing::debug!("skip random symmetric punch because punch_randomly=false");
        }
        if !punch_predictably && !punch_randomly {
            return Ok(None);
        }

        let predictable_rpc_stub = if punch_predictably {
            Some(self.get_rpc_stub(dst_peer_id).await)
        } else {
            None
        };
        let random_rpc_stub = if punch_randomly {
            Some(self.get_rpc_stub(dst_peer_id).await)
        } else {
            None
        };
        let punch_task =
            AbortOnDropHandle::new(tokio::spawn(Self::remote_send_hole_punch_packets(
                predictable_rpc_stub,
                random_rpc_stub,
                predictable_port_window,
                runtime_my_nat_info,
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
            remote_scan.as_mut(),
        )
        .await?;

        if ret_tunnel.is_some() {
            tracing::info!(?ret_tunnel, "sym punch tasks produced tunnel");
            return Ok(ret_tunnel);
        }

        let punch_task_result = punch_task.await;
        tracing::info!(
            ?punch_task_result,
            ?ret_tunnel,
            "sym punch tasks got result"
        );

        if punch_randomly {
            if let Ok(Some(next_port_idx)) = punch_task_result {
                *last_port_idx = next_port_idx as usize;
            } else {
                *last_port_idx = rand::random();
            }
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
        assert_eq!(
            super::easy_sym_predict_window(0),
            super::EASY_SYM_PREDICT_WINDOW
        );
        assert_eq!(
            super::easy_sym_predict_window(10_000),
            super::EASY_SYM_PREDICT_WINDOW
        );
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

    #[test]
    fn unknown_nat_with_large_runtime_spread_is_treated_as_hard_symmetric() {
        let runtime_nat = super::runtime_nat_info_for_punch(super::UdpNatType::Unknown, 512);
        assert_eq!(
            runtime_nat,
            super::UdpNatType::HardSymmetric(NatType::Symmetric)
        );
    }

    #[test]
    fn unknown_nat_uses_hard_symmetric_port_prediction() {
        assert_eq!(
            super::nat_info_for_port_prediction(super::UdpNatType::Unknown),
            Some(super::UdpNatType::HardSymmetric(NatType::Symmetric))
        );

        let prediction = super::predictable_port_window_from_samples(
            super::nat_info_for_port_prediction(super::UdpNatType::Unknown).unwrap(),
            &[55_900, 56_010, 56_140],
        )
        .unwrap();

        assert_eq!(prediction.max_port_num, super::HARD_SYM_PREDICT_WINDOW);
        assert!(prediction.is_incremental);

        let ports = super::easy_sym_target_ports(
            prediction.base_port_num as u32,
            prediction.max_port_num,
            prediction.is_incremental,
        );
        assert!(ports.contains(&55_900));
        assert!(ports.contains(&56_140));
    }

    #[test]
    fn unknown_remote_nat_uses_centered_then_random_scan_plan() {
        let plan = super::RemotePortScanPlan::new(
            "198.51.100.10:45678".parse().unwrap(),
            super::UdpNatType::Unknown,
        )
        .unwrap();

        assert_eq!(plan.kind(), super::RemotePortScanKind::CenteredThenRandom);
        assert_eq!(
            plan.ports_per_tick,
            super::REMOTE_HARD_SYM_SCAN_PORTS_PER_TICK
        );
        assert_eq!(plan.socket_limit, super::REMOTE_SYM_SCAN_SOCKET_LIMIT);
        assert_eq!(plan.port_count(), u16::MAX as usize);
        assert_eq!(&plan.ports[..5], &[45_678, 45_679, 45_677, 45_680, 45_676]);
    }

    #[test]
    fn stable_predictable_port_window_covers_sampled_ports() {
        let prediction = super::stable_predictable_port_window(&[61_552, 61_553, 61_555]).unwrap();
        assert_eq!(prediction.max_port_num, super::STABLE_PUNCH_WINDOW);
        assert!(prediction.is_incremental);

        let ports = super::easy_sym_target_ports(
            prediction.base_port_num as u32,
            prediction.max_port_num,
            prediction.is_incremental,
        );
        assert!(ports.contains(&61_552));
        assert!(ports.contains(&61_553));
        assert!(ports.contains(&61_555));
    }

    #[test]
    fn wider_stable_predictable_port_window_keeps_samples_centered() {
        let prediction =
            super::stable_predictable_port_window_with_width(&[13_002, 13_003, 13_004], 16_384)
                .unwrap();
        assert_eq!(prediction.max_port_num, 16_384);
        assert!(prediction.is_incremental);

        let ports = super::easy_sym_target_ports(
            prediction.base_port_num as u32,
            prediction.max_port_num,
            prediction.is_incremental,
        );
        assert!(ports.contains(&13_002));
        assert!(ports.contains(&13_003));
        assert!(ports.contains(&13_004));
        assert_eq!(ports.first().copied(), Some(4_811));
        assert_eq!(ports.last().copied(), Some(21_194));
    }

    #[test]
    fn runtime_port_prediction_uses_sample_spread_for_stable_socket_gate() {
        let stable = super::RuntimePortPrediction {
            predictable_port_window: Some(super::PredictablePortWindow {
                base_port_num: 61_555,
                max_port_num: super::HARD_SYM_PREDICT_WINDOW,
                is_incremental: true,
            }),
            mapped_ports: vec![61_552, 61_553, 61_555],
        };
        assert_eq!(stable.observed_port_spread(), 3);
        assert!(stable.should_try_stable_socket_punch());

        let unstable = super::RuntimePortPrediction {
            predictable_port_window: stable.predictable_port_window,
            mapped_ports: vec![10_000, 10_256],
        };
        assert_eq!(unstable.observed_port_spread(), 256);
        assert!(!unstable.should_try_stable_socket_punch());

        let no_window = super::RuntimePortPrediction {
            predictable_port_window: None,
            mapped_ports: vec![61_552, 61_553, 61_555],
        };
        assert!(!no_window.should_try_stable_socket_punch());
    }

    #[test]
    fn easy_sym_inc_predicts_from_highest_runtime_sample() {
        let prediction = super::predictable_port_window_from_samples(
            super::UdpNatType::EasySymmetric(NatType::SymmetricEasyInc, true),
            &[14_552, 14_553, 14_554, 14_583],
        )
        .unwrap();

        assert_eq!(prediction.base_port_num, 14_583);
        assert_eq!(prediction.max_port_num, super::EASY_SYM_PREDICT_WINDOW);
        assert!(prediction.is_incremental);
    }

    #[test]
    fn easy_sym_dec_predicts_from_lowest_runtime_sample() {
        let prediction = super::predictable_port_window_from_samples(
            super::UdpNatType::EasySymmetric(NatType::SymmetricEasyDec, false),
            &[32_100, 32_099, 32_098, 32_070],
        )
        .unwrap();

        assert_eq!(prediction.base_port_num, 32_070);
        assert_eq!(prediction.max_port_num, super::EASY_SYM_PREDICT_WINDOW);
        assert!(!prediction.is_incremental);
    }

    #[test]
    fn hard_sym_predicts_centered_window_from_monotonic_runtime_samples() {
        let prediction = super::predictable_port_window_from_samples(
            super::UdpNatType::HardSymmetric(NatType::Symmetric),
            &[22_590, 22_640, 22_779, 23_010],
        )
        .unwrap();

        assert_eq!(prediction.base_port_num, 6_415);
        assert_eq!(prediction.max_port_num, super::HARD_SYM_PREDICT_WINDOW);
        assert!(prediction.is_incremental);

        let ports = super::easy_sym_target_ports(
            prediction.base_port_num as u32,
            prediction.max_port_num,
            prediction.is_incremental,
        );
        assert!(ports.contains(&22_590));
        assert!(ports.contains(&23_010));
        assert!(ports.contains(&30_000));
    }

    #[test]
    fn hard_sym_dec_uses_same_centered_window() {
        let prediction = super::predictable_port_window_from_samples(
            super::UdpNatType::HardSymmetric(NatType::Symmetric),
            &[23_010, 22_779, 22_640, 22_590],
        )
        .unwrap();

        assert_eq!(prediction.base_port_num, 6_415);
        assert_eq!(prediction.max_port_num, super::HARD_SYM_PREDICT_WINDOW);
        assert!(prediction.is_incremental);
    }

    #[test]
    fn hard_sym_centered_window_covers_real_low_peer_port() {
        let prediction = super::predictable_port_window_from_samples(
            super::UdpNatType::HardSymmetric(NatType::Symmetric),
            &[
                8_121, 8_122, 8_123, 8_124, 8_125, 8_126, 8_128, 8_129, 8_130, 8_131, 8_133, 8_134,
                8_135, 8_136, 8_137, 8_138, 8_140, 8_141, 8_142, 8_143, 8_144, 8_145, 8_146, 8_553,
                8_554, 8_555, 8_556, 8_557, 8_558, 8_559, 8_560, 8_561,
            ],
        )
        .unwrap();

        assert_eq!(prediction.base_port_num, 0);
        assert_eq!(prediction.max_port_num, super::HARD_SYM_PREDICT_WINDOW);
        assert!(prediction.is_incremental);

        let ports = super::easy_sym_target_ports(
            prediction.base_port_num as u32,
            prediction.max_port_num,
            prediction.is_incremental,
        );
        assert_eq!(ports.first().copied(), Some(1));
        assert_eq!(ports.last().copied(), Some(32_768));
        assert!(ports.contains(&4_866));
        assert!(ports.contains(&8_121));
        assert!(ports.contains(&8_561));
    }

    #[test]
    fn hard_sym_rejects_non_monotonic_runtime_samples() {
        let prediction = super::predictable_port_window_from_samples(
            super::UdpNatType::HardSymmetric(NatType::Symmetric),
            &[22_590, 22_640, 22_620, 23_010],
        );

        assert!(prediction.is_none());
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
