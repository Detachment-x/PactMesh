use std::{
    net::Ipv4Addr,
    ops::{Div, Mul},
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
    common::{PeerId, global_ctx::ArcGlobalCtx, stun::StunInfoCollectorTrait},
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

fn easy_sym_predict_window(observed_span: u32) -> u32 {
    observed_span
        .saturating_add((UDP_ARRAY_SIZE_FOR_HARD_SYM as u32) * 16)
        .saturating_add(512)
        .clamp(1024, 4096)
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

        let port_start = if is_incremental {
            base_port_num.saturating_add(1)
        } else {
            base_port_num.saturating_sub(max_port_num)
        };

        let port_end = if is_incremental {
            base_port_num.saturating_add(max_port_num)
        } else {
            base_port_num.saturating_sub(1)
        };

        if port_end <= port_start {
            return Err(anyhow::anyhow!("send_punch_packet_easy_sym invalid port range").into());
        }

        let ports = (port_start..=port_end)
            .map(|x| x as u16)
            .collect::<Vec<_>>();
        tracing::debug!(
            ?ports,
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

        // send max k1 packets if we are predicting the dst port
        let max_k1: u32 = 180;
        // send max k2 packets if we are sending to random port
        let mut max_k2: u32 = rand::thread_rng().gen_range(600..800);
        if round > 2 {
            max_k2 = max_k2.mul(2).div(round).max(max_k1);
        }

        let mut next_port_index = 0;
        for _ in 0..2 {
            next_port_index = send_symmetric_hole_punch_packet(
                &self.shuffled_port_vec,
                listener.clone(),
                transaction_id,
                &public_ips,
                last_port_index,
                max_k2 as usize,
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
            tracing::debug!(?my_nat_info, "skip predictable punch for non-easy-symmetric NAT");
            return;
        };
        let Some((base_port_num, max_port_num)) = base_port_for_easy_sym else {
            tracing::debug!(?my_nat_info, "skip predictable punch without easy-symmetric port mapping");
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
                    timeout_ms: 4000,
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
        while finish_time.is_none() || finish_time.as_ref().unwrap().elapsed().as_millis() < 1000 {
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
