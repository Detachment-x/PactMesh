use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use rand::seq::SliceRandom;
use tokio::sync::Mutex;
use tokio_util::task::AbortOnDropHandle;

use crate::{
    common::{PeerId, stun::StunInfoCollectorTrait},
    connector::udp_hole_punch::common::{
        HOLE_PUNCH_PACKET_BODY_LEN, UdpHolePunchListener, try_connect_with_socket,
    },
    connector::udp_hole_punch::handle_rpc_result,
    peers::peer_manager::PeerManager,
    proto::{
        peer_rpc::{
            SendPunchPacketBothEasySymRequest, SendPunchPacketBothEasySymResponse,
            UdpHolePunchRpcClientFactory,
        },
        rpc_types::{self, controller::BaseController},
    },
    tunnel::{Tunnel, udp::new_hole_punch_packet},
};

use super::common::{PunchHoleServerCommon, UdpNatType, UdpSocketArray};

const UDP_ARRAY_SIZE_FOR_BOTH_EASY_SYM: usize = 25;
const DST_PORT_OFFSET: u16 = 20;
const REMOTE_WAIT_TIME_MS: u64 = 5000;
const COORDINATED_SYM_MAX_WAIT_TIME_MS: u32 = 20_000;
const COORDINATED_SYM_PORTS_PER_TICK: usize = 128;
const COORDINATED_SYM_CENTERED_PORTS_PER_TICK: usize = 64;
const COORDINATED_SYM_RANDOM_PORTS_PER_TICK: usize = 64;
const COORDINATED_SYM_SOCKET_LIMIT: usize = 16;

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

fn best_effort_cached_udp_mapped_addr(
    global_ctx: &crate::common::global_ctx::ArcGlobalCtx,
    local_port: u16,
) -> Option<SocketAddr> {
    let stun_info = global_ctx.get_stun_info_collector().get_stun_info();
    let public_ip = stun_info
        .public_ip
        .iter()
        .find_map(|ip| ip.parse::<Ipv4Addr>().ok())?;

    let min_port = u16::try_from(stun_info.min_port)
        .ok()
        .filter(|port| *port != 0);
    let max_port = u16::try_from(stun_info.max_port)
        .ok()
        .filter(|port| *port != 0);
    let port = match (min_port, max_port) {
        (Some(min_port), Some(max_port)) => {
            let lo = min_port.min(max_port) as u32;
            let hi = min_port.max(max_port) as u32;
            (lo + hi.saturating_sub(lo) / 2) as u16
        }
        _ if local_port != 0 => local_port,
        _ => 1,
    };

    Some(SocketAddr::V4(SocketAddrV4::new(public_ip, port)))
}

#[derive(Debug)]
struct CoordinatedSymPortPlan {
    public_ip: Ipv4Addr,
    centered_ports: Vec<u16>,
    random_ports: Vec<u16>,
    next_centered_idx: usize,
    next_random_idx: usize,
    coordinated: bool,
}

impl CoordinatedSymPortPlan {
    fn new(request: &SendPunchPacketBothEasySymRequest, public_ip: Ipv4Addr) -> Self {
        let coordinated = request.dst_max_port_num > 0 || request.dst_random_scan;
        let centered_ports = if request.dst_max_port_num > 0 {
            easy_sym_target_ports(
                request.dst_base_port_num,
                request.dst_max_port_num,
                request.dst_is_incremental,
            )
        } else if request.dst_port_num == 0 {
            Vec::new()
        } else {
            vec![request.dst_port_num as u16]
        };

        let mut random_ports = Vec::new();
        if request.dst_random_scan {
            let mut included = vec![false; u16::MAX as usize + 1];
            for port in centered_ports.iter().copied() {
                included[port as usize] = true;
            }
            random_ports.reserve(u16::MAX as usize - centered_ports.len());
            for port in 1..=u16::MAX {
                if !included[port as usize] {
                    random_ports.push(port);
                }
            }
            random_ports.shuffle(&mut rand::thread_rng());
        }

        Self {
            public_ip,
            centered_ports,
            random_ports,
            next_centered_idx: 0,
            next_random_idx: 0,
            coordinated,
        }
    }

    fn port_count(&self) -> usize {
        self.centered_ports.len() + self.random_ports.len()
    }

    fn next_ports_for_tick(&mut self) -> Vec<u16> {
        if !self.coordinated {
            return self.centered_ports.first().copied().into_iter().collect();
        }

        let centered_count = if self.random_ports.is_empty() {
            COORDINATED_SYM_PORTS_PER_TICK
        } else {
            COORDINATED_SYM_CENTERED_PORTS_PER_TICK
        }
        .min(self.centered_ports.len());
        let random_count = if self.random_ports.is_empty() {
            0
        } else {
            COORDINATED_SYM_RANDOM_PORTS_PER_TICK
        }
        .min(self.random_ports.len());

        let mut ports = Vec::with_capacity(centered_count + random_count);
        for _ in 0..centered_count {
            ports.push(self.centered_ports[self.next_centered_idx % self.centered_ports.len()]);
            self.next_centered_idx = (self.next_centered_idx + 1) % self.centered_ports.len();
        }
        for _ in 0..random_count {
            ports.push(self.random_ports[self.next_random_idx % self.random_ports.len()]);
            self.next_random_idx = (self.next_random_idx + 1) % self.random_ports.len();
        }

        ports
    }

    async fn send_next(
        &mut self,
        udp_array: &UdpSocketArray,
        packet: &[u8],
    ) -> Result<(), anyhow::Error> {
        let ports = self.next_ports_for_tick();
        if ports.is_empty() {
            return Ok(());
        }

        let sockets = udp_array.sockets();
        let socket_limit = if self.coordinated {
            COORDINATED_SYM_SOCKET_LIMIT.min(sockets.len())
        } else {
            sockets.len()
        };
        for port in ports {
            let addr = SocketAddr::V4(SocketAddrV4::new(self.public_ip, port));
            for socket in sockets.iter().take(socket_limit) {
                for _ in 0..3 {
                    socket.send_to(packet, addr).await?;
                }
            }
        }
        Ok(())
    }
}

pub(crate) struct PunchBothEasySymHoleServer {
    common: Arc<PunchHoleServerCommon>,
    task: Mutex<Option<AbortOnDropHandle<()>>>,
}

impl PunchBothEasySymHoleServer {
    pub(crate) fn new(common: Arc<PunchHoleServerCommon>) -> Self {
        Self {
            common,
            task: Mutex::new(None),
        }
    }

    // hard sym means public port is random and cannot be predicted
    #[tracing::instrument(skip(self), ret, err)]
    pub(crate) async fn send_punch_packet_both_easy_sym(
        &self,
        request: SendPunchPacketBothEasySymRequest,
    ) -> Result<SendPunchPacketBothEasySymResponse, rpc_types::error::Error> {
        tracing::info!("send_punch_packet_both_easy_sym start");
        let busy_resp = Ok(SendPunchPacketBothEasySymResponse {
            is_busy: true,
            ..Default::default()
        });
        let Ok(mut locked_task) = self.task.try_lock() else {
            return busy_resp;
        };
        if locked_task.is_some() && !locked_task.as_ref().unwrap().is_finished() {
            return busy_resp;
        }

        let global_ctx = self.common.get_global_ctx();

        tracing::info!("send_punch_packet_hard_sym start");
        let socket_count = request.udp_socket_count as usize;
        let public_ip = request
            .public_ip
            .ok_or(anyhow::anyhow!("public_ip is required"))?;
        let public_ip = Ipv4Addr::from(public_ip);
        let transaction_id = request.transaction_id;
        let coordinated = request.dst_max_port_num > 0 || request.dst_random_scan;

        let udp_array = UdpSocketArray::new(socket_count, global_ctx.net_ns.clone());
        let cur_mapped_addr = if coordinated {
            let sockets = udp_array.bind_sockets().await?;
            let local_port = sockets
                .first()
                .and_then(|socket| socket.local_addr().ok())
                .map(|addr| addr.port())
                .unwrap_or(0);
            let mapped_addr = best_effort_cached_udp_mapped_addr(&global_ctx, local_port)
                .ok_or(anyhow::anyhow!("failed to get cached udp mapped addr"))?;
            udp_array.start_with_sockets(sockets).await?;
            mapped_addr
        } else {
            let mapped_addr = global_ctx
                .get_stun_info_collector()
                .get_udp_port_mapping(0)
                .await
                .with_context(|| "failed to get udp port mapping")?;
            udp_array.start().await?;
            mapped_addr
        };
        udp_array.add_intreast_tid(transaction_id);
        let peer_mgr = self.common.get_peer_mgr();

        let punch_packet =
            new_hole_punch_packet(transaction_id, HOLE_PUNCH_PACKET_BODY_LEN).into_bytes();
        let mut punched = vec![];
        let common = self.common.clone();
        let mut port_plan = CoordinatedSymPortPlan::new(&request, public_ip);
        tracing::info!(
            coordinated,
            mapped_addr = ?cur_mapped_addr,
            target_port_count = port_plan.port_count(),
            "send_punch_packet_both_easy_sym target plan"
        );

        let task = tokio::spawn(async move {
            let mut listeners = Vec::new();
            let start_time = Instant::now();
            let wait_time_ms = if coordinated {
                request.wait_time_ms.min(COORDINATED_SYM_MAX_WAIT_TIME_MS)
            } else {
                request.wait_time_ms.min(8000)
            };
            while start_time.elapsed() < Duration::from_millis(wait_time_ms as u64) {
                if let Err(e) = port_plan.send_next(&udp_array, &punch_packet).await {
                    tracing::error!(?e, "failed to send coordinated hole punch packet");
                    break;
                }

                tokio::time::sleep(Duration::from_millis(100)).await;

                if let Some(s) = udp_array.try_fetch_punched_socket(transaction_id) {
                    tracing::info!(?s, ?transaction_id, "got punched socket in both easy sym");
                    assert!(Arc::strong_count(&s.socket) == 1);
                    let Some(port) = s.socket.local_addr().ok().map(|addr| addr.port()) else {
                        tracing::warn!("failed to get local addr from punched socket");
                        continue;
                    };
                    let remote_addr = s.remote_addr;
                    drop(s);

                    let listener =
                        match UdpHolePunchListener::new_ext(peer_mgr.clone(), false, Some(port))
                            .await
                        {
                            Ok(l) => l,
                            Err(e) => {
                                tracing::warn!(?e, "failed to create listener");
                                continue;
                            }
                        };
                    punched.push((listener.get_socket().await, remote_addr));
                    listeners.push(listener);
                }

                // if any listener is punched, we can break the loop
                for l in &listeners {
                    if l.get_conn_count().await > 0 {
                        tracing::info!(?l, "got punched listener");
                        break;
                    }
                }

                if !punched.is_empty() {
                    tracing::debug!(?punched, "got punched socket and keep sending punch packet");
                }

                for p in &punched {
                    let (socket, remote_addr) = p;
                    let send_remote_ret = socket.send_to(&punch_packet, remote_addr).await;
                    tracing::debug!(
                        ?send_remote_ret,
                        ?socket,
                        "send hole punch packet to punched remote"
                    );
                }
            }

            for l in listeners {
                if l.get_conn_count().await > 0 {
                    common.add_listener(l).await;
                }
            }
        });

        *locked_task = Some(AbortOnDropHandle::new(task));
        return Ok(SendPunchPacketBothEasySymResponse {
            is_busy: false,
            base_mapped_addr: Some(cur_mapped_addr.into()),
        });
    }
}

#[derive(Debug)]
pub(crate) struct PunchBothEasySymHoleClient {
    peer_mgr: Arc<PeerManager>,
    blacklist: Arc<timedmap::TimedMap<PeerId, ()>>,
}

impl PunchBothEasySymHoleClient {
    pub(crate) fn new(
        peer_mgr: Arc<PeerManager>,
        blacklist: Arc<timedmap::TimedMap<PeerId, ()>>,
    ) -> Self {
        Self {
            peer_mgr,
            blacklist,
        }
    }

    #[tracing::instrument(ret)]
    pub(crate) async fn do_hole_punching(
        &self,
        dst_peer_id: PeerId,
        my_nat_info: UdpNatType,
        peer_nat_info: UdpNatType,
        is_busy: &mut bool,
    ) -> Result<Option<Box<dyn Tunnel>>, anyhow::Error> {
        // Check if peer is blacklisted
        if self.blacklist.contains(&dst_peer_id) {
            tracing::debug!(?dst_peer_id, "peer is blacklisted, skipping hole punching");
            return Ok(None);
        }

        *is_busy = false;

        let udp_array = UdpSocketArray::new(
            UDP_ARRAY_SIZE_FOR_BOTH_EASY_SYM,
            self.peer_mgr.get_global_ctx().net_ns.clone(),
        );
        udp_array.start().await?;

        let global_ctx = self.peer_mgr.get_global_ctx();
        let cur_mapped_addr = global_ctx
            .get_stun_info_collector()
            .get_udp_port_mapping(0)
            .await
            .with_context(|| "failed to get udp port mapping")?;
        let my_public_ip = match cur_mapped_addr.ip() {
            IpAddr::V4(v4) => v4,
            _ => {
                anyhow::bail!("ipv6 is not supported");
            }
        };
        let me_is_incremental = my_nat_info
            .get_inc_of_easy_sym()
            .ok_or(anyhow::anyhow!("me_is_incremental is required"))?;
        let peer_is_incremental = peer_nat_info
            .get_inc_of_easy_sym()
            .ok_or(anyhow::anyhow!("peer_is_incremental is required"))?;

        let rpc_stub = self
            .peer_mgr
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<UdpHolePunchRpcClientFactory<BaseController>>(
                self.peer_mgr.my_peer_id(),
                dst_peer_id,
                global_ctx.get_network_name(),
            );

        let tid = rand::random();
        udp_array.add_intreast_tid(tid);

        let remote_ret = rpc_stub
            .send_punch_packet_both_easy_sym(
                BaseController {
                    timeout_ms: 2000,
                    ..Default::default()
                },
                SendPunchPacketBothEasySymRequest {
                    transaction_id: tid,
                    public_ip: Some(my_public_ip.into()),
                    dst_port_num: if me_is_incremental {
                        cur_mapped_addr.port().saturating_add(DST_PORT_OFFSET)
                    } else {
                        cur_mapped_addr.port().saturating_sub(DST_PORT_OFFSET)
                    } as u32,
                    udp_socket_count: UDP_ARRAY_SIZE_FOR_BOTH_EASY_SYM as u32,
                    wait_time_ms: REMOTE_WAIT_TIME_MS as u32,
                    dst_base_port_num: 0,
                    dst_max_port_num: 0,
                    dst_is_incremental: false,
                    dst_random_scan: false,
                },
            )
            .await;

        let remote_ret = handle_rpc_result(remote_ret, dst_peer_id, &self.blacklist)?;

        if remote_ret.is_busy {
            *is_busy = true;
            anyhow::bail!("remote is busy");
        }

        let mut remote_mapped_addr = remote_ret
            .base_mapped_addr
            .ok_or(anyhow::anyhow!("remote_mapped_addr is required"))?;

        let now = Instant::now();
        remote_mapped_addr.port = if peer_is_incremental {
            remote_mapped_addr
                .port
                .saturating_add(DST_PORT_OFFSET as u32)
        } else {
            remote_mapped_addr
                .port
                .saturating_sub(DST_PORT_OFFSET as u32)
        };
        tracing::debug!(
            ?remote_mapped_addr,
            ?remote_ret,
            "start send hole punch packet for both easy sym"
        );

        while now.elapsed().as_millis() < (REMOTE_WAIT_TIME_MS + 1000).into() {
            udp_array
                .send_with_all(
                    &new_hole_punch_packet(tid, HOLE_PUNCH_PACKET_BODY_LEN).into_bytes(),
                    remote_mapped_addr.into(),
                )
                .await?;

            tokio::time::sleep(Duration::from_millis(100)).await;

            let Some(socket) = udp_array.try_fetch_punched_socket(tid) else {
                tracing::trace!(
                    ?remote_mapped_addr,
                    ?tid,
                    "no punched socket found, send some more hole punch packets"
                );
                continue;
            };

            tracing::info!(
                ?socket,
                ?remote_mapped_addr,
                ?tid,
                "got punched socket in both easy sym"
            );

            for _ in 0..2 {
                match try_connect_with_socket(
                    global_ctx.clone(),
                    socket.socket.clone(),
                    remote_mapped_addr.into(),
                )
                .await
                {
                    Ok(tunnel) => {
                        return Ok(Some(tunnel));
                    }
                    Err(e) => {
                        tracing::error!(?e, "failed to connect with socket");
                        continue;
                    }
                }
            }
            udp_array.add_new_socket(socket.socket).await?;
        }

        Ok(None)
    }
}

#[cfg(test)]
pub mod tests {
    use std::{
        sync::{Arc, atomic::AtomicU32},
        time::Duration,
    };

    use tokio::net::UdpSocket;

    use crate::connector::udp_hole_punch::RUN_TESTING;
    use crate::{
        connector::udp_hole_punch::{
            UdpHolePunchConnector, tests::create_mock_peer_manager_with_mock_stun,
        },
        peers::tests::{connect_peer_manager, wait_route_appear},
        proto::common::NatType,
        tunnel::common::tests::wait_for_condition,
    };

    #[rstest::rstest]
    #[tokio::test]
    #[serial_test::serial(hole_punch)]
    async fn hole_punching_easy_sym(#[values("true", "false")] is_inc: bool) {
        RUN_TESTING.store(true, std::sync::atomic::Ordering::Relaxed);

        let p_a = create_mock_peer_manager_with_mock_stun(if is_inc {
            NatType::SymmetricEasyInc
        } else {
            NatType::SymmetricEasyDec
        })
        .await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_c = create_mock_peer_manager_with_mock_stun(if !is_inc {
            NatType::SymmetricEasyInc
        } else {
            NatType::SymmetricEasyDec
        })
        .await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        let mut hole_punching_a = UdpHolePunchConnector::new(p_a.clone());
        let mut hole_punching_c = UdpHolePunchConnector::new(p_c.clone());

        hole_punching_a.run().await.unwrap();
        hole_punching_c.run().await.unwrap();

        // 144 + DST_PORT_OFFSET = 164
        let udp1 = Arc::new(UdpSocket::bind("0.0.0.0:40164").await.unwrap());
        // 144 - DST_PORT_OFFSET = 124
        let udp2 = Arc::new(UdpSocket::bind("0.0.0.0:40124").await.unwrap());
        let udps = [udp1, udp2];

        let counter = Arc::new(AtomicU32::new(0));

        // all these sockets should receive hole punching packet
        for udp in udps.iter().map(Arc::clone) {
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let (len, addr) = udp.recv_from(&mut buf).await.unwrap();
                println!(
                    "got predictable punch packet, {:?} {:?} {:?}",
                    len,
                    addr,
                    udp.local_addr()
                );
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            });
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
