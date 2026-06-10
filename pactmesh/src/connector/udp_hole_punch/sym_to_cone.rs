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
    common::{
        PeerId,
        global_ctx::ArcGlobalCtx,
        stun::{StunInfoCollectorTrait, get_udp_port_mapping_with_socket_and_server},
        upnp,
    },
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
            SelectPunchListenerRequest, SendPunchPacketBothEasySymRequest,
            SendPunchPacketEasySymRequest, SendPunchPacketHardSymRequest,
            SendPunchPacketHardSymResponse, UdpHolePunchRpc, UdpHolePunchRpcClientFactory,
            WarmPunchListenerRequest,
        },
        rpc_types::{self, controller::BaseController},
    },
    tunnel::{Tunnel, udp::new_hole_punch_packet},
};

use super::common::{PunchHoleServerCommon, UdpNatType, UdpSocketArray};

const UDP_ARRAY_SIZE_FOR_HARD_SYM: usize = 84;
const PEER_REFLEXIVE_MAPPING_PROBES: usize = 6;
const EASY_SYM_MAPPING_TIMEOUT_MS: u64 = 30_000;
const PEER_REFLEXIVE_MAPPING_TIMEOUT_MS: u64 = 2500;
const PEER_REFLEXIVE_PREWARM_PORT_WINDOW: u32 = 2048;
const PEER_REFLEXIVE_PREWARM_PACKET_COUNT: u32 = 2;
const PEER_REFLEXIVE_PREWARM_CANDIDATE_PROBES: usize = 3;
const PEER_REFLEXIVE_PREWARM_RPC_TIMEOUT_MS: i32 = 8_000;
const PEER_REFLEXIVE_PREWARM_SETTLE_MS: u64 = 150;
const PUNCH_RESULT_GRACE_MS: u128 = 2000;
const PREDICTABLE_PUNCH_RPC_TIMEOUT_MS: i32 = 30_000;
const RANDOM_PUNCH_RPC_TIMEOUT_MS: i32 = 20_000;
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

const HARD_SYM_RANDOM_PASSES: usize = 3;
const HARD_SYM_RANDOM_PORTS_PER_PASS_MIN: u32 = 3072;
const HARD_SYM_RANDOM_PORTS_PER_PASS_MAX: u32 = 4096;
const HARD_SYM_PREDICT_MIN_SAMPLES: usize = 3;
const REMOTE_SYM_SCAN_PORTS_PER_TICK: usize = 32;
const REMOTE_HARD_SYM_SCAN_PORTS_PER_TICK: usize = 192;
const REMOTE_SYM_SCAN_WINDOW: u16 = 4096;
const REMOTE_SYM_SCAN_SOCKET_LIMIT: usize = 16;
const REMOTE_HARD_SYM_CENTERED_PORTS_PER_TICK: usize = 64;
const REMOTE_HARD_SYM_RANDOM_PORTS_PER_TICK: usize = 128;
const REMOTE_SYM_PRIORITY_PORTS_PER_TICK: usize = 32;
const REMOTE_SYM_PRIORITY_SCAN_WINDOW: u16 = 2048;
const COORDINATED_SYM_ARRAY_SIZE: usize = 48;
const COORDINATED_SYM_WAIT_MS: u64 = 30_000;
const COORDINATED_SYM_SCAN_WINDOW: u32 = HARD_SYM_PREDICT_WINDOW;
const LEARNED_ENDPOINTS_PER_TICK: usize = 8;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimePortPredictionSource {
    PeerReflexive,
    PublicStunFallback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimePortPrediction {
    predictable_port_window: Option<PredictablePortWindow>,
    mapped_ports: Vec<u16>,
    sample_source: RuntimePortPredictionSource,
}

impl RuntimePortPrediction {
    fn observed_port_spread(&self) -> u32 {
        observed_port_spread(&self.mapped_ports)
    }

    fn is_peer_reflexive(&self) -> bool {
        self.sample_source == RuntimePortPredictionSource::PeerReflexive
    }

    fn should_try_stable_socket_punch(&self) -> bool {
        self.is_peer_reflexive()
            && self.predictable_port_window.is_some()
            && self.observed_port_spread() <= STABLE_PUNCH_SPREAD_MAX
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OrderedPortSamples {
    is_incremental: bool,
    crosses_boundary: bool,
    spread: u32,
    last: u16,
    min: u16,
    max: u16,
}

fn forward_port_delta(from: u16, to: u16) -> u32 {
    if to >= from {
        to.saturating_sub(from) as u32
    } else {
        u16::MAX as u32 - from as u32 + to as u32
    }
}

fn backward_port_delta(from: u16, to: u16) -> u32 {
    if from >= to {
        from.saturating_sub(to) as u32
    } else {
        from as u32 + u16::MAX as u32 - to as u32
    }
}

fn ordered_delta_sum(mapped_ports: &[u16], is_incremental: bool) -> Option<(u32, bool)> {
    let mut spread = 0u32;
    let mut crosses_boundary = false;
    for ports in mapped_ports.windows(2) {
        let delta = if is_incremental {
            crosses_boundary |= ports[1] < ports[0];
            forward_port_delta(ports[0], ports[1])
        } else {
            crosses_boundary |= ports[1] > ports[0];
            backward_port_delta(ports[0], ports[1])
        };
        if delta == 0 || delta > HARD_SYM_PREDICT_WINDOW {
            return None;
        }
        spread = spread.saturating_add(delta);
        if spread > HARD_SYM_PREDICT_WINDOW {
            return None;
        }
    }
    Some((spread, crosses_boundary))
}

fn infer_ordered_port_samples(mapped_ports: &[u16]) -> Option<OrderedPortSamples> {
    if mapped_ports.len() < HARD_SYM_PREDICT_MIN_SAMPLES {
        return None;
    }

    let inc = ordered_delta_sum(mapped_ports, true);
    let dec = ordered_delta_sum(mapped_ports, false);
    let (is_incremental, spread, crosses_boundary) = match (inc, dec) {
        (Some((spread, crosses_boundary)), None) => (true, spread, crosses_boundary),
        (None, Some((spread, crosses_boundary))) => (false, spread, crosses_boundary),
        _ => return None,
    };

    let min = *mapped_ports.iter().min()?;
    let max = *mapped_ports.iter().max()?;
    Some(OrderedPortSamples {
        is_incremental,
        crosses_boundary,
        spread,
        last: *mapped_ports.last()?,
        min,
        max,
    })
}

fn infer_ordered_port_direction(mapped_ports: &[u16]) -> Option<bool> {
    infer_ordered_port_samples(mapped_ports).map(|samples| samples.is_incremental)
}

fn observed_port_spread(mapped_ports: &[u16]) -> u32 {
    if let Some(samples) = infer_ordered_port_samples(mapped_ports) {
        return samples.spread;
    }

    let Some(min_port) = mapped_ports.iter().min() else {
        return 0;
    };
    let Some(max_port) = mapped_ports.iter().max() else {
        return 0;
    };

    max_port.saturating_sub(*min_port) as u32
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

fn should_try_coordinated_symmetric_punch(
    my_nat_info: UdpNatType,
    peer_nat_info: UdpNatType,
) -> bool {
    (my_nat_info.is_unknown() || my_nat_info.is_sym())
        && (peer_nat_info.is_unknown() || peer_nat_info.is_sym())
}

fn stun_info_port_window(
    stun_info: &crate::proto::common::StunInfo,
) -> Option<PredictablePortWindow> {
    let min_port = u16::try_from(stun_info.min_port).ok()?;
    let max_port = u16::try_from(stun_info.max_port).ok()?;
    if min_port == 0 || max_port == 0 {
        return None;
    }

    Some(centered_predictable_port_window(
        min_port.min(max_port),
        min_port.max(max_port),
        COORDINATED_SYM_SCAN_WINDOW,
    ))
}

fn coordinated_symmetric_target_window(
    runtime_prediction: Option<&RuntimePortPrediction>,
    _stun_info: &crate::proto::common::StunInfo,
) -> Option<PredictablePortWindow> {
    runtime_prediction
        .filter(|prediction| prediction.is_peer_reflexive())
        .and_then(|prediction| {
            prediction.predictable_port_window.or_else(|| {
                stable_predictable_port_window_with_width(
                    &prediction.mapped_ports,
                    COORDINATED_SYM_SCAN_WINDOW,
                )
            })
        })
}

fn select_runtime_port_prediction(
    sampled_prediction: Option<RuntimePortPrediction>,
    cached_prediction: Option<RuntimePortPrediction>,
) -> Option<RuntimePortPrediction> {
    match sampled_prediction {
        Some(sampled_prediction) if sampled_prediction.is_peer_reflexive() => {
            Some(sampled_prediction)
        }
        Some(sampled_prediction) => cached_prediction.or(Some(sampled_prediction)),
        None => cached_prediction,
    }
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
    let observed_span = observed_port_spread(mapped_ports);

    let Some(is_incremental) = known_inc else {
        let ordered_samples = infer_ordered_port_samples(mapped_ports)?;
        if ordered_samples.crosses_boundary {
            return Some(PredictablePortWindow {
                base_port_num: ordered_samples.last,
                max_port_num: HARD_SYM_PREDICT_WINDOW,
                is_incremental: ordered_samples.is_incremental,
            });
        }
        return Some(hard_sym_centered_port_window(
            ordered_samples.min,
            ordered_samples.max,
        ));
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

#[derive(Debug, Default)]
struct PortScanTickStats {
    port_count: usize,
    socket_count: usize,
    packet_count: usize,
    first_port: Option<u16>,
    last_port: Option<u16>,
    sample_ports: Vec<u16>,
}

struct RemotePortScanPlan {
    public_ip: Ipv4Addr,
    priority_ports: Vec<u16>,
    centered_ports: Vec<u16>,
    random_ports: Vec<u16>,
    next_priority_idx: usize,
    next_centered_idx: usize,
    next_random_idx: usize,
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

fn wrapping_add_port(base: u16, offset: u16) -> u16 {
    ((base as u32 + offset as u32 - 1) % u16::MAX as u32 + 1) as u16
}

fn wrapping_sub_port(base: u16, offset: u16) -> u16 {
    ((base as i32 - offset as i32 - 1).rem_euclid(u16::MAX as i32) + 1) as u16
}

fn push_unique_port(ports: &mut Vec<u16>, seen_ports: &mut [bool], port: u16) {
    if !seen_ports[port as usize] {
        seen_ports[port as usize] = true;
        ports.push(port);
    }
}

fn priority_ports_around_hints(hints: &[u32], window: u16) -> Vec<u16> {
    let mut bases = Vec::new();
    let mut seen_bases = vec![false; u16::MAX as usize + 1];
    for port in hints.iter().filter_map(|port| u16::try_from(*port).ok()) {
        if port == 0 || seen_bases[port as usize] {
            continue;
        }
        seen_bases[port as usize] = true;
        bases.push(port);
    }

    let mut seen_ports = vec![false; u16::MAX as usize + 1];
    let mut ports = Vec::new();
    for offset in 0..=window {
        for base in bases.iter().copied() {
            if offset == 0 {
                push_unique_port(&mut ports, &mut seen_ports, base);
                continue;
            }

            push_unique_port(&mut ports, &mut seen_ports, wrapping_add_port(base, offset));
            push_unique_port(&mut ports, &mut seen_ports, wrapping_sub_port(base, offset));
        }
    }

    ports
}

fn filter_known_ports(ports: Vec<u16>, known_ports: &[bool]) -> Vec<u16> {
    ports
        .into_iter()
        .filter(|port| !known_ports[*port as usize])
        .collect()
}

fn mark_ports(known_ports: &mut [bool], ports: &[u16]) {
    for port in ports.iter().copied() {
        known_ports[port as usize] = true;
    }
}

fn push_unique_port_num(ports: &mut Vec<u32>, port: u16) {
    if port == 0 {
        return;
    }

    let port = port as u32;
    if !ports.contains(&port) {
        ports.push(port);
    }
}

fn push_unique_socket_addr(addrs: &mut Vec<SocketAddr>, addr: SocketAddr) {
    if !addrs.contains(&addr) {
        addrs.push(addr);
    }
}

impl RemotePortScanPlan {
    fn new(
        remote_addr: SocketAddr,
        peer_nat_info: UdpNatType,
        priority_port_nums: &[u32],
    ) -> Option<Self> {
        let remote_addr = match remote_addr {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => return None,
        };
        let public_ip = *remote_addr.ip();
        let base_port = remote_addr.port();
        let priority_ports =
            priority_ports_around_hints(priority_port_nums, REMOTE_SYM_PRIORITY_SCAN_WINDOW);
        let mut included = vec![false; u16::MAX as usize + 1];
        mark_ports(&mut included, &priority_ports);
        let centered_ports = filter_known_ports(
            centered_ports_around(base_port, REMOTE_SYM_SCAN_WINDOW),
            &included,
        );
        mark_ports(&mut included, &centered_ports);

        if peer_nat_info.is_unknown() || peer_nat_info.is_hard_sym() {
            let mut remaining_ports =
                Vec::with_capacity(u16::MAX as usize - priority_ports.len() - centered_ports.len());
            for port in 1..=u16::MAX {
                if !included[port as usize] {
                    remaining_ports.push(port);
                }
            }
            remaining_ports.shuffle(&mut rand::thread_rng());

            return Some(Self {
                public_ip,
                priority_ports,
                centered_ports,
                random_ports: remaining_ports,
                next_priority_idx: 0,
                next_centered_idx: 0,
                next_random_idx: 0,
                ports_per_tick: REMOTE_HARD_SYM_SCAN_PORTS_PER_TICK,
                socket_limit: REMOTE_SYM_SCAN_SOCKET_LIMIT,
                kind: RemotePortScanKind::CenteredThenRandom,
            });
        }

        Some(Self {
            public_ip,
            priority_ports,
            centered_ports,
            random_ports: Vec::new(),
            next_priority_idx: 0,
            next_centered_idx: 0,
            next_random_idx: 0,
            ports_per_tick: REMOTE_SYM_SCAN_PORTS_PER_TICK,
            socket_limit: usize::MAX,
            kind: RemotePortScanKind::Centered,
        })
    }

    fn kind(&self) -> RemotePortScanKind {
        self.kind
    }

    fn port_count(&self) -> usize {
        self.priority_ports.len() + self.centered_ports.len() + self.random_ports.len()
    }

    fn preview_ports(&self, count: usize) -> Vec<u16> {
        let priority_count = REMOTE_SYM_PRIORITY_PORTS_PER_TICK
            .min(self.priority_ports.len())
            .min(count);
        let remaining_count = count.saturating_sub(priority_count);
        let mut ports: Vec<u16> = self
            .priority_ports
            .iter()
            .copied()
            .take(priority_count)
            .collect();
        match self.kind {
            RemotePortScanKind::Centered => {
                ports.extend(self.centered_ports.iter().copied().take(remaining_count))
            }
            RemotePortScanKind::CenteredThenRandom => {
                let centered_count = if self.priority_ports.is_empty() {
                    REMOTE_HARD_SYM_CENTERED_PORTS_PER_TICK.min(remaining_count)
                } else {
                    (remaining_count / 2).min(self.centered_ports.len())
                };
                ports.extend(self.centered_ports.iter().copied().take(centered_count));
                ports.extend(
                    self.random_ports
                        .iter()
                        .copied()
                        .take(remaining_count.saturating_sub(centered_count)),
                );
            }
        }
        ports
    }

    fn push_cyclic_ports(dst: &mut Vec<u16>, src: &[u16], next_idx: &mut usize, count: usize) {
        if src.is_empty() {
            return;
        }
        for _ in 0..count.min(src.len()) {
            dst.push(src[*next_idx % src.len()]);
            *next_idx = (*next_idx + 1) % src.len();
        }
    }

    fn next_ports_for_tick(&mut self) -> Vec<u16> {
        let priority_count = REMOTE_SYM_PRIORITY_PORTS_PER_TICK.min(self.priority_ports.len());
        match self.kind {
            RemotePortScanKind::Centered => {
                let centered_count = self
                    .ports_per_tick
                    .saturating_sub(priority_count)
                    .min(self.centered_ports.len());
                let mut ports = Vec::with_capacity(priority_count + centered_count);
                Self::push_cyclic_ports(
                    &mut ports,
                    &self.priority_ports,
                    &mut self.next_priority_idx,
                    priority_count,
                );
                Self::push_cyclic_ports(
                    &mut ports,
                    &self.centered_ports,
                    &mut self.next_centered_idx,
                    centered_count,
                );
                ports
            }
            RemotePortScanKind::CenteredThenRandom => {
                let remaining_count = self.ports_per_tick.saturating_sub(priority_count);
                let (centered_count, random_count) = if self.centered_ports.is_empty() {
                    (0, remaining_count.min(self.random_ports.len()))
                } else if self.random_ports.is_empty() {
                    (remaining_count.min(self.centered_ports.len()), 0)
                } else {
                    let total_share = REMOTE_HARD_SYM_CENTERED_PORTS_PER_TICK
                        + REMOTE_HARD_SYM_RANDOM_PORTS_PER_TICK;
                    let centered_count =
                        (remaining_count * REMOTE_HARD_SYM_CENTERED_PORTS_PER_TICK / total_share)
                            .min(self.centered_ports.len());
                    let random_count = remaining_count
                        .saturating_sub(centered_count)
                        .min(self.random_ports.len());
                    (centered_count, random_count)
                };
                let mut ports = Vec::with_capacity(priority_count + centered_count + random_count);
                Self::push_cyclic_ports(
                    &mut ports,
                    &self.priority_ports,
                    &mut self.next_priority_idx,
                    priority_count,
                );
                Self::push_cyclic_ports(
                    &mut ports,
                    &self.centered_ports,
                    &mut self.next_centered_idx,
                    centered_count,
                );
                Self::push_cyclic_ports(
                    &mut ports,
                    &self.random_ports,
                    &mut self.next_random_idx,
                    random_count,
                );

                ports
            }
        }
    }

    async fn send_next(
        &mut self,
        udp_array: &Arc<UdpSocketArray>,
        packet: &[u8],
    ) -> Result<PortScanTickStats, anyhow::Error> {
        let sockets = udp_array.sockets();
        if sockets.is_empty() {
            return Ok(PortScanTickStats::default());
        }

        let socket_count = self.socket_limit.min(sockets.len());
        let ports = self.next_ports_for_tick();
        if ports.is_empty() {
            return Ok(PortScanTickStats::default());
        }

        let mut packet_count = 0usize;
        for port in ports.iter().copied() {
            let addr = SocketAddr::V4(SocketAddrV4::new(self.public_ip, port));
            for socket in sockets.iter().take(socket_count) {
                for _ in 0..3 {
                    socket.send_to(packet, addr).await?;
                    packet_count += 1;
                }
            }
        }

        Ok(PortScanTickStats {
            port_count: ports.len(),
            socket_count,
            packet_count,
            first_port: ports.first().copied(),
            last_port: ports.last().copied(),
            sample_ports: ports.iter().copied().take(8).collect(),
        })
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
            .find_listener_or_select_replacement(&listener_addr, true)
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
            .find_listener_or_select_replacement(&listener_addr, true)
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
    udp_array_runtime_port_prediction: RwLock<Option<RuntimePortPrediction>>,
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
            udp_array_runtime_port_prediction: RwLock::new(None),
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
                let plan = RemotePortScanPlan::new(remote_addr, peer_nat_info, &[]);
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
                &[],
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

    async fn cache_runtime_port_prediction(&self, prediction: &RuntimePortPrediction) {
        if prediction.mapped_ports.is_empty() {
            return;
        }
        if !prediction.is_peer_reflexive() {
            tracing::debug!(
                sample_source = ?prediction.sample_source,
                mapped_ports = ?prediction.mapped_ports,
                "skip caching low-confidence symmetric nat prediction"
            );
            return;
        }

        let mut wlocked = self.udp_array_runtime_port_prediction.write().await;
        wlocked.replace(prediction.clone());
    }

    async fn cached_runtime_port_prediction(&self) -> Option<RuntimePortPrediction> {
        self.udp_array_runtime_port_prediction.read().await.clone()
    }

    pub(crate) async fn clear_udp_array(&self) {
        let mut wlocked = self.udp_array.write().await;
        wlocked.take();
        let mut prediction = self.udp_array_predictable_port_window.write().await;
        prediction.take();
        let mut runtime_prediction = self.udp_array_runtime_port_prediction.write().await;
        runtime_prediction.take();
    }

    async fn warm_remote_punch_listener(
        &self,
        dst_peer_id: PeerId,
        remote_mapped_addr: crate::proto::common::SocketAddr,
        dest_addrs: &[SocketAddr],
    ) {
        if dest_addrs.is_empty() {
            return;
        }

        let req = WarmPunchListenerRequest {
            listener_mapped_addr: Some(remote_mapped_addr),
            dest_addrs: dest_addrs.iter().copied().map(Into::into).collect(),
            port_window: PEER_REFLEXIVE_PREWARM_PORT_WINDOW,
            packet_count: PEER_REFLEXIVE_PREWARM_PACKET_COUNT,
        };
        tracing::info!(
            ?dst_peer_id,
            ?req,
            "peer-reflexive sampling: request remote listener prewarm"
        );

        let ret = self
            .get_rpc_stub(dst_peer_id)
            .await
            .warm_punch_listener(
                BaseController {
                    timeout_ms: PEER_REFLEXIVE_PREWARM_RPC_TIMEOUT_MS,
                    trace_id: 0,
                    ..Default::default()
                },
                req,
            )
            .await;
        if let Err(err) = ret {
            tracing::warn!(
                ?dst_peer_id,
                ?err,
                "peer-reflexive sampling: remote listener prewarm failed"
            );
        }
    }

    async fn sample_runtime_port_prediction(
        &self,
        dst_peer_id: PeerId,
        my_nat_info: UdpNatType,
        remote_mapped_addr: crate::proto::common::SocketAddr,
        prediction_sockets: Option<&[Arc<UdpSocket>]>,
    ) -> Option<RuntimePortPrediction> {
        let prediction_nat_info = nat_info_for_port_prediction(my_nat_info)?;

        let global_ctx = self.peer_mgr.get_global_ctx();
        let stun_collector = global_ctx.get_stun_info_collector();
        let peer_stun_server: SocketAddr = remote_mapped_addr.into();
        let target_samples = if prediction_nat_info.get_inc_of_easy_sym().is_some() {
            1
        } else {
            HARD_SYM_PREDICT_MIN_SAMPLES
        };

        let mut peer_mapped_ports = Vec::new();
        let mut public_fallback_ports = Vec::new();
        let from_udp_array = prediction_sockets.is_some();
        let mut owned_temp_sockets = Vec::new();
        let sockets = if let Some(prediction_sockets) = prediction_sockets {
            prediction_sockets
                .iter()
                .take(PEER_REFLEXIVE_MAPPING_PROBES)
                .cloned()
                .collect::<Vec<_>>()
        } else {
            for _ in 0..PEER_REFLEXIVE_MAPPING_PROBES {
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
                owned_temp_sockets.push(socket);
            }
            owned_temp_sockets.clone()
        };

        if sockets.is_empty() {
            tracing::warn!("failed to prepare any udp sockets for sym prediction");
            return None;
        }

        let mut prewarm_candidate_addrs = Vec::new();
        for socket in sockets.iter().take(PEER_REFLEXIVE_PREWARM_CANDIDATE_PROBES) {
            match stun_collector
                .get_udp_port_mapping_with_socket(socket.clone())
                .await
            {
                Ok(addr) => {
                    tracing::info!(
                        ?addr,
                        local_addr = ?socket.local_addr().ok(),
                        sample_source = ?RuntimePortPredictionSource::PublicStunFallback,
                        "public STUN candidate sampled for peer-reflexive prewarm"
                    );
                    push_unique_socket_addr(&mut prewarm_candidate_addrs, addr);
                }
                ret => tracing::warn!(
                    ?ret,
                    local_addr = ?socket.local_addr().ok(),
                    "failed to map udp socket through public STUN for peer-reflexive prewarm"
                ),
            }
        }

        self.warm_remote_punch_listener(dst_peer_id, remote_mapped_addr, &prewarm_candidate_addrs)
            .await;
        if !prewarm_candidate_addrs.is_empty() {
            tokio::time::sleep(Duration::from_millis(PEER_REFLEXIVE_PREWARM_SETTLE_MS)).await;
        }

        for socket in sockets.iter() {
            match get_udp_port_mapping_with_socket_and_server(
                socket.clone(),
                peer_stun_server,
                Duration::from_millis(PEER_REFLEXIVE_MAPPING_TIMEOUT_MS),
            )
            .await
            {
                Ok(addr) => {
                    tracing::info!(
                        ?addr,
                        ?peer_stun_server,
                        local_addr = ?socket.local_addr().ok(),
                        sample_source = ?RuntimePortPredictionSource::PeerReflexive,
                        "peer-reflexive udp socket mapping sampled"
                    );
                    peer_mapped_ports.push(addr.port());
                    if peer_mapped_ports.len() >= target_samples {
                        break;
                    }
                }
                Err(peer_err) => tracing::warn!(
                    ?peer_err,
                    ?peer_stun_server,
                    local_addr = ?socket.local_addr().ok(),
                    timeout_ms = PEER_REFLEXIVE_MAPPING_TIMEOUT_MS,
                    "peer-reflexive udp socket mapping failed"
                ),
            }
        }

        if peer_mapped_ports.is_empty() {
            tracing::warn!(
                ?peer_stun_server,
                target_samples,
                candidate_addrs = ?prewarm_candidate_addrs,
                "peer-reflexive udp socket mapping produced no samples; public STUN fallback is low-confidence"
            );
            for addr in prewarm_candidate_addrs.iter().copied() {
                public_fallback_ports.push(addr.port());
                if public_fallback_ports.len() >= target_samples {
                    break;
                }
            }

            if public_fallback_ports.is_empty() {
                match stun_collector.get_udp_port_mapping(0).await {
                    Ok(addr) => {
                        tracing::info!(
                            ?addr,
                            sample_source = ?RuntimePortPredictionSource::PublicStunFallback,
                            "public STUN fallback standalone udp mapping sampled"
                        );
                        public_fallback_ports.push(addr.port());
                    }
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

        let (mapped_ports, sample_source) = if peer_mapped_ports.is_empty() {
            if public_fallback_ports.is_empty() {
                tracing::warn!("failed to sample any udp sockets for sym prediction");
                return None;
            }
            (
                public_fallback_ports,
                RuntimePortPredictionSource::PublicStunFallback,
            )
        } else {
            (
                peer_mapped_ports,
                RuntimePortPredictionSource::PeerReflexive,
            )
        };

        let prediction = if sample_source == RuntimePortPredictionSource::PeerReflexive {
            predictable_port_window_from_samples(prediction_nat_info, &mapped_ports)
        } else {
            None
        };
        let runtime_prediction = RuntimePortPrediction {
            predictable_port_window: prediction,
            mapped_ports,
            sample_source,
        };
        tracing::info!(
            mapped_ports = ?runtime_prediction.mapped_ports,
            observed_spread = runtime_prediction.observed_port_spread(),
            prediction = ?runtime_prediction.predictable_port_window,
            sample_source = ?runtime_prediction.sample_source,
            ?my_nat_info,
            ?prediction_nat_info,
            target_samples,
            from_udp_array,
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

    async fn try_coordinated_symmetric_punch(
        &self,
        dst_peer_id: PeerId,
        udp_array: &Arc<UdpSocketArray>,
        runtime_port_prediction: Option<&RuntimePortPrediction>,
        stun_info: &crate::proto::common::StunInfo,
        public_ips: &[Ipv4Addr],
        peer_nat_info: UdpNatType,
    ) -> Result<Option<Box<dyn Tunnel>>, anyhow::Error> {
        let Some(public_ip) = public_ips.first().copied() else {
            return Ok(None);
        };
        let target_window = coordinated_symmetric_target_window(runtime_port_prediction, stun_info);
        if target_window.is_none() {
            tracing::info!(
                ?stun_info,
                stun_info_window = ?stun_info_port_window(stun_info),
                sample_source = ?runtime_port_prediction.map(|prediction| prediction.sample_source),
                "coordinated symmetric punch will use random-only scan without peer-reflexive target window"
            );
        }

        let tid: u32 = rand::thread_rng().r#gen();
        let packet = new_hole_punch_packet(tid, HOLE_PUNCH_PACKET_BODY_LEN).into_bytes();
        udp_array.add_intreast_tid(tid);
        defer! { udp_array.remove_intreast_tid(tid); }

        let rpc_stub = self.get_rpc_stub(dst_peer_id).await;
        let req = SendPunchPacketBothEasySymRequest {
            udp_socket_count: COORDINATED_SYM_ARRAY_SIZE as u32,
            public_ip: Some(public_ip.into()),
            transaction_id: tid,
            dst_port_num: 0,
            wait_time_ms: COORDINATED_SYM_WAIT_MS as u32,
            dst_base_port_num: target_window
                .map(|window| window.base_port_num as u32)
                .unwrap_or(0),
            dst_max_port_num: target_window.map(|window| window.max_port_num).unwrap_or(0),
            dst_is_incremental: target_window
                .map(|window| window.is_incremental)
                .unwrap_or(false),
            dst_random_scan: true,
            dst_priority_port_nums: runtime_port_prediction
                .filter(|prediction| prediction.is_peer_reflexive())
                .map(|prediction| {
                    prediction
                        .mapped_ports
                        .iter()
                        .copied()
                        .map(u32::from)
                        .collect()
                })
                .unwrap_or_default(),
        };
        tracing::info!(
            ?req,
            ?target_window,
            "coordinated symmetric punch: request remote udp array scan"
        );
        let remote_ret = rpc_stub
            .send_punch_packet_both_easy_sym(
                BaseController {
                    timeout_ms: 12_000,
                    trace_id: 0,
                    ..Default::default()
                },
                req,
            )
            .await;
        let remote_ret = handle_rpc_result(remote_ret, dst_peer_id, &self.blacklist)?;
        if remote_ret.is_busy {
            tracing::debug!(?dst_peer_id, "coordinated symmetric punch: remote is busy");
            return Ok(None);
        }

        let mut remote_priority_port_nums = remote_ret.base_priority_port_nums.clone();
        let remote_mapped_addr = remote_ret.base_mapped_addr.ok_or(anyhow::anyhow!(
            "coordinated symmetric punch response missing remote mapped addr"
        ))?;
        let remote_addr: SocketAddr = remote_mapped_addr.clone().into();
        let mut remote_candidate_addrs = Vec::new();
        push_unique_socket_addr(&mut remote_candidate_addrs, remote_addr);
        for addr in remote_ret.mapped_addrs {
            let addr: SocketAddr = addr.into();
            if !addr.ip().is_ipv4() || addr.ip().is_unspecified() || addr.port() == 0 {
                continue;
            }
            push_unique_socket_addr(&mut remote_candidate_addrs, addr);
            push_unique_port_num(&mut remote_priority_port_nums, addr.port());
        }

        let mut remote_scan =
            RemotePortScanPlan::new(remote_addr, peer_nat_info, &remote_priority_port_nums);
        if let Some(plan) = remote_scan.as_ref() {
            tracing::info!(
                ?remote_addr,
                ?remote_candidate_addrs,
                ?remote_priority_port_nums,
                ?peer_nat_info,
                scan_kind = ?plan.kind(),
                ports_per_tick = plan.ports_per_tick,
                socket_limit = plan.socket_limit,
                port_count = plan.port_count(),
                "coordinated symmetric punch: local udp array scan enabled"
            );
        }

        for addr in remote_candidate_addrs.iter().copied() {
            udp_array.send_with_all(&packet, addr).await?;
        }
        let wait_task = AbortOnDropHandle::new(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(COORDINATED_SYM_WAIT_MS + 1000)).await;
        }));
        let tunnel = Self::check_hole_punch_result(
            self.peer_mgr.get_global_ctx(),
            udp_array,
            &packet,
            tid,
            remote_mapped_addr,
            &wait_task,
            remote_scan.as_mut(),
            &remote_candidate_addrs,
        )
        .await?;
        let _ = wait_task.await;

        if tunnel.is_some() {
            tracing::info!(?dst_peer_id, "coordinated symmetric punch produced tunnel");
        }
        Ok(tunnel)
    }

    async fn check_hole_punch_result<T>(
        global_ctx: ArcGlobalCtx,
        udp_array: &Arc<UdpSocketArray>,
        packet: &[u8],
        tid: u32,
        remote_mapped_addr: crate::proto::common::SocketAddr,
        punch_task: &AbortOnDropHandle<T>,
        mut remote_scan: Option<&mut RemotePortScanPlan>,
        remote_candidate_addrs: &[SocketAddr],
    ) -> Result<Option<Box<dyn Tunnel>>, anyhow::Error> {
        // no matter what the result is, we should check if we received any hole punching packet
        let mut ret_tunnel: Option<Box<dyn Tunnel>> = None;
        let mut finish_time: Option<Instant> = None;
        let mut scan_tick_idx = 0usize;
        while finish_time.is_none()
            || finish_time.as_ref().unwrap().elapsed().as_millis() < PUNCH_RESULT_GRACE_MS
        {
            let remote_addr: SocketAddr = remote_mapped_addr.clone().into();
            udp_array.send_with_all(packet, remote_addr).await?;
            for candidate_addr in remote_candidate_addrs
                .iter()
                .copied()
                .filter(|addr| *addr != remote_addr)
            {
                tracing::debug!(
                    ?candidate_addr,
                    ?tid,
                    "send hole punch packet to remote candidate endpoint"
                );
                udp_array.send_with_all(packet, candidate_addr).await?;
            }
            if let Some(remote_scan) = remote_scan.as_deref_mut() {
                let scan_stats = remote_scan.send_next(udp_array, packet).await?;
                scan_tick_idx += 1;
                if scan_tick_idx <= 3 || scan_tick_idx % 20 == 0 {
                    tracing::info!(
                        scan_tick_idx,
                        remote_ip = ?remote_scan.public_ip,
                        port_count = scan_stats.port_count,
                        socket_count = scan_stats.socket_count,
                        packet_count = scan_stats.packet_count,
                        first_port = ?scan_stats.first_port,
                        last_port = ?scan_stats.last_port,
                        sample_ports = ?scan_stats.sample_ports,
                        "symmetric punch: local remote scan tick sent"
                    );
                }
            }

            for learned_addr in udp_array
                .recent_punch_addrs()
                .into_iter()
                .filter(|addr| *addr != remote_addr)
                .take(LEARNED_ENDPOINTS_PER_TICK)
            {
                tracing::debug!(
                    ?learned_addr,
                    ?tid,
                    "send hole punch packet to learned endpoint"
                );
                udp_array.send_with_all(packet, learned_addr).await?;
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
        let sampled_runtime_port_prediction = if punch_predictably {
            if let Some(prediction_sockets) = prediction_sockets.as_deref() {
                tokio::time::timeout(
                    Duration::from_millis(EASY_SYM_MAPPING_TIMEOUT_MS),
                    self.sample_runtime_port_prediction(
                        dst_peer_id,
                        runtime_my_nat_info,
                        remote_mapped_addr,
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
        if let Some(prediction) = sampled_runtime_port_prediction.as_ref() {
            self.cache_runtime_port_prediction(prediction).await;
        }

        let runtime_port_prediction = if punch_predictably {
            let cached_prediction = if sampled_runtime_port_prediction.is_none() {
                self.cached_runtime_port_prediction().await
            } else {
                None
            };
            let prediction =
                select_runtime_port_prediction(sampled_runtime_port_prediction, cached_prediction);
            if prediction_sockets.is_none()
                && let Some(prediction) = prediction.as_ref()
            {
                tracing::info!(
                    mapped_ports = ?prediction.mapped_ports,
                    prediction = ?prediction.predictable_port_window,
                    sample_source = ?prediction.sample_source,
                    "reuse cached symmetric nat prediction for udp array"
                );
            }
            prediction
        } else {
            None
        };
        let predictable_port_window = if punch_predictably {
            let prediction = runtime_port_prediction
                .as_ref()
                .filter(|prediction| prediction.is_peer_reflexive())
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
                sample_source = ?runtime_port_prediction.sample_source,
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

        if should_try_coordinated_symmetric_punch(runtime_my_nat_info, peer_nat_info)
            && let Some(tunnel) = self
                .try_coordinated_symmetric_punch(
                    dst_peer_id,
                    &udp_array,
                    runtime_port_prediction.as_ref(),
                    &stun_info,
                    &public_ips,
                    peer_nat_info,
                )
                .await?
        {
            return Ok(Some(tunnel));
        }

        let mut remote_scan = if peer_nat_info.is_unknown() || peer_nat_info.is_sym() {
            let remote_addr: SocketAddr = remote_mapped_addr.into();
            let plan = RemotePortScanPlan::new(remote_addr, peer_nat_info, &[]);
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
            &[],
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
            &[],
        )
        .unwrap();

        assert_eq!(plan.kind(), super::RemotePortScanKind::CenteredThenRandom);
        assert_eq!(
            plan.ports_per_tick,
            super::REMOTE_HARD_SYM_SCAN_PORTS_PER_TICK
        );
        assert_eq!(plan.socket_limit, super::REMOTE_SYM_SCAN_SOCKET_LIMIT);
        assert_eq!(plan.port_count(), u16::MAX as usize);
        assert_eq!(
            plan.preview_ports(5),
            vec![45_678, 45_679, 45_677, 45_680, 45_676]
        );
    }

    #[test]
    fn hard_symmetric_remote_scan_interleaves_centered_and_random_ports() {
        let mut plan = super::RemotePortScanPlan::new(
            "198.51.100.10:45678".parse().unwrap(),
            super::UdpNatType::Unknown,
            &[],
        )
        .unwrap();

        let ports = plan.next_ports_for_tick();
        assert_eq!(ports.len(), super::REMOTE_HARD_SYM_SCAN_PORTS_PER_TICK);
        assert_eq!(&ports[..5], &[45_678, 45_679, 45_677, 45_680, 45_676]);
        assert!(
            ports[super::REMOTE_HARD_SYM_CENTERED_PORTS_PER_TICK..]
                .iter()
                .all(|port| !plan.centered_ports.contains(port))
        );
    }

    #[test]
    fn remote_scan_prioritizes_runtime_port_hints() {
        let mut plan = super::RemotePortScanPlan::new(
            "198.51.100.10:45678".parse().unwrap(),
            super::UdpNatType::Unknown,
            &[48_667],
        )
        .unwrap();

        assert_eq!(
            plan.preview_ports(5),
            vec![48_667, 48_668, 48_666, 48_669, 48_665]
        );
        let first_tick = plan.next_ports_for_tick();
        assert_eq!(&first_tick[..5], &[48_667, 48_668, 48_666, 48_669, 48_665]);
        assert!(first_tick.contains(&45_678));
    }

    #[test]
    fn learned_endpoint_limit_is_small() {
        assert_eq!(super::LEARNED_ENDPOINTS_PER_TICK, 8);
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
            sample_source: super::RuntimePortPredictionSource::PeerReflexive,
        };
        assert_eq!(stable.observed_port_spread(), 3);
        assert!(stable.should_try_stable_socket_punch());

        let unstable = super::RuntimePortPrediction {
            predictable_port_window: stable.predictable_port_window,
            mapped_ports: vec![10_000, 10_256],
            sample_source: super::RuntimePortPredictionSource::PeerReflexive,
        };
        assert_eq!(unstable.observed_port_spread(), 256);
        assert!(!unstable.should_try_stable_socket_punch());

        let no_window = super::RuntimePortPrediction {
            predictable_port_window: None,
            mapped_ports: vec![61_552, 61_553, 61_555],
            sample_source: super::RuntimePortPredictionSource::PeerReflexive,
        };
        assert!(!no_window.should_try_stable_socket_punch());

        let fallback = super::RuntimePortPrediction {
            predictable_port_window: stable.predictable_port_window,
            mapped_ports: vec![61_552, 61_553, 61_555],
            sample_source: super::RuntimePortPredictionSource::PublicStunFallback,
        };
        assert!(!fallback.should_try_stable_socket_punch());
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
    fn hard_sym_wraparound_samples_stay_predictable() {
        let prediction = super::predictable_port_window_from_samples(
            super::UdpNatType::HardSymmetric(NatType::Symmetric),
            &[62_050, 4_867, 4_868],
        )
        .unwrap();

        assert_eq!(prediction.base_port_num, 4_868);
        assert_eq!(prediction.max_port_num, super::HARD_SYM_PREDICT_WINDOW);
        assert!(prediction.is_incremental);
        assert_eq!(super::observed_port_spread(&[62_050, 4_867, 4_868]), 8_353);
    }

    #[test]
    fn hard_sym_rejects_non_monotonic_runtime_samples() {
        let prediction = super::predictable_port_window_from_samples(
            super::UdpNatType::HardSymmetric(NatType::Symmetric),
            &[22_590, 22_640, 22_620, 23_010],
        );

        assert!(prediction.is_none());
    }

    #[test]
    fn coordinated_symmetric_punch_is_used_for_unknown_or_symmetric_peers() {
        assert!(super::should_try_coordinated_symmetric_punch(
            super::UdpNatType::Unknown,
            super::UdpNatType::HardSymmetric(NatType::Symmetric),
        ));
        assert!(super::should_try_coordinated_symmetric_punch(
            super::UdpNatType::HardSymmetric(NatType::Symmetric),
            super::UdpNatType::Unknown,
        ));
        assert!(!super::should_try_coordinated_symmetric_punch(
            super::UdpNatType::HardSymmetric(NatType::Symmetric),
            super::UdpNatType::Cone(NatType::PortRestricted),
        ));
    }

    #[test]
    fn coordinated_symmetric_target_window_prefers_runtime_samples() {
        let runtime = super::RuntimePortPrediction {
            predictable_port_window: None,
            mapped_ports: vec![12_423, 12_450, 12_510],
            sample_source: super::RuntimePortPredictionSource::PeerReflexive,
        };
        let stun_info = crate::proto::common::StunInfo {
            min_port: 50_000,
            max_port: 50_100,
            ..Default::default()
        };

        let window =
            super::coordinated_symmetric_target_window(Some(&runtime), &stun_info).unwrap();
        let ports = super::easy_sym_target_ports(
            window.base_port_num as u32,
            window.max_port_num,
            window.is_incremental,
        );

        assert_eq!(window.max_port_num, super::COORDINATED_SYM_SCAN_WINDOW);
        assert!(ports.contains(&12_423));
        assert!(ports.contains(&12_510));
        assert!(!ports.contains(&50_000));
    }

    #[test]
    fn coordinated_symmetric_target_window_ignores_public_stun_fallback_samples() {
        let runtime = super::RuntimePortPrediction {
            predictable_port_window: Some(super::PredictablePortWindow {
                base_port_num: 12_423,
                max_port_num: super::HARD_SYM_PREDICT_WINDOW,
                is_incremental: true,
            }),
            mapped_ports: vec![12_423, 12_450, 12_510],
            sample_source: super::RuntimePortPredictionSource::PublicStunFallback,
        };
        let stun_info = crate::proto::common::StunInfo {
            min_port: 50_000,
            max_port: 50_100,
            ..Default::default()
        };

        assert_eq!(
            super::coordinated_symmetric_target_window(Some(&runtime), &stun_info),
            None
        );
    }

    #[test]
    fn runtime_port_prediction_prefers_peer_reflexive_samples_over_cache() {
        let cached = super::RuntimePortPrediction {
            predictable_port_window: Some(super::PredictablePortWindow {
                base_port_num: 36_447,
                max_port_num: super::HARD_SYM_PREDICT_WINDOW,
                is_incremental: true,
            }),
            mapped_ports: vec![36_447, 36_451, 36_459],
            sample_source: super::RuntimePortPredictionSource::PeerReflexive,
        };
        let peer_sampled = super::RuntimePortPrediction {
            predictable_port_window: Some(super::PredictablePortWindow {
                base_port_num: 53_100,
                max_port_num: super::HARD_SYM_PREDICT_WINDOW,
                is_incremental: true,
            }),
            mapped_ports: vec![53_100, 53_104, 53_109],
            sample_source: super::RuntimePortPredictionSource::PeerReflexive,
        };
        let fallback_sampled = super::RuntimePortPrediction {
            predictable_port_window: None,
            mapped_ports: vec![53_100],
            sample_source: super::RuntimePortPredictionSource::PublicStunFallback,
        };

        assert_eq!(
            super::select_runtime_port_prediction(None, Some(cached.clone())),
            Some(cached.clone())
        );
        assert_eq!(
            super::select_runtime_port_prediction(Some(peer_sampled.clone()), Some(cached.clone())),
            Some(peer_sampled)
        );
        assert_eq!(
            super::select_runtime_port_prediction(Some(fallback_sampled), Some(cached.clone())),
            Some(cached)
        );
    }

    #[tokio::test]
    async fn cached_runtime_port_prediction_is_cleared_with_udp_array() {
        let peer_mgr = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let client =
            super::PunchSymToConeHoleClient::new(peer_mgr, Arc::new(timedmap::TimedMap::new()));
        let prediction = super::RuntimePortPrediction {
            predictable_port_window: Some(super::PredictablePortWindow {
                base_port_num: 36_447,
                max_port_num: super::HARD_SYM_PREDICT_WINDOW,
                is_incremental: true,
            }),
            mapped_ports: vec![36_447, 36_451, 36_459],
            sample_source: super::RuntimePortPredictionSource::PeerReflexive,
        };

        client.cache_runtime_port_prediction(&prediction).await;
        assert_eq!(
            client.cached_runtime_port_prediction().await,
            Some(prediction)
        );

        client.clear_udp_array().await;
        assert_eq!(client.cached_runtime_port_prediction().await, None);
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
