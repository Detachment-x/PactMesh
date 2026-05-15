//! 派生函数：把 RPC 拿到的 PeerRoutePair / StunInfo 推导成对人友好的展示语言。
//! 全部为纯函数，无状态、无 IO，便于单元测试。

use crate::proto::{
    api::instance::PeerRoutePair,
    common::{NatType, StunInfo},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathType {
    Direct,
    Relay { hop_peer_id: u32 },
    Trying,
    Unknown,
}

impl std::fmt::Display for PathType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathType::Direct => write!(f, "direct"),
            PathType::Relay { hop_peer_id } => write!(f, "relay→{hop_peer_id:#x}"),
            PathType::Trying => write!(f, "trying"),
            PathType::Unknown => write!(f, "?"),
        }
    }
}

pub fn path_type(pair: &PeerRoutePair) -> PathType {
    let Some(route) = pair.route.as_ref() else { return PathType::Unknown };
    let Some(peer) = pair.peer.as_ref() else { return PathType::Unknown };

    let has_direct_conn = !peer.directly_connected_conns.is_empty()
        && peer.conns.iter().any(|c| !c.is_closed);
    if has_direct_conn {
        return PathType::Direct;
    }
    if route.next_hop_peer_id != 0 && route.next_hop_peer_id != route.peer_id {
        return PathType::Relay { hop_peer_id: route.next_hop_peer_id };
    }
    PathType::Trying
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayReason {
    PeerIsPublicServer,
    PeerSetAvoidRelay,
    DoubleSymmetricNat,
    StunProbeIncomplete,
    Unknown,
}

impl std::fmt::Display for RelayReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayReason::PeerIsPublicServer => write!(f, "peer is public server"),
            RelayReason::PeerSetAvoidRelay => write!(f, "peer set avoid_relay_data"),
            RelayReason::DoubleSymmetricNat => write!(f, "double symmetric NAT"),
            RelayReason::StunProbeIncomplete => write!(f, "stun probe incomplete"),
            RelayReason::Unknown => write!(f, "unknown — see Logs tab"),
        }
    }
}

fn is_symmetric(nat: NatType) -> bool {
    matches!(
        nat,
        NatType::Symmetric
            | NatType::SymUdpFirewall
            | NatType::SymmetricEasyInc
            | NatType::SymmetricEasyDec
    )
}

fn is_unknown_or_nopat(nat: NatType) -> bool {
    matches!(nat, NatType::Unknown | NatType::NoPat)
}

pub fn relay_reason(pair: &PeerRoutePair, my_stun: &StunInfo) -> RelayReason {
    let Some(route) = pair.route.as_ref() else { return RelayReason::Unknown };

    if let Some(ff) = route.feature_flag.as_ref() {
        if ff.is_public_server {
            return RelayReason::PeerIsPublicServer;
        }
        if ff.avoid_relay_data {
            return RelayReason::PeerSetAvoidRelay;
        }
    }

    let my_udp = NatType::try_from(my_stun.udp_nat_type).unwrap_or(NatType::Unknown);
    let my_tcp = NatType::try_from(my_stun.tcp_nat_type).unwrap_or(NatType::Unknown);

    if let Some(peer_stun) = route.stun_info.as_ref() {
        let peer_udp =
            NatType::try_from(peer_stun.udp_nat_type).unwrap_or(NatType::Unknown);
        if is_symmetric(my_udp) && is_symmetric(peer_udp) {
            return RelayReason::DoubleSymmetricNat;
        }
    }

    if my_tcp == NatType::Unknown && is_unknown_or_nopat(my_udp) {
        return RelayReason::StunProbeIncomplete;
    }

    RelayReason::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::api::instance::{PeerConnInfo, PeerInfo, PeerRoutePair, Route};
    use crate::proto::common::{NatType, PeerFeatureFlag, StunInfo, Uuid};

    fn pair(route: Route, peer: PeerInfo) -> PeerRoutePair {
        PeerRoutePair { route: Some(route), peer: Some(peer) }
    }

    fn open_conn() -> PeerConnInfo {
        PeerConnInfo { is_closed: false, ..Default::default() }
    }

    fn closed_conn() -> PeerConnInfo {
        PeerConnInfo { is_closed: true, ..Default::default() }
    }

    fn stun(udp: NatType, tcp: NatType) -> StunInfo {
        StunInfo {
            udp_nat_type: udp as i32,
            tcp_nat_type: tcp as i32,
            ..Default::default()
        }
    }

    // -------- path_type --------

    #[test]
    fn path_type_unknown_when_route_missing() {
        let p = PeerRoutePair { route: None, peer: Some(PeerInfo::default()) };
        assert_eq!(path_type(&p), PathType::Unknown);
    }

    #[test]
    fn path_type_direct_when_active_conn_with_direct_uuid() {
        let peer = PeerInfo {
            peer_id: 2,
            conns: vec![open_conn()],
            directly_connected_conns: vec![Uuid::default()],
            ..Default::default()
        };
        let route = Route { peer_id: 2, ..Default::default() };
        assert_eq!(path_type(&pair(route, peer)), PathType::Direct);
    }

    #[test]
    fn path_type_not_direct_when_only_closed_conns() {
        let peer = PeerInfo {
            peer_id: 2,
            conns: vec![closed_conn()],
            directly_connected_conns: vec![Uuid::default()],
            ..Default::default()
        };
        let route = Route { peer_id: 2, ..Default::default() };
        assert_ne!(path_type(&pair(route, peer)), PathType::Direct);
    }

    #[test]
    fn path_type_relay_when_next_hop_differs() {
        let route = Route { peer_id: 5, next_hop_peer_id: 3, ..Default::default() };
        assert_eq!(
            path_type(&pair(route, PeerInfo::default())),
            PathType::Relay { hop_peer_id: 3 }
        );
    }

    #[test]
    fn path_type_trying_when_no_direct_and_no_next_hop() {
        let route = Route { peer_id: 5, next_hop_peer_id: 0, ..Default::default() };
        assert_eq!(
            path_type(&pair(route, PeerInfo::default())),
            PathType::Trying
        );
    }

    // -------- relay_reason --------

    #[test]
    fn relay_reason_peer_is_public_server_takes_precedence() {
        let route = Route {
            feature_flag: Some(PeerFeatureFlag {
                is_public_server: true,
                avoid_relay_data: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            relay_reason(&pair(route, PeerInfo::default()), &StunInfo::default()),
            RelayReason::PeerIsPublicServer,
        );
    }

    #[test]
    fn relay_reason_peer_set_avoid_relay_data() {
        let route = Route {
            feature_flag: Some(PeerFeatureFlag {
                avoid_relay_data: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            relay_reason(&pair(route, PeerInfo::default()), &StunInfo::default()),
            RelayReason::PeerSetAvoidRelay,
        );
    }

    #[test]
    fn relay_reason_double_symmetric_nat() {
        let route = Route {
            stun_info: Some(stun(NatType::SymmetricEasyInc, NatType::Unknown)),
            ..Default::default()
        };
        let my = stun(NatType::Symmetric, NatType::OpenInternet);
        assert_eq!(
            relay_reason(&pair(route, PeerInfo::default()), &my),
            RelayReason::DoubleSymmetricNat,
        );
    }

    #[test]
    fn relay_reason_stun_probe_incomplete() {
        let my = StunInfo::default(); // 全 Unknown
        assert_eq!(
            relay_reason(&pair(Route::default(), PeerInfo::default()), &my),
            RelayReason::StunProbeIncomplete,
        );
    }

    #[test]
    fn relay_reason_fallback_unknown_when_full_cone() {
        let route = Route {
            stun_info: Some(stun(NatType::FullCone, NatType::FullCone)),
            ..Default::default()
        };
        let my = stun(NatType::FullCone, NatType::FullCone);
        assert_eq!(
            relay_reason(&pair(route, PeerInfo::default()), &my),
            RelayReason::Unknown,
        );
    }
}
