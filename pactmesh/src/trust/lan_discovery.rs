use std::{net::SocketAddr, time::Duration};

use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::net::UdpSocket;

use super::{NetworkLocalId, TrustDomainId, TrustDomainPool, from_cbor, to_canonical_cbor};

pub const LAN_DISCOVERY_PROTOCOL_VERSION: u16 = 2;
pub const LAN_DISCOVERY_MAX_PACKET_BYTES: usize = 16 * 1024;
pub const LAN_DISCOVERY_SOURCE: &str = "lan-network-state-discovery";

#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq)]
pub struct LanNetworkStateQuery {
    #[n(0)]
    pub protocol_version: u16,
    #[n(1)]
    pub trust_domain_id: TrustDomainId,
    #[n(2)]
    pub network_local_id: NetworkLocalId,
    #[n(3)]
    pub current_network_state_version: u64,
    #[n(4)]
    pub device_label: Option<String>,
}

#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq)]
pub struct LanNetworkStateResponse {
    #[n(0)]
    pub protocol_version: u16,
    #[n(1)]
    pub trust_domain_id: TrustDomainId,
    #[n(2)]
    pub network_local_id: NetworkLocalId,
    #[n(3)]
    pub network_state_version: u64,
    #[n(4)]
    pub network_state_digest: Vec<u8>,
    #[n(5)]
    pub responder_peer_id: Option<u32>,
    #[n(6)]
    pub peer_hints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanNetworkStateDiscoveryReport {
    pub source: String,
    pub trust_domain_id: TrustDomainId,
    pub network_local_id: NetworkLocalId,
    pub remote_version: u64,
    pub remote_digest: Vec<u8>,
    pub responder_peer_id: Option<u32>,
    pub peer_hints: Vec<String>,
    pub should_sync: bool,
}

#[derive(Error, Debug)]
pub enum LanDiscoveryError {
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("packet too large: {0} bytes")]
    PacketTooLarge(usize),
    #[error("cbor: {0}")]
    Cbor(String),
    #[error("trust_domain_id mismatch")]
    TrustDomainMismatch,
    #[error("network_local_id mismatch")]
    NetworkLocalIdMismatch,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub fn build_lan_query(
    trust_domain_id: TrustDomainId,
    network_local_id: NetworkLocalId,
    current_network_state_version: u64,
    device_label: Option<String>,
) -> LanNetworkStateQuery {
    LanNetworkStateQuery {
        protocol_version: LAN_DISCOVERY_PROTOCOL_VERSION,
        trust_domain_id,
        network_local_id,
        current_network_state_version,
        device_label,
    }
}

pub fn encode_lan_query(query: &LanNetworkStateQuery) -> Vec<u8> {
    to_canonical_cbor(query)
}

pub fn decode_lan_query(bytes: &[u8]) -> Result<LanNetworkStateQuery, LanDiscoveryError> {
    ensure_packet_size(bytes)?;
    let query: LanNetworkStateQuery = from_cbor(bytes)
        .map_err(|err| LanDiscoveryError::Cbor(format!("decode query failed: {err}")))?;
    ensure_version(query.protocol_version)?;
    Ok(query)
}

pub fn encode_lan_response(response: &LanNetworkStateResponse) -> Vec<u8> {
    to_canonical_cbor(response)
}

pub fn decode_lan_response(bytes: &[u8]) -> Result<LanNetworkStateResponse, LanDiscoveryError> {
    ensure_packet_size(bytes)?;
    let response: LanNetworkStateResponse = from_cbor(bytes)
        .map_err(|err| LanDiscoveryError::Cbor(format!("decode response failed: {err}")))?;
    ensure_version(response.protocol_version)?;
    Ok(response)
}

pub fn response_for_query(
    pool: &TrustDomainPool,
    query: &LanNetworkStateQuery,
) -> Option<LanNetworkStateResponse> {
    if query.protocol_version != LAN_DISCOVERY_PROTOCOL_VERSION {
        return None;
    }
    let state = pool.network_state(&query.trust_domain_id, &query.network_local_id)?;
    if state.details.version <= query.current_network_state_version {
        return None;
    }
    let state_cbor = to_canonical_cbor(state);
    Some(LanNetworkStateResponse {
        protocol_version: LAN_DISCOVERY_PROTOCOL_VERSION,
        trust_domain_id: query.trust_domain_id,
        network_local_id: query.network_local_id.clone(),
        network_state_version: state.details.version,
        network_state_digest: Sha256::digest(&state_cbor).to_vec(),
        responder_peer_id: None,
        peer_hints: state
            .details
            .payload
            .peer_hints
            .iter()
            .filter(|hint| hint.capabilities.iter().any(|cap| cap == "config-sync"))
            .map(|hint| hint.url.clone())
            .take(4)
            .collect(),
    })
}

pub fn discovery_report_for_response(
    expected_trust_domain_id: &TrustDomainId,
    expected_network_local_id: &NetworkLocalId,
    current_network_state_version: u64,
    response: LanNetworkStateResponse,
    remote_addr: Option<SocketAddr>,
) -> Result<LanNetworkStateDiscoveryReport, LanDiscoveryError> {
    ensure_version(response.protocol_version)?;
    if &response.trust_domain_id != expected_trust_domain_id {
        return Err(LanDiscoveryError::TrustDomainMismatch);
    }
    if &response.network_local_id != expected_network_local_id {
        return Err(LanDiscoveryError::NetworkLocalIdMismatch);
    }

    Ok(LanNetworkStateDiscoveryReport {
        source: remote_addr
            .map(|addr| format!("{LAN_DISCOVERY_SOURCE}:{addr}"))
            .unwrap_or_else(|| LAN_DISCOVERY_SOURCE.to_owned()),
        trust_domain_id: response.trust_domain_id,
        network_local_id: response.network_local_id,
        remote_version: response.network_state_version,
        remote_digest: response.network_state_digest,
        responder_peer_id: response.responder_peer_id,
        peer_hints: response.peer_hints,
        should_sync: response.network_state_version > current_network_state_version,
    })
}

pub async fn udp_query_once(
    bind_addr: SocketAddr,
    target_addr: SocketAddr,
    query: &LanNetworkStateQuery,
    timeout: Duration,
) -> Result<Option<(LanNetworkStateResponse, SocketAddr)>, LanDiscoveryError> {
    let socket = UdpSocket::bind(bind_addr).await?;
    if matches!(target_addr.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast()) {
        socket.set_broadcast(true)?;
    }
    socket
        .send_to(&encode_lan_query(query), target_addr)
        .await?;

    let mut buf = vec![0u8; LAN_DISCOVERY_MAX_PACKET_BYTES];
    let recv = tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await;
    let Ok(Ok((len, remote_addr))) = recv else {
        return Ok(None);
    };
    let response = decode_lan_response(&buf[..len])?;
    Ok(Some((response, remote_addr)))
}

fn ensure_version(version: u16) -> Result<(), LanDiscoveryError> {
    if version == LAN_DISCOVERY_PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(LanDiscoveryError::UnsupportedVersion(version))
    }
}

fn ensure_packet_size(bytes: &[u8]) -> Result<(), LanDiscoveryError> {
    if bytes.len() <= LAN_DISCOVERY_MAX_PACKET_BYTES {
        Ok(())
    } else {
        Err(LanDiscoveryError::PacketTooLarge(bytes.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::{NetworkStatePayload, TrustDomainRoot, UnsignedNetworkState};

    fn sample_state(
        version: u64,
    ) -> (
        TrustDomainRoot,
        NetworkLocalId,
        crate::trust::SignedNetworkState,
    ) {
        let root = TrustDomainRoot::generate();
        let network_local_id = NetworkLocalId::try_from_str("office-net").unwrap();
        let state = UnsignedNetworkState {
            trust_domain_id: root.id(),
            network_local_id: network_local_id.clone(),
            version,
            payload: NetworkStatePayload {
                member_cert_index: Vec::new(),
                revoked_certs: Vec::new(),
                disabled_certs: Vec::new(),
                acl: b"private-acl".to_vec(),
                routes: b"private-routes".to_vec(),
                peer_hints: Vec::new(),
                ip_assignments: Vec::new(),
            },
        }
        .sign(&root);
        (root, network_local_id, state)
    }

    #[test]
    fn lan_response_contains_digest_not_network_state_payload() {
        let (root, network_local_id, state) = sample_state(2);
        let mut pool = TrustDomainPool::new();
        pool.add_root(root.public_key().into());
        pool.apply_network_state(state.clone()).unwrap();
        let query = build_lan_query(root.id(), network_local_id.clone(), 1, None);

        let response = response_for_query(&pool, &query).unwrap();
        let encoded = encode_lan_response(&response);

        assert_eq!(response.network_state_version, 2);
        assert_eq!(response.trust_domain_id, root.id());
        assert_eq!(response.network_local_id, network_local_id);
        assert_eq!(
            response.network_state_digest,
            Sha256::digest(to_canonical_cbor(&state)).to_vec()
        );
        assert!(
            !encoded
                .windows(b"private-acl".len())
                .any(|w| w == b"private-acl")
        );
        assert!(
            !encoded
                .windows(b"private-routes".len())
                .any(|w| w == b"private-routes")
        );
    }

    #[test]
    fn lan_response_only_requests_sync_for_newer_version() {
        let (root, network_local_id, state) = sample_state(3);
        let response = LanNetworkStateResponse {
            protocol_version: LAN_DISCOVERY_PROTOCOL_VERSION,
            trust_domain_id: root.id(),
            network_local_id: network_local_id.clone(),
            network_state_version: state.details.version,
            network_state_digest: Sha256::digest(to_canonical_cbor(&state)).to_vec(),
            responder_peer_id: Some(42),
            peer_hints: vec!["tcp://127.0.0.1:11010".to_string()],
        };

        let newer =
            discovery_report_for_response(&root.id(), &network_local_id, 2, response.clone(), None)
                .unwrap();
        assert!(newer.should_sync);

        let current =
            discovery_report_for_response(&root.id(), &network_local_id, 3, response, None)
                .unwrap();
        assert!(!current.should_sync);
    }
}
