use std::{net::SocketAddr, path::Path, time::Duration};

use thiserror::Error;
use tokio::{net::UdpSocket, sync::RwLock};

use super::{
    NetworkLocalId, NetworkStateReceiveError, NetworkStateReceiveReport, SignedNetworkState,
    TrustDomainId, TrustDomainPool, from_cbor, receive_network_state, to_canonical_cbor,
};

pub const LAN_DISCOVERY_PROTOCOL_VERSION: u16 = 1;
pub const LAN_DISCOVERY_MAX_PACKET_BYTES: usize = 256 * 1024;
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
    pub network_state: SignedNetworkState,
}

#[derive(Error, Debug)]
pub enum LanDiscoveryError {
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("packet too large: {0} bytes")]
    PacketTooLarge(usize),
    #[error("cbor: {0}")]
    Cbor(String),
    #[error("network_state receive failed: {0}")]
    Receive(#[from] NetworkStateReceiveError),
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
    Some(LanNetworkStateResponse {
        protocol_version: LAN_DISCOVERY_PROTOCOL_VERSION,
        network_state: state.clone(),
    })
}

pub async fn apply_lan_response(
    pool: &RwLock<TrustDomainPool>,
    expected_trust_domain_id: &TrustDomainId,
    expected_network_local_id: &NetworkLocalId,
    response: LanNetworkStateResponse,
    persist_domain_dir: Option<&Path>,
    remote_addr: Option<SocketAddr>,
) -> Result<NetworkStateReceiveReport, LanDiscoveryError> {
    ensure_version(response.protocol_version)?;
    let source = remote_addr
        .map(|addr| format!("{LAN_DISCOVERY_SOURCE}:{addr}"))
        .unwrap_or_else(|| LAN_DISCOVERY_SOURCE.to_owned());
    receive_network_state(
        pool,
        expected_trust_domain_id,
        expected_network_local_id,
        response.network_state,
        persist_domain_dir,
        source,
    )
    .await
    .map_err(Into::into)
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
