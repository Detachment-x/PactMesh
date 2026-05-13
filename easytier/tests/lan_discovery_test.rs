use std::sync::Arc;

use easytier::{
    connector::manual::recovery_candidate_urls_for_diagnostics,
    trust::{
        LanDiscoveryError, NetworkLocalId, NetworkStatePayload, PeerHint, TrustDomainPool,
        TrustDomainRoot, UnsignedNetworkState, apply_lan_response, build_lan_query,
        response_for_query,
    },
};
use easytier::trust::lan_discovery::{
    LAN_DISCOVERY_MAX_PACKET_BYTES, decode_lan_query, decode_lan_response, encode_lan_query,
};
use tokio::sync::RwLock;

const NETWORK: &str = "office-net";
const NOW: u64 = 1_700_000_000;

fn network_id(value: &str) -> NetworkLocalId {
    NetworkLocalId::try_from_str(value).unwrap()
}

fn hint(url: &str) -> PeerHint {
    PeerHint {
        url: url.to_owned(),
        label: Some("public-a2".to_owned()),
        capabilities: vec!["public-reachable".to_owned()],
        updated_at: NOW,
        expires_at: Some(NOW + 3600),
    }
}

fn state(
    root: &TrustDomainRoot,
    network: &str,
    version: u64,
    hints: Vec<PeerHint>,
) -> easytier::trust::SignedNetworkState {
    UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: network_id(network),
        version,
        payload: NetworkStatePayload {
            member_cert_index: Vec::new(),
            revoked_certs: Vec::new(),
            disabled_certs: Vec::new(),
            acl: Vec::new(),
            routes: Vec::new(),
            peer_hints: hints,
        },
    }
    .sign(root)
}

fn pool_with(
    root: &TrustDomainRoot,
    state: easytier::trust::SignedNetworkState,
) -> TrustDomainPool {
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    pool.apply_network_state(state).unwrap();
    pool
}

#[test]
fn test_lan_query_cbor_round_trip() {
    let root = TrustDomainRoot::generate();
    let query = build_lan_query(root.id(), network_id(NETWORK), 7, Some("nas-b".to_owned()));

    let decoded = decode_lan_query(&encode_lan_query(&query)).unwrap();

    assert_eq!(decoded, query);
}

#[tokio::test]
async fn test_lan_discovery_happy_path_applies_newer_state_and_exposes_hint() {
    let root = TrustDomainRoot::generate();
    let updated_state = state(&root, NETWORK, 2, vec![hint("tcp://203.0.113.20:11010")]);
    let responder_pool = pool_with(&root, updated_state.clone());
    let requester_pool = Arc::new(RwLock::new(pool_with(
        &root,
        state(&root, NETWORK, 1, Vec::new()),
    )));
    let query = build_lan_query(root.id(), network_id(NETWORK), 1, Some("nas-b".to_owned()));

    let response = response_for_query(&responder_pool, &query).unwrap();
    let report = apply_lan_response(
        &requester_pool,
        &root.id(),
        &network_id(NETWORK),
        decode_lan_response(&easytier::trust::lan_discovery::encode_lan_response(
            &response,
        ))
        .unwrap(),
        None,
        "127.0.0.1:40000".parse().ok(),
    )
    .await
    .unwrap();

    assert_eq!(report.old_version, Some(1));
    assert_eq!(report.new_version, 2);
    assert!(report.source.contains("lan-network-state-discovery"));
    let guard = requester_pool.read().await;
    let stored = guard
        .network_state(&root.id(), &network_id(NETWORK))
        .unwrap();
    assert_eq!(stored, &updated_state);
    let candidates = recovery_candidate_urls_for_diagnostics(
        Some(stored),
        None,
        &root.id().to_string(),
        NETWORK,
        NOW,
    );
    assert_eq!(
        candidates
            .signed_peer_hints
            .into_iter()
            .map(|url| url.to_string())
            .collect::<Vec<_>>(),
        vec!["tcp://203.0.113.20:11010"]
    );
}

#[test]
fn test_lan_responder_ignores_old_or_equal_state() {
    let root = TrustDomainRoot::generate();
    let responder_pool = pool_with(&root, state(&root, NETWORK, 2, Vec::new()));

    let query = build_lan_query(root.id(), network_id(NETWORK), 2, None);

    assert!(response_for_query(&responder_pool, &query).is_none());
}

#[tokio::test]
async fn test_lan_discovery_rejects_wrong_scope_and_tamper() {
    let root = TrustDomainRoot::generate();
    let other = TrustDomainRoot::generate();
    let requester_pool = Arc::new(RwLock::new(pool_with(
        &root,
        state(&root, NETWORK, 1, Vec::new()),
    )));

    let wrong_domain_response = easytier::trust::lan_discovery::LanNetworkStateResponse {
        protocol_version: easytier::trust::lan_discovery::LAN_DISCOVERY_PROTOCOL_VERSION,
        network_state: state(&other, NETWORK, 2, Vec::new()),
    };
    let err = apply_lan_response(
        &requester_pool,
        &root.id(),
        &network_id(NETWORK),
        wrong_domain_response,
        None,
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        LanDiscoveryError::Receive(easytier::trust::NetworkStateReceiveError::TrustDomainMismatch)
    ));

    let wrong_network_response = easytier::trust::lan_discovery::LanNetworkStateResponse {
        protocol_version: easytier::trust::lan_discovery::LAN_DISCOVERY_PROTOCOL_VERSION,
        network_state: state(&root, "lab-net", 2, Vec::new()),
    };
    let err = apply_lan_response(
        &requester_pool,
        &root.id(),
        &network_id(NETWORK),
        wrong_network_response,
        None,
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        LanDiscoveryError::Receive(
            easytier::trust::NetworkStateReceiveError::NetworkLocalIdMismatch
        )
    ));

    let mut tampered = state(&root, NETWORK, 2, Vec::new());
    tampered.details.payload.acl.push(0xAA);
    let tampered_response = easytier::trust::lan_discovery::LanNetworkStateResponse {
        protocol_version: easytier::trust::lan_discovery::LAN_DISCOVERY_PROTOCOL_VERSION,
        network_state: tampered,
    };
    let err = apply_lan_response(
        &requester_pool,
        &root.id(),
        &network_id(NETWORK),
        tampered_response,
        None,
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        LanDiscoveryError::Receive(easytier::trust::NetworkStateReceiveError::PoolApply(
            easytier::trust::pool::PoolApplyError::BadSignature
        ))
    ));
}

#[test]
fn test_lan_discovery_rejects_oversized_packet() {
    let bytes = vec![0u8; LAN_DISCOVERY_MAX_PACKET_BYTES + 1];

    let err = decode_lan_query(&bytes).unwrap_err();

    assert!(matches!(err, LanDiscoveryError::PacketTooLarge(_)));
}

#[test]
fn test_discovery_failure_does_not_remove_other_recovery_sources() {
    let root = TrustDomainRoot::generate();
    let signed = state(&root, NETWORK, 1, vec![hint("tcp://203.0.113.30:11010")]);
    let query = build_lan_query(root.id(), network_id(NETWORK), 1, None);
    let empty_responder = pool_with(&root, state(&root, NETWORK, 1, Vec::new()));

    assert!(response_for_query(&empty_responder, &query).is_none());
    let candidates = recovery_candidate_urls_for_diagnostics(
        Some(&signed),
        None,
        &root.id().to_string(),
        NETWORK,
        NOW,
    );
    assert_eq!(
        candidates
            .signed_peer_hints
            .into_iter()
            .map(|url| url.to_string())
            .collect::<Vec<_>>(),
        vec!["tcp://203.0.113.30:11010"]
    );
}
