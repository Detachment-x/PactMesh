use std::sync::Arc;

use easytier::{
    connector::manual::recovery_candidate_urls_for_diagnostics,
    trust::{
        NetworkLocalId, NetworkStatePayload, PeerHint, TrustDomainPool, TrustDomainRoot,
        UnsignedNetworkState, apply_lan_response, build_lan_query, response_for_query,
    },
};
use tokio::sync::RwLock;

const NETWORK: &str = "office-net";
const NOW: u64 = 1_700_000_000;

fn network_id() -> NetworkLocalId {
    NetworkLocalId::try_from_str(NETWORK).unwrap()
}

fn a2_hint() -> PeerHint {
    PeerHint {
        url: "tcp://203.0.113.20:11010".to_owned(),
        label: Some("public-a2".to_owned()),
        capabilities: vec!["public-reachable".to_owned()],
        updated_at: NOW,
        expires_at: Some(NOW + 3600),
    }
}

fn state(
    root: &TrustDomainRoot,
    version: u64,
    hints: Vec<PeerHint>,
) -> easytier::trust::SignedNetworkState {
    UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: network_id(),
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

#[tokio::test]
async fn test_a_down_a2_hint_reaches_offline_b_via_updated_lan_c() {
    let root = TrustDomainRoot::generate();
    let c_pool = pool_with(&root, state(&root, 2, vec![a2_hint()]));
    let b_pool = Arc::new(RwLock::new(pool_with(&root, state(&root, 1, Vec::new()))));
    let query_from_b = build_lan_query(root.id(), network_id(), 1, Some("node-b".to_owned()));

    let response_from_c = response_for_query(&c_pool, &query_from_b).unwrap();
    apply_lan_response(
        &b_pool,
        &root.id(),
        &network_id(),
        response_from_c,
        None,
        "192.168.1.30:40123".parse().ok(),
    )
    .await
    .unwrap();

    let guard = b_pool.read().await;
    let b_state = guard.network_state(&root.id(), &network_id()).unwrap();
    let candidates = recovery_candidate_urls_for_diagnostics(
        Some(b_state),
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

#[tokio::test]
async fn test_lan_recovery_rejects_wrong_domain_and_keeps_b_on_old_state() {
    let root = TrustDomainRoot::generate();
    let other = TrustDomainRoot::generate();
    let b_pool = Arc::new(RwLock::new(pool_with(&root, state(&root, 1, Vec::new()))));
    let malicious_response = easytier::trust::lan_discovery::LanNetworkStateResponse {
        protocol_version: easytier::trust::lan_discovery::LAN_DISCOVERY_PROTOCOL_VERSION,
        network_state: state(&other, 2, vec![a2_hint()]),
    };

    assert!(
        apply_lan_response(
            &b_pool,
            &root.id(),
            &network_id(),
            malicious_response,
            None,
            None,
        )
        .await
        .is_err()
    );

    let guard = b_pool.read().await;
    assert_eq!(
        guard
            .network_state(&root.id(), &network_id())
            .unwrap()
            .details
            .version,
        1
    );
}

#[test]
fn test_lan_discovery_miss_still_leaves_signed_hint_fallback_usable() {
    let root = TrustDomainRoot::generate();
    let b_state = state(&root, 2, vec![a2_hint()]);
    let responder_without_newer_state = pool_with(&root, state(&root, 2, Vec::new()));
    let query_from_b = build_lan_query(root.id(), network_id(), 2, Some("node-b".to_owned()));

    assert!(response_for_query(&responder_without_newer_state, &query_from_b).is_none());
    let candidates = recovery_candidate_urls_for_diagnostics(
        Some(&b_state),
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
