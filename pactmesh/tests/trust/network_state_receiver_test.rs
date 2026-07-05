use std::sync::Arc;

use pactmesh::trust::{
    NetworkLocalId, NetworkStatePayload, NetworkStateReceiveError, PeerHint, TrustDomainPool,
    TrustDomainRoot, UnsignedNetworkState, receive_network_state,
};
use tokio::sync::RwLock;

fn network_id(value: &str) -> NetworkLocalId {
    NetworkLocalId::try_from_str(value).unwrap()
}

fn state(
    root: &TrustDomainRoot,
    network: &str,
    version: u64,
) -> pactmesh::trust::SignedNetworkState {
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
            peer_hints: vec![PeerHint {
                url: "tcp://203.0.113.20:11010".to_owned(),
                label: Some("public-a2".to_owned()),
                capabilities: vec!["public-reachable".to_owned()],
                updated_at: 100,
                expires_at: Some(2_000_000_000),
            }],
            ip_assignments: Vec::new(),
            capability_grants: Vec::new(),
            hostname_bindings: Vec::new(),
        },
    }
    .sign(root)
}

fn pool(root: &TrustDomainRoot) -> Arc<RwLock<TrustDomainPool>> {
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    Arc::new(RwLock::new(pool))
}

#[tokio::test]
async fn test_receive_network_state_accepts_and_persists_newer_state() {
    let root = TrustDomainRoot::generate();
    let pool = pool(&root);
    receive_network_state(
        &pool,
        &root.id(),
        &network_id("office-net"),
        state(&root, "office-net", 1),
        None,
        "test-initial",
    )
    .await
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let updated = state(&root, "office-net", 2);

    let report = receive_network_state(
        &pool,
        &root.id(),
        &network_id("office-net"),
        updated.clone(),
        Some(dir.path()),
        "test-source",
    )
    .await
    .unwrap();

    assert_eq!(report.old_version, Some(1));
    assert_eq!(report.new_version, 2);
    let path = report.persisted_path.unwrap();
    let persisted =
        pactmesh::trust::SignedNetworkState::from_pem(&std::fs::read_to_string(path).unwrap())
            .unwrap();
    assert_eq!(persisted, updated);
}

#[tokio::test]
async fn test_receive_network_state_rejects_stale_without_overwriting_disk() {
    let root = TrustDomainRoot::generate();
    let pool = pool(&root);
    let dir = tempfile::tempdir().unwrap();
    let current = state(&root, "office-net", 2);
    receive_network_state(
        &pool,
        &root.id(),
        &network_id("office-net"),
        current.clone(),
        Some(dir.path()),
        "test-current",
    )
    .await
    .unwrap();

    let err = receive_network_state(
        &pool,
        &root.id(),
        &network_id("office-net"),
        state(&root, "office-net", 1),
        Some(dir.path()),
        "test-stale",
    )
    .await
    .unwrap_err();

    assert!(matches!(
        err,
        NetworkStateReceiveError::PoolApply(pactmesh::trust::pool::PoolApplyError::StaleVersion {
            have: 2,
            got: 1
        })
    ));
    let persisted = pactmesh::trust::SignedNetworkState::from_pem(
        &std::fs::read_to_string(
            dir.path()
                .join("networks/office-net/network_state.cbor.pem"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(persisted, current);
}

#[tokio::test]
async fn test_receive_network_state_rejects_wrong_scope_and_tamper() {
    let root = TrustDomainRoot::generate();
    let other = TrustDomainRoot::generate();
    let pool = pool(&root);

    let err = receive_network_state(
        &pool,
        &root.id(),
        &network_id("office-net"),
        state(&other, "office-net", 1),
        None,
        "wrong-domain",
    )
    .await
    .unwrap_err();
    assert!(matches!(err, NetworkStateReceiveError::TrustDomainMismatch));

    let err = receive_network_state(
        &pool,
        &root.id(),
        &network_id("office-net"),
        state(&root, "lab-net", 1),
        None,
        "wrong-network",
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        NetworkStateReceiveError::NetworkLocalIdMismatch
    ));

    let mut tampered = state(&root, "office-net", 1);
    tampered.details.payload.acl.push(0xAA);
    let err = receive_network_state(
        &pool,
        &root.id(),
        &network_id("office-net"),
        tampered,
        None,
        "tampered",
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        NetworkStateReceiveError::PoolApply(pactmesh::trust::pool::PoolApplyError::BadSignature)
    ));
}
