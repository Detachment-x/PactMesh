use pactmesh::trust::{
    LanRecoveryError, NetworkLocalId, NetworkStatePayload, PeerHint, TrustDomainPool,
    TrustDomainRoot, UnsignedNetworkState, apply_lan_recovered_network_state,
};

fn network_id(value: &str) -> NetworkLocalId {
    NetworkLocalId::try_from_str(value).unwrap()
}

fn peer_hint(url: &str) -> PeerHint {
    PeerHint {
        url: url.to_owned(),
        label: Some("new-public-peer".to_owned()),
        capabilities: vec!["public-reachable".to_owned()],
        updated_at: 100,
        expires_at: Some(2_000_000_000),
    }
}

fn state(
    root: &TrustDomainRoot,
    network: &str,
    version: u64,
    hints: Vec<PeerHint>,
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
            peer_hints: hints,
            ip_assignments: Vec::new(),
            capability_grants: Vec::new(),
            hostname_bindings: Vec::new(),
        },
    }
    .sign(root)
}

fn pool_for(
    root: &TrustDomainRoot,
    initial: pactmesh::trust::SignedNetworkState,
) -> TrustDomainPool {
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    pool.apply_network_state(initial).unwrap();
    pool
}

#[test]
fn test_lan_recovery_accepts_trusted_newer_state_with_peer_hint() {
    let root = TrustDomainRoot::generate();
    let mut pool = pool_for(&root, state(&root, "office-net", 1, Vec::new()));
    let recovered = state(
        &root,
        "office-net",
        2,
        vec![peer_hint("tcp://203.0.113.20:11010")],
    );

    let result = apply_lan_recovered_network_state(
        &mut pool,
        &root.id(),
        &network_id("office-net"),
        recovered,
    );

    assert_eq!(result, Ok(()));
    let stored = pool
        .network_state(&root.id(), &network_id("office-net"))
        .unwrap();
    assert_eq!(stored.details.version, 2);
    assert_eq!(
        stored.details.payload.peer_hints[0].url,
        "tcp://203.0.113.20:11010"
    );
}

#[test]
fn test_lan_recovery_rejects_wrong_trust_domain() {
    let root = TrustDomainRoot::generate();
    let other = TrustDomainRoot::generate();
    let mut pool = pool_for(&root, state(&root, "office-net", 1, Vec::new()));

    let err = apply_lan_recovered_network_state(
        &mut pool,
        &root.id(),
        &network_id("office-net"),
        state(
            &other,
            "office-net",
            2,
            vec![peer_hint("tcp://203.0.113.20:11010")],
        ),
    )
    .unwrap_err();

    assert_eq!(err, LanRecoveryError::TrustDomainMismatch);
}

#[test]
fn test_lan_recovery_rejects_wrong_network() {
    let root = TrustDomainRoot::generate();
    let mut pool = pool_for(&root, state(&root, "office-net", 1, Vec::new()));

    let err = apply_lan_recovered_network_state(
        &mut pool,
        &root.id(),
        &network_id("office-net"),
        state(
            &root,
            "lab-net",
            2,
            vec![peer_hint("tcp://203.0.113.20:11010")],
        ),
    )
    .unwrap_err();

    assert_eq!(err, LanRecoveryError::NetworkMismatch);
}

#[test]
fn test_lan_recovery_rejects_tampered_state() {
    let root = TrustDomainRoot::generate();
    let mut pool = pool_for(&root, state(&root, "office-net", 1, Vec::new()));
    let mut recovered = state(&root, "office-net", 2, Vec::new());
    recovered
        .details
        .payload
        .peer_hints
        .push(peer_hint("tcp://203.0.113.20:11010"));

    let err = apply_lan_recovered_network_state(
        &mut pool,
        &root.id(),
        &network_id("office-net"),
        recovered,
    )
    .unwrap_err();

    assert!(matches!(err, LanRecoveryError::PoolApply(_)));
}
