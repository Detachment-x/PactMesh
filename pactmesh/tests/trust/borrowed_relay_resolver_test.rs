use ed25519_dalek::SigningKey;
use pactmesh::trust::relay_borrow::BorrowedRelayError;
use pactmesh::trust::trust_domain_meta::ActiveRelay;
use pactmesh::trust::{
    BorrowedRelayProof, BorrowedRelayResolver, Capabilities, MemberCert, NetworkBootstrap,
    NetworkLocalId, NetworkStatePayload, RelayCandidate, RelayCapabilities, RelayGrantEntry,
    RelayGrantTable, SignedTrustDomainMeta, TrustDomainId, TrustDomainPool, TrustDomainRoot,
    UnsignedMemberCert, UnsignedNetworkState, UnsignedTrustDomainMeta,
};
use rand::rngs::OsRng;
use std::time::{SystemTime, UNIX_EPOCH};

const NOW: u64 = 1_700_000_000;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

fn sample_member_cert(root: &TrustDomainRoot, expires_at: u64) -> MemberCert {
    let device_pk = SigningKey::generate(&mut OsRng).verifying_key();

    UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str("office-net").unwrap(),
        device_pk,
        device_label: "relay-client".to_owned(),
        not_before: NOW.saturating_sub(60),
        expires_at,
        capabilities: Capabilities {
            can_relay_data: true,
            can_relay_control: false,
            can_proxy_subnet: Vec::new(),
        },
        network_state_version_ref: 1,
        hostname: None,
    }
    .sign(root)
}

fn relay_grants_for(trust_domain_id: TrustDomainId) -> RelayGrantTable {
    RelayGrantTable::from_entries(vec![RelayGrantEntry {
        foreign_root_pk: trust_domain_id,
        capabilities: RelayCapabilities {
            can_relay_data: true,
            can_assist_holepunch: true,
        },
        expires_at: NOW + 3600,
    }])
}

#[test]
fn test_validate_ok_returns_trust_domain_id() {
    let root = TrustDomainRoot::generate();
    let proof = BorrowedRelayProof {
        trust_domain_id: root.id(),
        member_cert: sample_member_cert(&root, NOW + 3600),
        timestamp: NOW,
    };

    let resolver = BorrowedRelayResolver;
    let grants = relay_grants_for(root.id());

    assert_eq!(resolver.validate(&proof, &grants, NOW), Ok(root.id()));
}

#[test]
fn test_validate_permits_miss_returns_not_serving() {
    let root = TrustDomainRoot::generate();
    let tdid = root.id();
    let proof = BorrowedRelayProof {
        trust_domain_id: tdid,
        member_cert: sample_member_cert(&root, NOW + 3600),
        timestamp: NOW,
    };

    let resolver = BorrowedRelayResolver;

    assert_eq!(
        resolver.validate(&proof, &RelayGrantTable::empty(), NOW),
        Err(BorrowedRelayError::NotServing(tdid))
    );
}

#[test]
fn test_validate_cert_expired() {
    let root = TrustDomainRoot::generate();
    let proof = BorrowedRelayProof {
        trust_domain_id: root.id(),
        member_cert: sample_member_cert(&root, NOW - 1),
        timestamp: NOW,
    };

    let resolver = BorrowedRelayResolver;

    assert_eq!(
        resolver.validate(&proof, &relay_grants_for(root.id()), NOW),
        Err(BorrowedRelayError::Expired)
    );
}

#[test]
fn test_validate_timestamp_skew_too_large() {
    let root = TrustDomainRoot::generate();
    let proof = BorrowedRelayProof {
        trust_domain_id: root.id(),
        member_cert: sample_member_cert(&root, NOW + 3600),
        timestamp: NOW - 301,
    };

    let resolver = BorrowedRelayResolver;

    assert_eq!(
        resolver.validate(&proof, &relay_grants_for(root.id()), NOW),
        Err(BorrowedRelayError::BadTimestamp)
    );
}

fn sample_trust_domain_meta(
    root: &TrustDomainRoot,
    expires_at: u64,
    can_relay_data: bool,
) -> SignedTrustDomainMeta {
    UnsignedTrustDomainMeta {
        trust_domain_id: root.id(),
        version: 1,
        active_relays: vec![ActiveRelay {
            device_pk: SigningKey::generate(&mut OsRng).verifying_key(),
            device_label: "relay-a".to_owned(),
            capabilities: RelayCapabilities {
                can_relay_data,
                can_assist_holepunch: true,
            },
            expires_at,
        }],
        outbound_grants: Vec::new(),
    }
    .sign(root)
}

fn sample_network_state(root: &TrustDomainRoot) -> pactmesh::trust::SignedNetworkState {
    UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str("office-net").unwrap(),
        version: 1,
        payload: NetworkStatePayload {
            member_cert_index: Vec::new(),
            revoked_certs: Vec::new(),
            disabled_certs: Vec::new(),
            acl: Vec::new(),
            routes: Vec::new(),
            peer_hints: Vec::new(),
        },
    }
    .sign(root)
}

fn bootstrap_for(root: &TrustDomainRoot, url: &str) -> NetworkBootstrap {
    NetworkBootstrap {
        trust_domain_id: root.id(),
        pk_root: root.public_key(),
        network_local_id: NetworkLocalId::try_from_str("office-net").unwrap(),
        bootstrap_seeds: vec![url.parse().unwrap()],
        trust_domain_label: None,
        network_name: Some("target-net".to_owned()),
        description: None,
    }
}

fn pool_with_target(
    root: &TrustDomainRoot,
    bootstrap: Option<NetworkBootstrap>,
    relay_expires_at: u64,
    can_relay_data: bool,
) -> TrustDomainPool {
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    pool.apply_network_state(sample_network_state(root))
        .unwrap();
    pool.apply_trust_domain_meta(sample_trust_domain_meta(
        root,
        relay_expires_at,
        can_relay_data,
    ))
    .unwrap();
    if let Some(bootstrap) = bootstrap {
        pool.apply_network_bootstrap(&root.id(), bootstrap).unwrap();
    }
    pool
}

#[test]
fn test_candidates_for_target_returns_bootstrap_seed() {
    let now = now_unix();
    let root = TrustDomainRoot::generate();
    let pool = pool_with_target(
        &root,
        Some(bootstrap_for(&root, "tcp://127.0.0.1:11010")),
        now + 3600,
        true,
    );

    let candidates = BorrowedRelayResolver::candidates_for_target(&root.id(), &pool);

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].foreign_trust_domain_id, root.id());
    assert_eq!(candidates[0].relay_url.as_str(), "tcp://127.0.0.1:11010");
    assert_eq!(candidates[0].foreign_root_pk, root.public_key());
}

#[test]
fn test_candidates_for_target_without_bootstrap_returns_empty() {
    let now = now_unix();
    let root = TrustDomainRoot::generate();
    let pool = pool_with_target(&root, None, now + 3600, true);

    let candidates = BorrowedRelayResolver::candidates_for_target(&root.id(), &pool);

    assert!(candidates.is_empty());
}

#[test]
fn test_candidates_for_target_filters_expired_relays() {
    let now = now_unix();
    let root = TrustDomainRoot::generate();
    let pool = pool_with_target(
        &root,
        Some(bootstrap_for(&root, "tcp://127.0.0.1:11010")),
        now - 1,
        true,
    );

    let candidates = BorrowedRelayResolver::candidates_for_target(&root.id(), &pool);

    assert!(candidates.is_empty());
}

#[test]
fn test_candidates_for_target_without_meta_returns_empty() {
    let root = TrustDomainRoot::generate();
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    pool.apply_network_state(sample_network_state(&root))
        .unwrap();
    pool.apply_network_bootstrap(&root.id(), bootstrap_for(&root, "tcp://127.0.0.1:11010"))
        .unwrap();

    let candidates = BorrowedRelayResolver::candidates_for_target(&root.id(), &pool);

    assert!(candidates.is_empty());
}

#[test]
fn test_candidates_for_target_requires_relay_capability() {
    let now = now_unix();
    let root = TrustDomainRoot::generate();
    let pool = pool_with_target(
        &root,
        Some(bootstrap_for(&root, "tcp://127.0.0.1:11010")),
        now + 3600,
        false,
    );

    let candidates = BorrowedRelayResolver::candidates_for_target(&root.id(), &pool);

    assert!(candidates.is_empty());
}

#[test]
fn test_relay_candidate_fields_round_trip() {
    let root = TrustDomainRoot::generate();
    let candidate = RelayCandidate {
        relay_url: "udp://192.0.2.1:12345".parse().unwrap(),
        foreign_trust_domain_id: root.id(),
        foreign_root_pk: root.public_key(),
    };

    assert_eq!(candidate.relay_url.as_str(), "udp://192.0.2.1:12345");
    assert_eq!(candidate.foreign_trust_domain_id, root.id());
    assert_eq!(candidate.foreign_root_pk, root.public_key());
}
