//! Tests for `trust::pool` (T-061 basic, T-062 verify, T-063 multi-domain).

use pactmesh::trust::network_state::UnsignedNetworkState;
use pactmesh::trust::pool::{PoolApplyError, TrustDomainPool};
use pactmesh::trust::trust_domain_meta::UnsignedTrustDomainMeta;
use pactmesh::trust::{NetworkLocalId, TrustDomainRoot};

fn sample_unsigned_network_state_for_root(
    root: &TrustDomainRoot,
    version: u64,
) -> UnsignedNetworkState {
    UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str("office-net").unwrap(),
        version,
        payload: pactmesh::trust::NetworkStatePayload {
            member_cert_index: Vec::new(),
            revoked_certs: Vec::new(),
            disabled_certs: Vec::new(),
            acl: Vec::new(),
            routes: Vec::new(),
            peer_hints: Vec::new(),
        },
    }
}

fn sample_unsigned_trust_domain_meta_for_root(
    root: &TrustDomainRoot,
    version: u64,
) -> UnsignedTrustDomainMeta {
    UnsignedTrustDomainMeta {
        trust_domain_id: root.id(),
        version,
        active_relays: Vec::new(),
        outbound_grants: Vec::new(),
    }
}

#[test]
fn test_add_root_returns_id() {
    let root = TrustDomainRoot::generate();
    let mut pool = TrustDomainPool::new();

    let id = pool.add_root(root.public_key().into());

    assert_eq!(id, root.id());
    assert_eq!(pool.ids().copied().collect::<Vec<_>>(), vec![root.id()]);
}

#[test]
fn test_apply_network_state_increments() {
    let root = TrustDomainRoot::generate();
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());

    let state_v1 = sample_unsigned_network_state_for_root(&root, 1).sign(&root);
    let state_v2 = sample_unsigned_network_state_for_root(&root, 2).sign(&root);

    assert_eq!(pool.apply_network_state(state_v1), Ok(()));
    assert_eq!(pool.apply_network_state(state_v2), Ok(()));

    let meta_v1 = sample_unsigned_trust_domain_meta_for_root(&root, 1).sign(&root);
    let meta_v2 = sample_unsigned_trust_domain_meta_for_root(&root, 2).sign(&root);

    assert_eq!(pool.apply_trust_domain_meta(meta_v1), Ok(()));
    assert_eq!(pool.apply_trust_domain_meta(meta_v2), Ok(()));
}

#[test]
fn test_apply_old_version_rejected() {
    let root = TrustDomainRoot::generate();
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());

    let state_v2 = sample_unsigned_network_state_for_root(&root, 2).sign(&root);
    let state_v1 = sample_unsigned_network_state_for_root(&root, 1).sign(&root);

    assert_eq!(pool.apply_network_state(state_v2), Ok(()));
    assert_eq!(
        pool.apply_network_state(state_v1),
        Err(PoolApplyError::StaleVersion { have: 2, got: 1 })
    );
}

#[test]
fn test_apply_wrong_signer_rejected() {
    let root = TrustDomainRoot::generate();
    let wrong_root = TrustDomainRoot::generate();
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());

    let wrong_state = sample_unsigned_network_state_for_root(&wrong_root, 1).sign(&wrong_root);

    assert_eq!(
        pool.apply_network_state(wrong_state),
        Err(PoolApplyError::UnknownDomain)
    );
}

#[test]
fn test_verify_full_chain_happy() {
    use ed25519_dalek::SigningKey;
    use pactmesh::trust::member_cert::{Capabilities, UnsignedMemberCert};
    use pnet::ipnetwork::IpNetwork as IpNet;
    use rand::rngs::OsRng;
    use std::str::FromStr;

    let root = TrustDomainRoot::generate();
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    let state = sample_unsigned_network_state_for_root(&root, 42).sign(&root);
    assert_eq!(pool.apply_network_state(state), Ok(()));

    let cert = UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str("office-net").unwrap(),
        device_pk: SigningKey::generate(&mut OsRng).verifying_key(),
        device_label: "laptop-a".to_owned(),
        not_before: 1_715_000_000,
        expires_at: 1_716_000_000,
        capabilities: Capabilities {
            can_be_exit_node: false,
            can_relay_data: true,
            can_relay_control: false,
            can_proxy_subnet: vec![IpNet::from_str("10.0.0.0/24").unwrap()],
        },
        network_state_version_ref: 42,
        hostname: None,
    }
    .sign(&root);

    let cached = pool.verify_member_cert(&cert, 1_715_000_100).unwrap();

    assert_eq!(cached.cert, cert);
    assert_eq!(cached.fingerprint, cert.fingerprint());
    assert_eq!(cached.signer_id, root.id());
    assert_eq!(cached.is_active_at(1_715_000_100), true);
}

#[test]
fn test_verify_revoked_rejected() {
    use ed25519_dalek::SigningKey;
    use pactmesh::trust::member_cert::{Capabilities, UnsignedMemberCert};
    use pactmesh::trust::pool::PoolVerifyError;
    use pactmesh::trust::revocation::{RevocationReason, RevokedCert};
    use pnet::ipnetwork::IpNetwork as IpNet;
    use rand::rngs::OsRng;
    use std::str::FromStr;

    let root = TrustDomainRoot::generate();
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    let cert = UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str("office-net").unwrap(),
        device_pk: SigningKey::generate(&mut OsRng).verifying_key(),
        device_label: "laptop-a".to_owned(),
        not_before: 1_715_000_000,
        expires_at: 1_716_000_000,
        capabilities: Capabilities {
            can_be_exit_node: false,
            can_relay_data: true,
            can_relay_control: false,
            can_proxy_subnet: vec![IpNet::from_str("10.0.0.0/24").unwrap()],
        },
        network_state_version_ref: 42,
        hostname: None,
    }
    .sign(&root);
    let mut state = sample_unsigned_network_state_for_root(&root, 42);
    state.payload.revoked_certs.push(RevokedCert {
        cert_fingerprint: cert.fingerprint(),
        revoked_at: 1_715_000_050,
        reason_code: RevocationReason::Removed,
        reason_note: None,
    });
    assert_eq!(pool.apply_network_state(state.sign(&root)), Ok(()));

    assert!(matches!(
        pool.verify_member_cert(&cert, 1_715_000_100),
        Err(PoolVerifyError::Revoked)
    ));
}

#[test]
fn test_verify_disabled_temporarily() {
    use ed25519_dalek::SigningKey;
    use pactmesh::trust::DisabledCert;
    use pactmesh::trust::member_cert::{Capabilities, UnsignedMemberCert};
    use pactmesh::trust::pool::PoolVerifyError;
    use pnet::ipnetwork::IpNetwork as IpNet;
    use rand::rngs::OsRng;
    use std::str::FromStr;

    let root = TrustDomainRoot::generate();
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    let cert = UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str("office-net").unwrap(),
        device_pk: SigningKey::generate(&mut OsRng).verifying_key(),
        device_label: "laptop-a".to_owned(),
        not_before: 1_715_000_000,
        expires_at: 1_716_000_000,
        capabilities: Capabilities {
            can_be_exit_node: false,
            can_relay_data: true,
            can_relay_control: false,
            can_proxy_subnet: vec![IpNet::from_str("10.0.0.0/24").unwrap()],
        },
        network_state_version_ref: 42,
        hostname: None,
    }
    .sign(&root);
    let mut state = sample_unsigned_network_state_for_root(&root, 42);
    state.payload.disabled_certs.push(DisabledCert {
        cert_fingerprint: cert.fingerprint(),
        disabled_at: 1_715_000_050,
        expected_until: Some(1_715_000_200),
        reason_note: None,
    });
    assert_eq!(pool.apply_network_state(state.sign(&root)), Ok(()));

    assert!(matches!(
        pool.verify_member_cert(&cert, 1_715_000_100),
        Err(PoolVerifyError::Disabled)
    ));
}

#[test]
fn test_verify_disabled_recovered_after_expected() {
    use ed25519_dalek::SigningKey;
    use pactmesh::trust::DisabledCert;
    use pactmesh::trust::member_cert::{Capabilities, UnsignedMemberCert};
    use pnet::ipnetwork::IpNetwork as IpNet;
    use rand::rngs::OsRng;
    use std::str::FromStr;

    let root = TrustDomainRoot::generate();
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    let cert = UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str("office-net").unwrap(),
        device_pk: SigningKey::generate(&mut OsRng).verifying_key(),
        device_label: "laptop-a".to_owned(),
        not_before: 1_715_000_000,
        expires_at: 1_716_000_000,
        capabilities: Capabilities {
            can_be_exit_node: false,
            can_relay_data: true,
            can_relay_control: false,
            can_proxy_subnet: vec![IpNet::from_str("10.0.0.0/24").unwrap()],
        },
        network_state_version_ref: 42,
        hostname: None,
    }
    .sign(&root);
    let mut state = sample_unsigned_network_state_for_root(&root, 42);
    state.payload.disabled_certs.push(DisabledCert {
        cert_fingerprint: cert.fingerprint(),
        disabled_at: 1_715_000_050,
        expected_until: Some(1_715_000_090),
        reason_note: None,
    });
    assert_eq!(pool.apply_network_state(state.sign(&root)), Ok(()));

    assert!(pool.verify_member_cert(&cert, 1_715_000_100).is_ok());
}

#[test]
fn test_multi_domain_isolated() {
    let root_a = TrustDomainRoot::generate();
    let root_b = TrustDomainRoot::generate();
    let mut pool = TrustDomainPool::new();

    let id_a = pool.add_root(root_a.public_key().into());
    let id_b = pool.add_root(root_b.public_key().into());

    assert_eq!(id_a, root_a.id());
    assert_eq!(id_b, root_b.id());
    let ids = pool.ids().copied().collect::<Vec<_>>();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&id_a));
    assert!(ids.contains(&id_b));

    let state_a = sample_unsigned_network_state_for_root(&root_a, 1).sign(&root_a);
    let state_b = sample_unsigned_network_state_for_root(&root_b, 1).sign(&root_b);

    assert_eq!(pool.apply_network_state(state_a), Ok(()));
    assert_eq!(pool.apply_network_state(state_b), Ok(()));

    let stale_for_a = sample_unsigned_network_state_for_root(&root_a, 1).sign(&root_a);
    assert_eq!(
        pool.apply_network_state(stale_for_a),
        Err(PoolApplyError::StaleVersion { have: 1, got: 1 })
    );
}

fn sample_member_cert_for_root(root: &TrustDomainRoot) -> pactmesh::trust::member_cert::MemberCert {
    use ed25519_dalek::SigningKey;
    use pactmesh::trust::member_cert::{Capabilities, UnsignedMemberCert};
    use pnet::ipnetwork::IpNetwork as IpNet;
    use rand::rngs::OsRng;
    use std::str::FromStr;

    UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str("office-net").unwrap(),
        device_pk: SigningKey::generate(&mut OsRng).verifying_key(),
        device_label: "borrower-a".to_owned(),
        not_before: 1_715_000_000,
        expires_at: 1_716_000_000,
        capabilities: Capabilities {
            can_be_exit_node: false,
            can_relay_data: true,
            can_relay_control: false,
            can_proxy_subnet: vec![IpNet::from_str("10.0.0.0/24").unwrap()],
        },
        network_state_version_ref: 42,
        hostname: None,
    }
    .sign(root)
}

#[test]
fn test_verify_with_external_root_accepts_cert_signed_by_external_root() {
    let external_root = TrustDomainRoot::generate();
    let pool = TrustDomainPool::new();
    let cert = sample_member_cert_for_root(&external_root);

    assert_eq!(
        pool.verify_with_external_root(&cert, &external_root.public_key(), 1_715_000_100),
        Ok(())
    );
}

#[test]
fn test_verify_with_external_root_rejects_wrong_root() {
    use pactmesh::trust::pool::PoolVerifyError;

    let external_root = TrustDomainRoot::generate();
    let wrong_root = TrustDomainRoot::generate();
    let pool = TrustDomainPool::new();
    let cert = sample_member_cert_for_root(&external_root);

    assert_eq!(
        pool.verify_with_external_root(&cert, &wrong_root.public_key(), 1_715_000_100),
        Err(PoolVerifyError::BadSignature)
    );
}

#[test]
fn test_verify_with_external_root_rejects_expired_cert() {
    use pactmesh::trust::pool::PoolVerifyError;

    let external_root = TrustDomainRoot::generate();
    let pool = TrustDomainPool::new();
    let cert = sample_member_cert_for_root(&external_root);

    assert_eq!(
        pool.verify_with_external_root(&cert, &external_root.public_key(), 1_716_000_000),
        Err(PoolVerifyError::Expired {
            now: 1_716_000_000,
            ea: 1_716_000_000,
        })
    );
}

#[test]
fn test_verify_with_external_root_does_not_consult_local_pool() {
    let external_root = TrustDomainRoot::generate();
    let pool = TrustDomainPool::new();
    let cert = sample_member_cert_for_root(&external_root);

    assert_eq!(pool.ids().count(), 0);
    assert_eq!(
        pool.verify_with_external_root(&cert, &external_root.public_key(), 1_715_000_100),
        Ok(())
    );
}

#[test]
fn test_verify_with_external_root_propagates_signature_error() {
    use pactmesh::trust::pool::PoolVerifyError;

    let external_root = TrustDomainRoot::generate();
    let pool = TrustDomainPool::new();
    let mut cert = sample_member_cert_for_root(&external_root);
    cert.signature.0.push(0xff);

    assert_eq!(
        pool.verify_with_external_root(&cert, &external_root.public_key(), 1_715_000_100),
        Err(PoolVerifyError::BadSignature)
    );
}
