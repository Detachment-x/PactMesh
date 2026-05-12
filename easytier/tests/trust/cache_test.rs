use std::str::FromStr;

use easytier::trust::cache::CachedMemberCert;
use easytier::trust::member_cert::{Capabilities, MemberCert, UnsignedMemberCert};
use easytier::trust::{TrustDomainId, TrustDomainRoot};
use ed25519_dalek::SigningKey;
use pnet::ipnetwork::IpNetwork as IpNet;
use rand::rngs::OsRng;

fn sample_unsigned_member_cert_for_root(root: &TrustDomainRoot) -> UnsignedMemberCert {
    let device_pk = SigningKey::generate(&mut OsRng).verifying_key();

    UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: "office-net".parse().unwrap(),
        device_pk,
        device_label: "laptop-a".to_owned(),
        not_before: 1_715_000_000,
        expires_at: 1_716_000_000,
        capabilities: Capabilities {
            can_relay_data: true,
            can_relay_control: false,
            can_proxy_subnet: vec![
                IpNet::from_str("10.0.0.0/24").unwrap(),
                IpNet::from_str("2001:db8::/64").unwrap(),
            ],
        },
        network_state_version_ref: 42,
        hostname: None,
    }
}

fn sample_member_cert_for_root(root: &TrustDomainRoot) -> MemberCert {
    sample_unsigned_member_cert_for_root(root).sign(root)
}

#[test]
fn test_cached_member_cert_from_verified() {
    let root = TrustDomainRoot::generate();
    let cert = sample_member_cert_for_root(&root);
    let signer_id = TrustDomainId::from_root_pubkey(&root.public_key());
    let cached = CachedMemberCert::from_verified(cert.clone(), signer_id);

    assert_eq!(cached.cert, cert);
    assert_eq!(cached.fingerprint, cert.fingerprint());
    assert_eq!(cached.signer_id, signer_id);
    assert_eq!(
        cached.proxy_subnets_set,
        cert.details
            .capabilities
            .can_proxy_subnet
            .iter()
            .copied()
            .collect()
    );
}

#[test]
fn test_cached_member_cert_is_active_at_window() {
    let root = TrustDomainRoot::generate();
    let cert = sample_member_cert_for_root(&root);
    let cached = CachedMemberCert::from_verified(cert.clone(), root.id());

    assert!(!cached.is_active_at(cert.details.not_before - 1));
    assert!(cached.is_active_at(cert.details.not_before));
    assert!(cached.is_active_at(cert.details.expires_at - 1));
    assert!(!cached.is_active_at(cert.details.expires_at));
}
