use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use pnet::ipnetwork::IpNetwork as IpNet;
use tokio::sync::RwLock;

use crate::trust::{
    Capabilities, DisabledCert, MemberCert, NetworkLocalId, NetworkStatePayload, RevocationReason,
    RevokedCert, SignKey, TrustDomainPool, TrustDomainRoot, UnsignedMemberCert,
    UnsignedNetworkState, VerifyKey,
};

const NETWORK_LOCAL_ID: &str = "office-net";
const CERT_NOT_BEFORE: u64 = 1_715_000_000;
const CERT_EXPIRES_AT: u64 = 4_102_444_800;
const NETWORK_STATE_VERSION: u64 = 42;

pub fn empty_trust_pool() -> Arc<RwLock<TrustDomainPool>> {
    Arc::new(RwLock::new(TrustDomainPool::new()))
}

pub fn trust_pool_with_root(root_pk: VerifyKey) -> Arc<RwLock<TrustDomainPool>> {
    let mut pool = TrustDomainPool::new();
    pool.add_root(root_pk);
    Arc::new(RwLock::new(pool))
}

pub fn sample_root_and_context() -> (TrustDomainRoot, SignKey, MemberCert) {
    let root = TrustDomainRoot::generate();
    let sk_self = SignKey::generate();
    let cert = sample_member_cert(&root, &sk_self);
    (root, sk_self, cert)
}

pub fn sample_member_cert(root: &TrustDomainRoot, sk_self: &SignKey) -> MemberCert {
    let device_pk =
        VerifyingKey::from_bytes(&sk_self.verify_key().0).expect("verify key bytes valid");
    UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str(NETWORK_LOCAL_ID).unwrap(),
        device_pk,
        device_label: "device-a".to_owned(),
        not_before: CERT_NOT_BEFORE,
        expires_at: CERT_EXPIRES_AT,
        capabilities: Capabilities {
            can_relay_data: true,
            can_relay_control: true,
            can_proxy_subnet: vec!["10.0.0.0/24".parse::<IpNet>().unwrap()],
        },
        network_state_version_ref: NETWORK_STATE_VERSION,
        hostname: None,
    }
    .sign(root)
}

pub fn trust_pool_with_cert(
    root: &TrustDomainRoot,
    cert: &MemberCert,
) -> Arc<RwLock<TrustDomainPool>> {
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    pool.apply_network_state(sample_network_state(root, cert, None, None))
        .unwrap();
    Arc::new(RwLock::new(pool))
}

pub fn trust_pool_with_revoked_cert(
    root: &TrustDomainRoot,
    cert: &MemberCert,
) -> Arc<RwLock<TrustDomainPool>> {
    let revoked = RevokedCert {
        cert_fingerprint: cert.fingerprint(),
        revoked_at: CERT_NOT_BEFORE + 10,
        reason_code: RevocationReason::Removed,
        reason_note: None,
    };
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    pool.apply_network_state(sample_network_state(root, cert, Some(revoked), None))
        .unwrap();
    Arc::new(RwLock::new(pool))
}

pub fn trust_pool_with_disabled_cert(
    root: &TrustDomainRoot,
    cert: &MemberCert,
) -> Arc<RwLock<TrustDomainPool>> {
    let disabled = DisabledCert {
        cert_fingerprint: cert.fingerprint(),
        disabled_at: CERT_NOT_BEFORE + 10,
        expected_until: Some(CERT_EXPIRES_AT + 100),
        reason_note: None,
    };
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    pool.apply_network_state(sample_network_state(root, cert, None, Some(disabled)))
        .unwrap();
    Arc::new(RwLock::new(pool))
}

pub fn trust_pool_with_expired_cert(
    root: &TrustDomainRoot,
    cert: &MemberCert,
) -> Arc<RwLock<TrustDomainPool>> {
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    pool.apply_network_state(sample_network_state(root, cert, None, None))
        .unwrap();
    Arc::new(RwLock::new(pool))
}

fn sample_network_state(
    root: &TrustDomainRoot,
    cert: &MemberCert,
    revoked: Option<RevokedCert>,
    disabled: Option<DisabledCert>,
) -> crate::trust::SignedNetworkState {
    UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: cert.details.network_local_id.clone(),
        version: NETWORK_STATE_VERSION,
        payload: NetworkStatePayload {
            member_cert_index: Vec::new(),
            revoked_certs: revoked.into_iter().collect(),
            disabled_certs: disabled.into_iter().collect(),
            acl: Vec::new(),
            routes: Vec::new(),
        },
    }
    .sign(root)
}
