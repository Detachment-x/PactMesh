use ed25519_dalek::SigningKey;
use pactmesh::trust::trust_domain_meta::{
    ActiveRelay, OutboundGrant, RelayCapabilities, TrustDomainMetaVerifyError,
    UnsignedTrustDomainMeta,
};
use pactmesh::trust::{TrustDomainId, TrustDomainRoot};
use pactmesh::trust::{from_cbor, to_canonical_cbor};
use rand::rngs::OsRng;

fn sample_active_relay() -> ActiveRelay {
    ActiveRelay {
        device_pk: SigningKey::generate(&mut OsRng).verifying_key(),
        device_label: "relay-us-east-1".to_owned(),
        capabilities: RelayCapabilities {
            can_relay_data: true,
            can_assist_holepunch: false,
        },
        expires_at: 1_720_000_000,
    }
}

fn sample_outbound_grant() -> OutboundGrant {
    let foreign_root_pk = SigningKey::generate(&mut OsRng).verifying_key();

    OutboundGrant {
        foreign_root_pk,
        foreign_trust_domain_id: TrustDomainId::from_root_pubkey(&foreign_root_pk),
        capabilities: RelayCapabilities {
            can_relay_data: false,
            can_assist_holepunch: true,
        },
        expires_at: 1_730_000_000,
    }
}

#[test]
fn test_active_relay_round_trip() {
    let relay = sample_active_relay();

    let encoded = to_canonical_cbor(&relay);
    let decoded: ActiveRelay = from_cbor(&encoded).unwrap();

    assert_eq!(decoded, relay);
    assert_eq!(decoded.device_pk.to_bytes(), relay.device_pk.to_bytes());
    assert_eq!(to_canonical_cbor(&decoded), encoded);
}

#[test]
fn test_active_relay_capabilities_round_trip() {
    let capabilities = RelayCapabilities {
        can_relay_data: false,
        can_assist_holepunch: true,
    };

    let encoded = to_canonical_cbor(&capabilities);
    let decoded: RelayCapabilities = from_cbor(&encoded).unwrap();

    assert_eq!(decoded, capabilities);
    assert_eq!(to_canonical_cbor(&decoded), encoded);
}
fn sample_unsigned_trust_domain_meta_for_root(root: &TrustDomainRoot) -> UnsignedTrustDomainMeta {
    UnsignedTrustDomainMeta {
        trust_domain_id: root.id(),
        version: 7,
        active_relays: vec![sample_active_relay()],
        outbound_grants: vec![],
    }
}

#[derive(minicbor::Encode)]
struct LegacyUnsignedTrustDomainMeta<'a> {
    #[n(0)]
    trust_domain_id: TrustDomainId,
    #[n(1)]
    version: u64,
    #[n(2)]
    active_relays: &'a [ActiveRelay],
}

#[test]
fn test_sign_verify_happy_path() {
    let root = TrustDomainRoot::generate();
    let meta = sample_unsigned_trust_domain_meta_for_root(&root).sign(&root);

    assert_eq!(meta.verify(&root.public_key().into()), Ok(()));
}

#[test]
fn test_verify_wrong_root_rejected() {
    let root = TrustDomainRoot::generate();
    let wrong_root = TrustDomainRoot::generate();
    let meta = sample_unsigned_trust_domain_meta_for_root(&root).sign(&root);

    assert_eq!(
        meta.verify(&wrong_root.public_key().into()),
        Err(TrustDomainMetaVerifyError::DomainMismatch)
    );
}

#[test]
fn test_marshal_deterministic() {
    let root = TrustDomainRoot::generate();
    let meta = sample_unsigned_trust_domain_meta_for_root(&root);

    let left = meta.marshal_for_signing();
    let right = meta.marshal_for_signing();

    assert_eq!(left, right);
    assert_eq!(left, to_canonical_cbor(&meta));
}

#[test]
fn test_trust_domain_meta_sign_verify_happy_path() {
    test_sign_verify_happy_path();
}

#[test]
fn test_trust_domain_meta_verify_wrong_root_rejected() {
    test_verify_wrong_root_rejected();
}

#[test]
fn test_trust_domain_meta_round_trip() {
    let root = TrustDomainRoot::generate();
    let original = sample_unsigned_trust_domain_meta_for_root(&root).sign(&root);

    let encoded = to_canonical_cbor(&original);
    let decoded: pactmesh::trust::trust_domain_meta::SignedTrustDomainMeta =
        from_cbor(&encoded).unwrap();

    assert_eq!(decoded, original);
    assert_eq!(to_canonical_cbor(&decoded), encoded);
}

#[test]
fn test_trust_domain_meta_marshal_deterministic() {
    test_marshal_deterministic();
}

#[test]
fn test_trust_domain_meta_outbound_grants_round_trip_cbor() {
    let root = TrustDomainRoot::generate();
    let mut meta = sample_unsigned_trust_domain_meta_for_root(&root);
    meta.outbound_grants = vec![sample_outbound_grant()];

    let encoded = to_canonical_cbor(&meta);
    let decoded: UnsignedTrustDomainMeta = from_cbor(&encoded).unwrap();

    assert_eq!(decoded, meta);
    assert_eq!(decoded.outbound_grants.len(), 1);
    assert_eq!(to_canonical_cbor(&decoded), encoded);
}

#[test]
fn test_trust_domain_meta_signature_covers_outbound_grants() {
    let root = TrustDomainRoot::generate();
    let mut meta = sample_unsigned_trust_domain_meta_for_root(&root).sign(&root);
    meta.details.outbound_grants.push(sample_outbound_grant());

    assert_eq!(
        meta.verify(&root.public_key().into()),
        Err(TrustDomainMetaVerifyError::BadSignature)
    );
}

#[test]
fn test_outbound_grant_capabilities_preserved() {
    let grant = sample_outbound_grant();
    let encoded = to_canonical_cbor(&grant);
    let decoded: OutboundGrant = from_cbor(&encoded).unwrap();

    assert_eq!(decoded.capabilities, grant.capabilities);
    assert_eq!(decoded, grant);
}

#[test]
fn test_decode_legacy_meta_without_outbound_grants_yields_empty_vec() {
    let root = TrustDomainRoot::generate();
    let meta = sample_unsigned_trust_domain_meta_for_root(&root);
    let legacy = LegacyUnsignedTrustDomainMeta {
        trust_domain_id: meta.trust_domain_id,
        version: meta.version,
        active_relays: &meta.active_relays,
    };

    let encoded = to_canonical_cbor(&legacy);
    let decoded: UnsignedTrustDomainMeta = from_cbor(&encoded).unwrap();

    assert_eq!(decoded.trust_domain_id, meta.trust_domain_id);
    assert_eq!(decoded.version, meta.version);
    assert_eq!(decoded.active_relays, meta.active_relays);
    assert!(decoded.outbound_grants.is_empty());
}
