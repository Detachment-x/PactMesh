use easytier::proto::peer_rpc::{JoinRequestEnvelope, TrustDomainMetaEnvelope};
use easytier::trust::trust_domain_meta::OutboundGrant;
use easytier::trust::{
    ActiveRelay, JoinRequest, NetworkLocalId, RelayCapabilities, SignKey, SignedTrustDomainMeta,
    TrustDomainRoot, UnsignedTrustDomainMeta, WireError, join_request_from_envelope,
    join_request_to_envelope, to_canonical_cbor, trust_domain_meta_from_envelope,
    trust_domain_meta_to_envelope,
};

fn vk_from(sk: &SignKey) -> ed25519_dalek::VerifyingKey {
    ed25519_dalek::VerifyingKey::from_bytes(&sk.verify_key().0).unwrap()
}

fn network_local_id() -> NetworkLocalId {
    NetworkLocalId::try_from_str("office-net").unwrap()
}

fn relay_caps() -> RelayCapabilities {
    RelayCapabilities {
        can_relay_data: true,
        can_assist_holepunch: true,
    }
}

fn meta_with_outbound_grants(
    root: &TrustDomainRoot,
    grants: Vec<OutboundGrant>,
) -> SignedTrustDomainMeta {
    let relay_sk = SignKey::generate();
    UnsignedTrustDomainMeta {
        trust_domain_id: root.id(),
        version: 11,
        active_relays: vec![ActiveRelay {
            device_pk: vk_from(&relay_sk),
            device_label: "relay-a".to_owned(),
            capabilities: relay_caps(),
            expires_at: 3600,
        }],
        outbound_grants: grants,
    }
    .sign(root)
}

fn join_request(root: &TrustDomainRoot, hint: &str) -> JoinRequest {
    JoinRequest::new_signed(
        root.id(),
        network_local_id(),
        &SignKey::generate(),
        "device-a".to_owned(),
        hint.to_owned(),
    )
}

#[test]
fn test_meta_round_trip_with_active_relays() {
    let root = TrustDomainRoot::generate();
    let meta = meta_with_outbound_grants(&root, Vec::new());
    let decoded = trust_domain_meta_from_envelope(&trust_domain_meta_to_envelope(&meta)).unwrap();

    assert_eq!(decoded, meta);
    decoded.verify(&root.public_key().into()).unwrap();
}

#[test]
fn test_meta_round_trip_with_outbound_grants() {
    let root = TrustDomainRoot::generate();
    let foreign = TrustDomainRoot::generate();
    let meta = meta_with_outbound_grants(
        &root,
        vec![OutboundGrant {
            foreign_root_pk: foreign.public_key(),
            foreign_trust_domain_id: foreign.id(),
            capabilities: relay_caps(),
            expires_at: 7200,
        }],
    );
    let decoded = trust_domain_meta_from_envelope(&trust_domain_meta_to_envelope(&meta)).unwrap();

    assert_eq!(decoded.details.outbound_grants.len(), 1);
    assert_eq!(decoded, meta);
}

#[test]
fn test_meta_corrupted_cbor_rejected() {
    let err = trust_domain_meta_from_envelope(&TrustDomainMetaEnvelope {
        cbor: vec![0xff, 0x02],
    })
    .unwrap_err();

    assert!(matches!(err, WireError::CborDecodeFailed(_)));
}

#[test]
fn test_join_round_trip_basic() {
    let root = TrustDomainRoot::generate();
    let request = join_request(&root, "near relay-a");
    let decoded = join_request_from_envelope(&join_request_to_envelope(&request)).unwrap();

    assert_eq!(decoded, request);
    decoded.verify_self_signature().unwrap();
}

#[test]
fn test_join_with_empty_hint_round_trip() {
    let root = TrustDomainRoot::generate();
    let request = join_request(&root, "");
    let env = join_request_to_envelope(&request);
    let decoded = join_request_from_envelope(&env).unwrap();

    assert_eq!(decoded.hint, "");
    assert_eq!(to_canonical_cbor(&decoded), env.cbor);
}

#[test]
fn test_join_corrupted_cbor_rejected() {
    let err = join_request_from_envelope(&JoinRequestEnvelope {
        cbor: vec![0xff, 0x03],
    })
    .unwrap_err();

    assert!(matches!(err, WireError::CborDecodeFailed(_)));
}
