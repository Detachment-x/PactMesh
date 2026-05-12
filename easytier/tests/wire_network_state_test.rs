use easytier::proto::peer_rpc::NetworkStateEnvelope;
use easytier::trust::{
    ACL_SCHEMA_VERSION, AclPolicy, AclRule, Action, DeviceFingerprint, DisabledCert,
    MemberCertFingerprint, MemberCertIndexEntry, NetworkLocalId, NetworkStatePayload, PortSpec,
    Proto, RevocationReason, RevokedCert, Selector, SignedNetworkState, TagName, TrustDomainRoot,
    UnsignedNetworkState, WireError, from_cbor, signed_network_state_from_envelope,
    signed_network_state_to_envelope, to_canonical_cbor,
};

fn fp(byte: u8) -> MemberCertFingerprint {
    MemberCertFingerprint([byte; 32])
}

fn device_fp(byte: u8) -> DeviceFingerprint {
    DeviceFingerprint::new([byte; 32])
}

fn network_local_id() -> NetworkLocalId {
    NetworkLocalId::try_from_str("office-net").unwrap()
}

fn signed_state(root: &TrustDomainRoot, payload: NetworkStatePayload) -> SignedNetworkState {
    UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: network_local_id(),
        version: 9,
        payload,
    }
    .sign(root)
}

fn policy(default_action: Action) -> AclPolicy {
    AclPolicy {
        tags: [(TagName::try_from_str("admin").unwrap(), vec![device_fp(1)])]
            .into_iter()
            .collect(),
        rules: vec![AclRule {
            action: Action::Drop,
            src: vec![Selector::Device(device_fp(1))],
            dst: vec![Selector::Wildcard],
            proto: Proto::Tcp,
            ports: Some(vec![PortSpec::Single(22)]),
        }],
        default_action,
        schema_version: ACL_SCHEMA_VERSION,
    }
}

fn full_payload() -> NetworkStatePayload {
    NetworkStatePayload {
        member_cert_index: vec![
            MemberCertIndexEntry {
                fingerprint: fp(1),
                device_label: "device-a".to_owned(),
                issued_at: 1,
                expires_at: 100,
            },
            MemberCertIndexEntry {
                fingerprint: fp(2),
                device_label: "device-b".to_owned(),
                issued_at: 2,
                expires_at: 200,
            },
        ],
        revoked_certs: vec![
            RevokedCert {
                cert_fingerprint: fp(3),
                revoked_at: 3,
                reason_code: RevocationReason::KeyCompromise,
                reason_note: Some("compromised".to_owned()),
            },
            RevokedCert {
                cert_fingerprint: fp(4),
                revoked_at: 4,
                reason_code: RevocationReason::Removed,
                reason_note: Some("removed".to_owned()),
            },
        ],
        disabled_certs: vec![
            DisabledCert {
                cert_fingerprint: fp(5),
                disabled_at: 5,
                expected_until: Some(50),
                reason_note: Some("maintenance".to_owned()),
            },
            DisabledCert {
                cert_fingerprint: fp(6),
                disabled_at: 6,
                expected_until: None,
                reason_note: Some("manual".to_owned()),
            },
        ],
        acl: to_canonical_cbor(&policy(Action::Drop)),
        routes: vec![0x01, 0x02],
    }
}

#[test]
fn test_round_trip_with_full_payload() {
    let root = TrustDomainRoot::generate();
    let state = signed_state(&root, full_payload());
    let decoded =
        signed_network_state_from_envelope(&signed_network_state_to_envelope(&state)).unwrap();

    assert_eq!(decoded, state);
    decoded.verify(&root.public_key().into()).unwrap();
}

#[test]
fn test_round_trip_with_empty_acl_default_action_accept() {
    let root = TrustDomainRoot::generate();
    let state = signed_state(
        &root,
        NetworkStatePayload {
            member_cert_index: Vec::new(),
            revoked_certs: Vec::new(),
            disabled_certs: Vec::new(),
            acl: to_canonical_cbor(&policy(Action::Accept)),
            routes: Vec::new(),
        },
    );
    let decoded =
        signed_network_state_from_envelope(&signed_network_state_to_envelope(&state)).unwrap();
    let acl: AclPolicy = from_cbor(&decoded.details.payload.acl).unwrap();

    assert_eq!(acl.default_action, Action::Accept);
}

#[test]
fn test_round_trip_signature_preserved_byte_exact() {
    let root = TrustDomainRoot::generate();
    let state = signed_state(&root, full_payload());
    let env = signed_network_state_to_envelope(&state);
    let decoded = signed_network_state_from_envelope(&env).unwrap();

    assert_eq!(to_canonical_cbor(&decoded), env.cbor);
}

#[test]
fn test_corrupted_cbor_rejected() {
    let err = signed_network_state_from_envelope(&NetworkStateEnvelope {
        cbor: vec![0xff, 0x01],
    })
    .unwrap_err();

    assert!(matches!(err, WireError::CborDecodeFailed(_)));
}
