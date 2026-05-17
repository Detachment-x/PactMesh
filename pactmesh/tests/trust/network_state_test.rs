//! Tests for `trust::network_state` (T-041 payload, T-042 sign/verify, T-043 PEM).

use pactmesh::trust::network_state::{
    MemberCertIndexEntry, NetworkStatePayload, NetworkStateVerifyError, PeerHint,
    SignedNetworkState, UnsignedNetworkState,
};
use pactmesh::trust::revocation::{DisabledCert, RevocationReason, RevokedCert};
use pactmesh::trust::{
    MemberCertFingerprint, NetworkLocalId, TrustDomainRoot, from_cbor, to_canonical_cbor,
};

#[derive(minicbor::Encode)]
struct LegacyNetworkStatePayload {
    #[n(0)]
    member_cert_index: Vec<MemberCertIndexEntry>,
    #[n(1)]
    revoked_certs: Vec<pactmesh::trust::RevokedCert>,
    #[n(2)]
    disabled_certs: Vec<pactmesh::trust::DisabledCert>,
    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    acl: Vec<u8>,
    #[n(4)]
    #[cbor(with = "minicbor::bytes")]
    routes: Vec<u8>,
}

fn fingerprint(byte: u8) -> MemberCertFingerprint {
    MemberCertFingerprint([byte; 32])
}

fn sample_payload() -> NetworkStatePayload {
    NetworkStatePayload {
        member_cert_index: vec![
            MemberCertIndexEntry {
                fingerprint: fingerprint(1),
                device_label: "laptop-a".to_owned(),
                issued_at: 1_710_000_000,
                expires_at: 1_720_000_000,
            },
            MemberCertIndexEntry {
                fingerprint: fingerprint(2),
                device_label: "server-b".to_owned(),
                issued_at: 1_710_000_100,
                expires_at: 1_720_000_100,
            },
        ],
        revoked_certs: vec![RevokedCert {
            cert_fingerprint: fingerprint(3),
            revoked_at: 1_715_000_000,
            reason_code: RevocationReason::Removed,
            reason_note: Some("member left".to_owned()),
        }],
        disabled_certs: vec![DisabledCert {
            cert_fingerprint: fingerprint(4),
            disabled_at: 1_716_000_000,
            expected_until: Some(1_716_100_000),
            reason_note: Some("maintenance".to_owned()),
        }],
        acl: vec![0x01, 0x02, 0x03, 0x80],
        routes: vec![0xa1, 0x00, 0x01],
        peer_hints: Vec::new(),
    }
}

fn sample_peer_hint() -> PeerHint {
    PeerHint {
        url: "tcp://203.0.113.10:11010".to_owned(),
        label: Some("public-vps-a".to_owned()),
        capabilities: vec!["public-reachable".to_owned(), "relay-capable".to_owned()],
        updated_at: 1_717_000_000,
        expires_at: Some(1_725_000_000),
    }
}

fn sample_unsigned_network_state_for_root(root: &TrustDomainRoot) -> UnsignedNetworkState {
    UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str("office-net").unwrap(),
        version: 42,
        payload: sample_payload(),
    }
}

#[test]
fn test_payload_round_trip() {
    let payload = sample_payload();
    let encoded = to_canonical_cbor(&payload);
    let decoded: NetworkStatePayload = from_cbor(&encoded).unwrap();

    assert_eq!(decoded, payload);
    assert_eq!(to_canonical_cbor(&decoded), encoded);
}

#[test]
fn test_payload_empty_lists_ok() {
    let payload = NetworkStatePayload {
        member_cert_index: Vec::new(),
        revoked_certs: Vec::new(),
        disabled_certs: Vec::new(),
        acl: Vec::new(),
        routes: Vec::new(),
        peer_hints: Vec::new(),
    };

    let encoded = to_canonical_cbor(&payload);
    let decoded: NetworkStatePayload = from_cbor(&encoded).unwrap();

    assert_eq!(decoded, payload);
    assert!(decoded.member_cert_index.is_empty());
    assert!(decoded.revoked_certs.is_empty());
    assert!(decoded.disabled_certs.is_empty());
}

#[test]
fn test_network_state_payload_round_trip() {
    test_payload_round_trip();
}

#[test]
fn test_network_state_payload_empty_lists_ok() {
    test_payload_empty_lists_ok();
}

#[test]
fn test_peer_hints_round_trip_cbor() {
    let mut payload = sample_payload();
    payload.peer_hints = vec![sample_peer_hint()];

    let encoded = to_canonical_cbor(&payload);
    let decoded: NetworkStatePayload = from_cbor(&encoded).unwrap();

    assert_eq!(decoded.peer_hints, payload.peer_hints);
    assert_eq!(decoded.peer_hints[0].url, "tcp://203.0.113.10:11010");
}

#[test]
fn test_peer_hints_covered_by_signature() {
    let root = TrustDomainRoot::generate();
    let mut state = sample_unsigned_network_state_for_root(&root).sign(&root);
    state.details.payload.peer_hints.push(sample_peer_hint());

    assert_eq!(
        state.verify(&root.public_key().into()),
        Err(NetworkStateVerifyError::BadSignature)
    );
}

#[test]
fn test_decode_legacy_payload_without_peer_hints_yields_empty_vec() {
    let legacy = LegacyNetworkStatePayload {
        member_cert_index: sample_payload().member_cert_index,
        revoked_certs: Vec::new(),
        disabled_certs: Vec::new(),
        acl: Vec::new(),
        routes: Vec::new(),
    };
    let decoded: NetworkStatePayload = from_cbor(&to_canonical_cbor(&legacy)).unwrap();

    assert!(decoded.peer_hints.is_empty());
}

#[test]
fn test_sign_verify_happy_path() {
    let root = TrustDomainRoot::generate();
    let state = sample_unsigned_network_state_for_root(&root).sign(&root);

    assert_eq!(state.verify(&root.public_key().into()), Ok(()));
}

#[test]
fn test_verify_wrong_root_rejected() {
    let root = TrustDomainRoot::generate();
    let wrong_root = TrustDomainRoot::generate();
    let state = sample_unsigned_network_state_for_root(&root).sign(&root);

    assert_eq!(
        state.verify(&wrong_root.public_key().into()),
        Err(NetworkStateVerifyError::DomainMismatch)
    );
}

#[test]
fn test_marshal_deterministic() {
    let root = TrustDomainRoot::generate();
    let state = sample_unsigned_network_state_for_root(&root);

    let left = state.marshal_for_signing();
    let right = state.marshal_for_signing();

    assert_eq!(left, right);
    assert_eq!(left, to_canonical_cbor(&state));
}

#[test]
fn test_network_state_sign_verify_happy_path() {
    test_sign_verify_happy_path();
}

#[test]
fn test_network_state_sign_verify_wrong_root_rejected() {
    test_verify_wrong_root_rejected();
}

#[test]
fn test_network_state_sign_marshal_deterministic() {
    test_marshal_deterministic();
}

#[test]
fn test_pem_round_trip() {
    let root = TrustDomainRoot::generate();
    let original = sample_unsigned_network_state_for_root(&root).sign(&root);

    let pem = original.to_pem();
    let decoded = SignedNetworkState::from_pem(&pem).unwrap();

    assert_eq!(decoded, original);
    assert_eq!(decoded.details, original.details);
    assert_eq!(decoded.signature, original.signature);
}
