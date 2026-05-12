use easytier::trust::join::{JoinRequest, JoinVerifyError};
use easytier::trust::{NetworkLocalId, SignKey, TrustDomainId, from_cbor, to_canonical_cbor};

fn sample_sign_key(seed: u8) -> SignKey {
    SignKey::from_bytes([seed; 32])
}

fn sample_ids() -> (TrustDomainId, NetworkLocalId) {
    let sk = sample_sign_key(7);
    (
        TrustDomainId::from_root_pubkey(
            &ed25519_dalek::VerifyingKey::from_bytes(&sk.verify_key().0).unwrap(),
        ),
        NetworkLocalId::try_from_str("office-net").unwrap(),
    )
}

#[test]
fn test_join_request_round_trip_happy_path() {
    let applicant_sk = sample_sign_key(11);
    let (trust_domain_id, network_local_id) = sample_ids();
    let request = JoinRequest::new_signed(
        trust_domain_id,
        network_local_id,
        &applicant_sk,
        "laptop-a".to_owned(),
        "first device".to_owned(),
    );

    let encoded = to_canonical_cbor(&request);
    let decoded: JoinRequest = from_cbor(&encoded).unwrap();

    assert_eq!(decoded, request);
    assert_eq!(decoded.verify_self_signature(), Ok(()));
    assert_eq!(decoded.nonce.len(), 16);
}

#[test]
fn test_join_request_tampered_field_rejected() {
    let applicant_sk = sample_sign_key(12);
    let (trust_domain_id, network_local_id) = sample_ids();
    let mut request = JoinRequest::new_signed(
        trust_domain_id,
        network_local_id,
        &applicant_sk,
        "laptop-a".to_owned(),
        "first device".to_owned(),
    );
    request.device_label.push_str("-tampered");

    assert_eq!(
        request.verify_self_signature(),
        Err(JoinVerifyError::BadSignature)
    );
}

#[test]
fn test_join_request_wrong_applicant_pk_rejected() {
    let applicant_sk = sample_sign_key(13);
    let (trust_domain_id, network_local_id) = sample_ids();
    let mut request = JoinRequest::new_signed(
        trust_domain_id,
        network_local_id,
        &applicant_sk,
        "laptop-a".to_owned(),
        "first device".to_owned(),
    );
    request.applicant_pk = sample_sign_key(99).verify_key();

    assert_eq!(
        request.verify_self_signature(),
        Err(JoinVerifyError::BadSignature)
    );
}

#[test]
fn test_sign_key_round_trip_bytes() {
    let original = SignKey::generate();
    let restored = SignKey::from_bytes(original.to_bytes());
    let msg = b"join-request-sign-key";

    assert_eq!(restored.to_bytes(), original.to_bytes());
    assert_eq!(restored.sign(msg), original.sign(msg));
    assert_eq!(restored.verify_key(), original.verify_key());
}
