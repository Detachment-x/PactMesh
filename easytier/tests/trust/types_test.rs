use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use easytier::trust::{MemberCertFingerprint, NetworkLocalId, NetworkLocalIdError, TrustDomainId};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

fn fixture_pubkey(seed: u8) -> ed25519_dalek::VerifyingKey {
    SigningKey::from_bytes(&[seed; 32]).verifying_key()
}

#[test]
fn test_trust_domain_id_deterministic() {
    let pk = fixture_pubkey(7);

    assert_eq!(
        TrustDomainId::from_root_pubkey(&pk),
        TrustDomainId::from_root_pubkey(&pk)
    );
}

#[test]
fn test_trust_domain_id_display_base64() {
    let pk = fixture_pubkey(11);
    let id = TrustDomainId::from_root_pubkey(&pk);
    let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(pk.as_bytes()));

    assert_eq!(id.to_base64(), expected);
    assert_eq!(id.to_string(), expected);
}

#[test]
fn test_member_cert_fingerprint_deterministic() {
    let cert_bytes = b"member-cert-fixture";

    assert_eq!(
        MemberCertFingerprint::from_cert_bytes(cert_bytes),
        MemberCertFingerprint::from_cert_bytes(cert_bytes)
    );
}

#[test]
fn test_member_cert_fingerprint_display() {
    let cert_bytes = b"member-cert-display";
    let fingerprint = MemberCertFingerprint::from_cert_bytes(cert_bytes);
    let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(cert_bytes));

    assert_eq!(fingerprint.to_base64(), expected);
    assert_eq!(fingerprint.to_string(), expected);
}

#[test]
fn test_network_local_id_valid_inputs() {
    for input in ["home", "office-1", "a", "z9-0", &"n".repeat(63)] {
        let network_id = NetworkLocalId::try_from_str(input).unwrap();
        assert_eq!(network_id.as_str(), input);
        assert_eq!(network_id.to_string(), input);
    }
}

#[test]
fn test_network_local_id_invalid_inputs() {
    assert_eq!(
        NetworkLocalId::try_from_str(""),
        Err(NetworkLocalIdError::Length(0))
    );
    assert_eq!(
        NetworkLocalId::try_from_str(&"x".repeat(64)),
        Err(NetworkLocalIdError::Length(64))
    );
    assert_eq!(
        NetworkLocalId::try_from_str("-home"),
        Err(NetworkLocalIdError::EdgeHyphen)
    );
    assert_eq!(
        NetworkLocalId::try_from_str("home-"),
        Err(NetworkLocalIdError::EdgeHyphen)
    );
    assert_eq!(
        NetworkLocalId::try_from_str("Home"),
        Err(NetworkLocalIdError::Charset(b'H'))
    );
    assert_eq!(
        NetworkLocalId::try_from_str("home_1"),
        Err(NetworkLocalIdError::Charset(b'_'))
    );
    assert_eq!(
        NetworkLocalId::try_from_str("中"),
        Err(NetworkLocalIdError::Charset(0xe4))
    );
}
