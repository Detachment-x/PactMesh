//! Tests for `trust::identity` (T-020 generate, T-021 seal/unseal, T-022 save/load).

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use easytier::trust::TrustDomainRoot;
use easytier::trust::identity::{SignatureError, UnsealError, VerifyKey, verify_signature};
use easytier::trust::types::TrustDomainId;

#[test]
fn test_root_generate_unique_each_call() {
    let left = TrustDomainRoot::generate();
    let right = TrustDomainRoot::generate();

    assert_ne!(left.id(), right.id());
    assert_ne!(left.public_key().to_bytes(), right.public_key().to_bytes());
}

#[test]
fn test_root_id_matches_pubkey_hash() {
    let root = TrustDomainRoot::generate();
    let pk = root.public_key();

    assert_eq!(root.id(), TrustDomainId::from_root_pubkey(&pk));
}

#[test]
fn test_root_signs_verifiable() {
    let root = TrustDomainRoot::generate();
    let pk = VerifyKey::from(root.public_key());
    let msg = b"trust-root-signature-fixture";
    let sig = root.sign(msg);

    assert_eq!(verify_signature(&pk, msg, &sig), Ok(()));
    assert_eq!(
        verify_signature(&pk, b"tampered", &sig),
        Err(SignatureError::Invalid)
    );
}

#[test]
fn test_seal_unseal_round_trip() {
    let root = TrustDomainRoot::generate();
    let sealed = root.seal("secret-passphrase").unwrap();
    let unsealed = TrustDomainRoot::unseal(&sealed, "secret-passphrase").unwrap();

    assert_eq!(unsealed.id(), root.id());
    assert_eq!(
        unsealed.public_key().to_bytes(),
        root.public_key().to_bytes()
    );
}

#[test]
fn test_unseal_wrong_password_rejected() {
    let root = TrustDomainRoot::generate();
    let sealed = root.seal("secret-passphrase").unwrap();
    let err = TrustDomainRoot::unseal(&sealed, "wrong-passphrase").unwrap_err();

    assert!(matches!(err, UnsealError::BadPassword));
}

#[test]
fn test_unseal_corrupted_blob_rejected() {
    let root = TrustDomainRoot::generate();
    let mut sealed = root.seal("secret-passphrase").unwrap();
    let last = sealed.len() - 1;
    sealed[last] ^= 0x01;
    let err = TrustDomainRoot::unseal(&sealed, "secret-passphrase").unwrap_err();

    assert!(matches!(err, UnsealError::BadPassword));
}

#[test]
fn test_save_load_round_trip() {
    let root = TrustDomainRoot::generate();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("root.age");

    root.save_to_file(&path, "secret-passphrase").unwrap();
    let loaded = TrustDomainRoot::load_from_file(&path, "secret-passphrase").unwrap();

    assert_eq!(loaded.id(), root.id());
    assert_eq!(loaded.public_key().to_bytes(), root.public_key().to_bytes());
}

#[cfg(unix)]
#[test]
fn test_save_creates_0600_unix() {
    let root = TrustDomainRoot::generate();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("root.age");

    root.save_to_file(&path, "secret-passphrase").unwrap();

    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}
