use pactmesh::trust::{
    AdminCapabilities, AdminGrantVerifyError, SignKey, TrustDomainRoot, UnsignedAdminGrant,
    VerifyKey, sign_admin_operation,
};

fn sample_grant(root: &TrustDomainRoot, admin_sk: &SignKey) -> UnsignedAdminGrant {
    UnsignedAdminGrant {
        trust_domain_id: root.id(),
        admin_device_pk: ed25519_dalek::VerifyingKey::from_bytes(&admin_sk.verify_key().0).unwrap(),
        admin_label: "ops-laptop".to_owned(),
        not_before: 100,
        expires_at: 200,
        capabilities: AdminCapabilities::approve_only(),
    }
}

#[test]
fn admin_grant_verify_happy_path_and_pem_roundtrip() {
    let root = TrustDomainRoot::generate();
    let admin_sk = SignKey::generate();
    let grant = sample_grant(&root, &admin_sk).sign(&root);

    grant
        .verify(&VerifyKey::from(root.public_key()), 150)
        .unwrap();
    assert!(grant.details.capabilities.approve_join);
    assert!(!grant.details.capabilities.revoke_member);

    let decoded = pactmesh::trust::AdminGrant::from_pem(&grant.to_pem()).unwrap();
    assert_eq!(decoded, grant);
}

#[test]
fn admin_grant_rejects_wrong_root_and_time() {
    let root = TrustDomainRoot::generate();
    let other = TrustDomainRoot::generate();
    let admin_sk = SignKey::generate();
    let grant = sample_grant(&root, &admin_sk).sign(&root);

    assert_eq!(
        grant
            .verify(&VerifyKey::from(other.public_key()), 150)
            .unwrap_err(),
        AdminGrantVerifyError::DomainMismatch
    );
    assert_eq!(
        grant
            .verify(&VerifyKey::from(root.public_key()), 250)
            .unwrap_err(),
        AdminGrantVerifyError::NotCurrentlyValid
    );
}

#[test]
fn admin_operation_signature_uses_admin_device_key() {
    let root = TrustDomainRoot::generate();
    let admin_sk = SignKey::generate();
    let other_sk = SignKey::generate();
    let grant = sample_grant(&root, &admin_sk).sign(&root);
    let message = b"approve join request fingerprint abc";

    let signature = sign_admin_operation(&admin_sk, message);
    grant.verify_admin_signature(message, &signature).unwrap();

    let wrong_signature = sign_admin_operation(&other_sk, message);
    assert_eq!(
        grant
            .verify_admin_signature(message, &wrong_signature)
            .unwrap_err(),
        AdminGrantVerifyError::BadAdminSignature
    );
}
