use std::io::Write;
use std::iter;
use std::path::Path;
use std::sync::Arc;

use age::secrecy::SecretString;
use age::{Encryptor, scrypt};
use easytier::common::config::TomlConfigLoader;
use easytier::common::global_ctx::GlobalCtx;
use easytier::common::trust_context::{LoadError, TrustDomainContext};
use easytier::trust::{
    Capabilities, MemberCert, SignKey, TrustDomainRoot, UnsignedMemberCert, wrap_armored,
};
use ed25519_dalek::VerifyingKey;

fn sample_unsigned_member_cert(
    root: &TrustDomainRoot,
    sk_self: &SignKey,
    network_local_id: &str,
) -> UnsignedMemberCert {
    let verify_key = sk_self.verify_key();
    let device_pk = VerifyingKey::from_bytes(&verify_key.0).unwrap();

    UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: network_local_id.parse().unwrap(),
        device_pk,
        device_label: "device-a".to_owned(),
        not_before: 1_715_000_000,
        expires_at: 1_716_000_000,
        capabilities: Capabilities {
            can_relay_data: false,
            can_relay_control: false,
            can_proxy_subnet: Vec::new(),
        },
        network_state_version_ref: 0,
        hostname: None,
    }
}

fn seal_sign_key(sk_self: &SignKey, password: &str) -> Vec<u8> {
    let mut recipient = scrypt::Recipient::new(SecretString::from(password.to_owned()));
    recipient.set_work_factor(2);

    let encryptor = Encryptor::with_recipients(iter::once(&recipient as &dyn age::Recipient))
        .expect("single scrypt recipient is valid");
    let mut encrypted = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
    writer.write_all(&sk_self.to_bytes()).unwrap();
    writer.finish().unwrap();
    encrypted
}

fn write_domain_files(
    domain_dir: &Path,
    network_local_id: &str,
    root: &TrustDomainRoot,
    cert: &MemberCert,
    sk_self: &SignKey,
    password: &str,
) {
    let network_dir = domain_dir.join("networks").join(network_local_id);
    std::fs::create_dir_all(&network_dir).unwrap();
    std::fs::write(
        domain_dir.join("pk_root.pem"),
        wrap_armored("PNW-PK-ROOT", root.public_key().as_bytes()),
    )
    .unwrap();
    std::fs::write(network_dir.join("member_cert.pem"), cert.to_pem()).unwrap();
    std::fs::write(
        network_dir.join("sk_self.age"),
        seal_sign_key(sk_self, password),
    )
    .unwrap();
}

fn sample_context_parts() -> (TrustDomainRoot, String, MemberCert, SignKey) {
    let root = TrustDomainRoot::generate();
    let sk_self = SignKey::generate();
    let network_local_id = "office-net".to_owned();
    let cert = sample_unsigned_member_cert(&root, &sk_self, &network_local_id).sign(&root);
    (root, network_local_id, cert, sk_self)
}

#[test]
fn test_new_constructs() {
    let (root, network_local_id, cert, sk_self) = sample_context_parts();

    let ctx = TrustDomainContext::new(
        root.id(),
        network_local_id.parse().unwrap(),
        cert.clone(),
        sk_self.clone(),
    );

    assert_eq!(ctx.trust_domain_id, root.id());
    assert_eq!(ctx.network_local_id.as_str(), network_local_id);
    assert_eq!(ctx.member_cert, cert);
    assert_eq!(ctx.sk_self.to_bytes(), sk_self.to_bytes());
}

#[test]
fn test_fingerprint_delegates_to_member_cert() {
    let (root, network_local_id, cert, sk_self) = sample_context_parts();
    let ctx = TrustDomainContext::new(
        root.id(),
        network_local_id.parse().unwrap(),
        cert.clone(),
        sk_self,
    );

    assert_eq!(ctx.fingerprint(), cert.fingerprint());
}

#[test]
fn test_load_from_dir_reads_pem_files() {
    let dir = tempfile::tempdir().unwrap();
    let (root, network_local_id, cert, sk_self) = sample_context_parts();
    write_domain_files(
        dir.path(),
        &network_local_id,
        &root,
        &cert,
        &sk_self,
        "correct-pass",
    );

    let ctx =
        TrustDomainContext::load_from_dir(dir.path(), &network_local_id, "correct-pass").unwrap();

    assert_eq!(ctx.trust_domain_id, root.id());
    assert_eq!(ctx.network_local_id.as_str(), network_local_id);
    assert_eq!(ctx.member_cert, cert);
    assert_eq!(ctx.sk_self.to_bytes(), sk_self.to_bytes());
}

#[test]
fn test_load_from_dir_missing_member_cert_fails() {
    let dir = tempfile::tempdir().unwrap();
    let (root, network_local_id, _cert, sk_self) = sample_context_parts();
    let network_dir = dir.path().join("networks").join(&network_local_id);
    std::fs::create_dir_all(&network_dir).unwrap();
    std::fs::write(
        dir.path().join("pk_root.pem"),
        wrap_armored("PNW-PK-ROOT", root.public_key().as_bytes()),
    )
    .unwrap();
    std::fs::write(
        network_dir.join("sk_self.age"),
        seal_sign_key(&sk_self, "correct-pass"),
    )
    .unwrap();

    let err = TrustDomainContext::load_from_dir(dir.path(), &network_local_id, "correct-pass")
        .unwrap_err();

    assert!(matches!(err, LoadError::Io(_)));
}

#[test]
fn test_load_from_dir_wrong_sk_self_password_fails() {
    let dir = tempfile::tempdir().unwrap();
    let (root, network_local_id, cert, sk_self) = sample_context_parts();
    write_domain_files(
        dir.path(),
        &network_local_id,
        &root,
        &cert,
        &sk_self,
        "correct-pass",
    );

    let err =
        TrustDomainContext::load_from_dir(dir.path(), &network_local_id, "wrong-pass").unwrap_err();

    assert!(matches!(err, LoadError::SkSelfDecryptFailed));
}

#[tokio::test]
async fn test_global_ctx_set_get_round_trip() {
    let global_ctx = GlobalCtx::new(TomlConfigLoader::default());
    assert!(global_ctx.get_trust_context().await.is_none());

    let (root, network_local_id, cert, sk_self) = sample_context_parts();
    let trust_context = Arc::new(TrustDomainContext::new(
        root.id(),
        network_local_id.parse().unwrap(),
        cert,
        sk_self,
    ));
    global_ctx.set_trust_context(trust_context.clone()).await;

    let loaded = global_ctx.get_trust_context().await.unwrap();
    assert!(Arc::ptr_eq(&loaded, &trust_context));
    assert_eq!(loaded.fingerprint(), trust_context.fingerprint());
}
