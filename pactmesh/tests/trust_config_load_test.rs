use std::io::Write;
use std::iter;
use std::path::Path;

use age::secrecy::SecretString;
use age::{Encryptor, scrypt};
use ed25519_dalek::VerifyingKey;
use pactmesh::common::config::TomlConfigLoader;
use pactmesh::instance::instance::Instance;
use pactmesh::launcher::inject_trust_domain_context_from_config;
use pactmesh::trust::{
    Capabilities, MemberCert, SignKey, TrustDomainRoot, UnsignedMemberCert, wrap_armored,
};

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

fn trust_config_toml(domain_dir: &Path, network_local_id: &str, password_env: &str) -> String {
    format!(
        "[network_identity]\nnetwork_name = \"test-network\"\n\n[trust_domain]\ndomain_dir = \"{}\"\nnetwork_local_id = \"{}\"\nsk_self_password_env = \"{}\"\n",
        domain_dir.display(),
        network_local_id,
        password_env
    )
}

fn network_only_toml() -> &'static str {
    "[network_identity]\nnetwork_name = \"test-network\"\n"
}

#[tokio::test]
async fn test_load_config_with_valid_trust_domain_succeeds() {
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

    let env_name = format!("PNW_SK_SELF_PASSWORD_{}", std::process::id());
    // SAFETY: tests run in-process here and use unique env var names scoped to this test.
    unsafe { std::env::set_var(&env_name, "correct-pass") };

    let cfg = TomlConfigLoader::new_from_str(&trust_config_toml(
        dir.path(),
        &network_local_id,
        &env_name,
    ))
    .unwrap();
    let instance = Instance::new(cfg.clone());

    inject_trust_domain_context_from_config(&cfg, instance.get_global_ctx())
        .await
        .unwrap();

    let loaded = instance.get_global_ctx().get_trust_context().await.unwrap();
    assert_eq!(loaded.trust_domain_id, root.id());
    assert_eq!(loaded.network_local_id.as_str(), network_local_id);
    assert_eq!(loaded.member_cert, cert);
    assert_eq!(loaded.sk_self.to_bytes(), sk_self.to_bytes());

    // SAFETY: removes the test-scoped env var created above.
    unsafe { std::env::remove_var(env_name) };
}

#[tokio::test]
async fn test_load_config_without_trust_domain_section_starts_with_none() {
    let cfg = TomlConfigLoader::new_from_str(network_only_toml()).unwrap();
    let instance = Instance::new(cfg.clone());

    inject_trust_domain_context_from_config(&cfg, instance.get_global_ctx())
        .await
        .unwrap();

    assert!(
        instance
            .get_global_ctx()
            .get_trust_context()
            .await
            .is_none()
    );
}

#[tokio::test]
async fn test_load_config_with_missing_member_cert_file_fails() {
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

    let env_name = format!("PNW_SK_SELF_PASSWORD_MISSING_{}", std::process::id());
    // SAFETY: tests run in-process here and use unique env var names scoped to this test.
    unsafe { std::env::set_var(&env_name, "correct-pass") };

    let cfg = TomlConfigLoader::new_from_str(&trust_config_toml(
        dir.path(),
        &network_local_id,
        &env_name,
    ))
    .unwrap();
    let instance = Instance::new(cfg.clone());

    let err = inject_trust_domain_context_from_config(&cfg, instance.get_global_ctx())
        .await
        .unwrap_err();
    let err_str = format!("{err:#}");
    assert!(
        err_str.contains("member_cert.pem"),
        "unexpected error: {err_str}"
    );

    // SAFETY: removes the test-scoped env var created above.
    unsafe { std::env::remove_var(env_name) };
}

#[tokio::test]
async fn test_load_config_with_wrong_sk_self_password_fails() {
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

    let env_name = format!("PNW_SK_SELF_PASSWORD_WRONG_{}", std::process::id());
    // SAFETY: tests run in-process here and use unique env var names scoped to this test.
    unsafe { std::env::set_var(&env_name, "wrong-pass") };

    let cfg = TomlConfigLoader::new_from_str(&trust_config_toml(
        dir.path(),
        &network_local_id,
        &env_name,
    ))
    .unwrap();
    let instance = Instance::new(cfg.clone());

    let err = inject_trust_domain_context_from_config(&cfg, instance.get_global_ctx())
        .await
        .unwrap_err();
    let err_str = format!("{err:#}");
    assert!(
        err_str.contains("failed to decrypt sk_self.age"),
        "unexpected error: {err_str}"
    );

    // SAFETY: removes the test-scoped env var created above.
    unsafe { std::env::remove_var(env_name) };
}
