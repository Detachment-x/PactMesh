use std::{path::Path, process::Command};

use base64::Engine as _;
use easytier::{
    common::trust_context::TrustDomainContext,
    trust::{MemberCert, SignedNetworkState, TrustDomainRoot, unwrap_armored},
};
use serde_json::Value;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_easytier-cli"))
}

fn config_home(root: &Path) -> std::path::PathBuf {
    root.join("xdg")
}

fn trust_domains_dir(root: &Path) -> std::path::PathBuf {
    config_home(root).join("privateNetwork/trust-domains")
}

fn create_domain(root: &Path) -> String {
    let output = cli()
        .env("XDG_CONFIG_HOME", config_home(root))
        .env("PNW_ROOT_PASSPHRASE", "long-enough-pass")
        .arg("trust")
        .arg("create-domain")
        .arg("--label")
        .arg("home")
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    value["trust_domain_id"].as_str().unwrap().to_owned()
}

fn create_network(root: &Path, domain_id: &str) {
    let output = cli()
        .env("XDG_CONFIG_HOME", config_home(root))
        .env("PNW_ROOT_PASSPHRASE", "long-enough-pass")
        .arg("trust")
        .arg("create-network")
        .arg(domain_id)
        .arg("office-net")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_bootstrap_self(root: &Path, domain_id: &str, extra: &[&str]) -> std::process::Output {
    let mut cmd = cli();
    cmd.env("XDG_CONFIG_HOME", config_home(root))
        .env("PNW_ROOT_PASSPHRASE", "long-enough-pass")
        .env("PNW_DEVICE_PASSPHRASE", "device-passphrase")
        .arg("trust")
        .arg("bootstrap-self")
        .arg(domain_id)
        .arg("office-net")
        .arg("--device-label")
        .arg("root-a");
    for arg in extra {
        cmd.arg(arg);
    }
    cmd.output().unwrap()
}

fn read_state(root: &Path, domain_id: &str) -> SignedNetworkState {
    let pem = std::fs::read_to_string(
        trust_domains_dir(root)
            .join(domain_id)
            .join("networks/office-net/network_state.cbor.pem"),
    )
    .unwrap();
    SignedNetworkState::from_pem(&pem).unwrap()
}

fn read_member_cert(root: &Path, domain_id: &str) -> MemberCert {
    let pem = std::fs::read_to_string(
        trust_domains_dir(root)
            .join(domain_id)
            .join("networks/office-net/member_cert.pem"),
    )
    .unwrap();
    MemberCert::from_pem(&pem).unwrap()
}

#[test]
fn test_bootstrap_self_writes_member_cert_and_updates_network_state() {
    let dir = tempfile::tempdir().unwrap();
    let domain_id = create_domain(dir.path());
    create_network(dir.path(), &domain_id);

    let output = run_bootstrap_self(dir.path(), &domain_id, &["--json"]);

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["old_version"], 1);
    assert_eq!(json["new_version"], 2);
    assert_eq!(json["wrote_cert"], true);

    let domain_dir = trust_domains_dir(dir.path()).join(&domain_id);
    let cert = read_member_cert(dir.path(), &domain_id);
    assert_eq!(cert.details.device_label, "root-a");
    assert_eq!(cert.details.network_state_version_ref, 2);
    assert!(domain_dir.join("networks/office-net/device_id").is_file());
    assert!(domain_dir.join("networks/office-net/sk_self.age").is_file());
    assert!(config_home(dir.path()).join("privateNetwork/devices/default/sk_self.age").is_file());
    let root = TrustDomainRoot::load_from_file(&domain_dir.join("sk_root.age"), "long-enough-pass").unwrap();
    cert.verify(&root.public_key()).unwrap();

    let state = read_state(dir.path(), &domain_id);
    assert_eq!(state.details.version, 2);
    assert_eq!(state.details.payload.member_cert_index.len(), 1);
    assert_eq!(state.details.payload.member_cert_index[0].fingerprint, cert.fingerprint());

    let ctx = TrustDomainContext::load_from_dir(&domain_dir, "office-net", "device-passphrase").unwrap();
    assert_eq!(ctx.member_cert.fingerprint(), cert.fingerprint());
}

#[test]
fn test_bootstrap_self_is_idempotent_for_same_device_key() {
    let dir = tempfile::tempdir().unwrap();
    let domain_id = create_domain(dir.path());
    create_network(dir.path(), &domain_id);
    let first = run_bootstrap_self(dir.path(), &domain_id, &["--json"]);
    assert!(first.status.success(), "stderr={}", String::from_utf8_lossy(&first.stderr));
    let cert = read_member_cert(dir.path(), &domain_id);

    let second = run_bootstrap_self(dir.path(), &domain_id, &["--json"]);

    assert!(
        second.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&second.stderr)
    );
    let json: Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(json["old_version"], 2);
    assert_eq!(json["new_version"], 2);
    assert_eq!(json["wrote_cert"], false);
    assert_eq!(read_member_cert(dir.path(), &domain_id).fingerprint(), cert.fingerprint());
    assert_eq!(read_state(dir.path(), &domain_id).details.payload.member_cert_index.len(), 1);
}

#[test]
fn test_bootstrap_self_rejects_existing_cert_for_different_device_key() {
    let dir = tempfile::tempdir().unwrap();
    let domain_id = create_domain(dir.path());
    create_network(dir.path(), &domain_id);
    let first = run_bootstrap_self(dir.path(), &domain_id, &[]);
    assert!(first.status.success(), "stderr={}", String::from_utf8_lossy(&first.stderr));
    let old_device_dir = config_home(dir.path()).join("privateNetwork/devices/default");
    std::fs::remove_file(old_device_dir.join("sk_self.age")).unwrap();
    std::fs::remove_file(old_device_dir.join("pk_self.pem")).unwrap();

    let second = run_bootstrap_self(dir.path(), &domain_id, &[]);

    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("different device key"));
}

#[test]
fn test_bootstrap_self_rejects_wrong_root_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let domain_id = create_domain(dir.path());
    create_network(dir.path(), &domain_id);

    let output = cli()
        .env("XDG_CONFIG_HOME", config_home(dir.path()))
        .env("PNW_ROOT_PASSPHRASE", "wrong-passphrase")
        .env("PNW_DEVICE_PASSPHRASE", "device-passphrase")
        .arg("trust")
        .arg("bootstrap-self")
        .arg(&domain_id)
        .arg("office-net")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("failed to unlock"));
}

#[test]
fn test_bootstrap_self_rejects_mismatched_existing_cert_domain() {
    let dir = tempfile::tempdir().unwrap();
    let domain_id = create_domain(dir.path());
    create_network(dir.path(), &domain_id);
    let other_root = TrustDomainRoot::generate();
    let other_cert = easytier::trust::UnsignedMemberCert {
        trust_domain_id: other_root.id(),
        network_local_id: easytier::trust::NetworkLocalId::try_from_str("office-net").unwrap(),
        device_pk: other_root.public_key(),
        device_label: "other".to_owned(),
        not_before: 1,
        expires_at: 100,
        capabilities: easytier::trust::Capabilities {
            can_relay_data: true,
            can_relay_control: true,
            can_proxy_subnet: Vec::new(),
        },
        network_state_version_ref: 1,
        hostname: None,
    }
    .sign(&other_root);
    let cert_path = trust_domains_dir(dir.path())
        .join(&domain_id)
        .join("networks/office-net/member_cert.pem");
    std::fs::write(&cert_path, other_cert.to_pem()).unwrap();

    let output = run_bootstrap_self(dir.path(), &domain_id, &[]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("trust_domain_id does not match"));
}

#[test]
fn test_bootstrap_self_rejects_corrupt_existing_member_cert() {
    let dir = tempfile::tempdir().unwrap();
    let domain_id = create_domain(dir.path());
    create_network(dir.path(), &domain_id);
    let cert_path = trust_domains_dir(dir.path())
        .join(&domain_id)
        .join("networks/office-net/member_cert.pem");
    std::fs::write(&cert_path, easytier::trust::wrap_armored("PNW-MEMBER-CERT", b"not-cbor")).unwrap();

    let output = run_bootstrap_self(dir.path(), &domain_id, &[]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("failed to parse"));
}

#[test]
fn test_bootstrap_self_device_id_points_to_pk_self() {
    let dir = tempfile::tempdir().unwrap();
    let domain_id = create_domain(dir.path());
    create_network(dir.path(), &domain_id);

    let output = run_bootstrap_self(dir.path(), &domain_id, &[]);

    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let device_id = std::fs::read_to_string(
        trust_domains_dir(dir.path())
            .join(&domain_id)
            .join("networks/office-net/device_id"),
    )
    .unwrap();
    let device_id = device_id.trim();
    let pk_pem = std::fs::read_to_string(config_home(dir.path()).join("privateNetwork/devices/default/pk_self.pem")).unwrap();
    let pk = unwrap_armored(&pk_pem, "PNW-PK-SELF").unwrap();
    assert_eq!(
        device_id,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk)
    );
}
