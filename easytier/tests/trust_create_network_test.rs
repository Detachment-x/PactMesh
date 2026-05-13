use std::{path::Path, process::Command};

use easytier::trust::{AclPolicy, Action, SignedNetworkState, TrustDomainRoot, from_cbor};
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

fn create_domain(root: &Path, passphrase: &str) -> String {
    let output = cli()
        .env("XDG_CONFIG_HOME", config_home(root))
        .env("PNW_ROOT_PASSPHRASE", passphrase)
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

fn run_create_network(
    root: &Path,
    domain_id: &str,
    network_id: &str,
    passphrase: &str,
    default_action: &str,
    json: bool,
) -> std::process::Output {
    let mut cmd = cli();
    cmd.env("XDG_CONFIG_HOME", config_home(root))
        .env("PNW_ROOT_PASSPHRASE", passphrase)
        .arg("trust")
        .arg("create-network")
        .arg(domain_id)
        .arg(network_id)
        .arg("--default-action")
        .arg(default_action);
    if json {
        cmd.arg("--json");
    }
    cmd.output().unwrap()
}

fn read_state(root: &Path, domain_id: &str, network_id: &str) -> SignedNetworkState {
    let pem = std::fs::read_to_string(
        trust_domains_dir(root)
            .join(domain_id)
            .join("networks")
            .join(network_id)
            .join("network_state.cbor.pem"),
    )
    .unwrap();
    SignedNetworkState::from_pem(&pem).unwrap()
}

#[test]
fn test_create_network_basic() {
    let dir = tempfile::tempdir().unwrap();
    let domain_id = create_domain(dir.path(), "long-enough-pass");

    let output = run_create_network(
        dir.path(),
        &domain_id,
        "office-net",
        "long-enough-pass",
        "accept",
        false,
    );

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Created network office-net"));
    assert!(stdout.contains("version 1"));
    assert!(stdout.contains("default_action accept"));
}

#[test]
fn test_create_network_duplicate_rejects() {
    let dir = tempfile::tempdir().unwrap();
    let domain_id = create_domain(dir.path(), "long-enough-pass");
    let first = run_create_network(
        dir.path(),
        &domain_id,
        "office-net",
        "long-enough-pass",
        "accept",
        false,
    );
    assert!(first.status.success());

    let second = run_create_network(
        dir.path(),
        &domain_id,
        "office-net",
        "long-enough-pass",
        "accept",
        false,
    );

    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("network already exists"));
}

#[test]
fn test_create_network_unknown_domain_rejects() {
    let dir = tempfile::tempdir().unwrap();
    let output = run_create_network(
        dir.path(),
        "missing-domain",
        "office-net",
        "long-enough-pass",
        "accept",
        false,
    );

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("trust domain not found"));
}

#[test]
fn test_create_network_default_drop_respected() {
    let dir = tempfile::tempdir().unwrap();
    let domain_id = create_domain(dir.path(), "long-enough-pass");
    let output = run_create_network(
        dir.path(),
        &domain_id,
        "office-net",
        "long-enough-pass",
        "drop",
        false,
    );
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let state = read_state(dir.path(), &domain_id, "office-net");
    assert_eq!(state.details.version, 1);
    assert_eq!(state.details.payload.member_cert_index.len(), 0);
    let root = TrustDomainRoot::load_from_file(
        &trust_domains_dir(dir.path())
            .join(&domain_id)
            .join("sk_root.age"),
        "long-enough-pass",
    )
    .unwrap();
    assert_eq!(state.verify(&root.public_key().into()), Ok(()));
    let acl: AclPolicy = from_cbor(&state.details.payload.acl).unwrap();
    assert_eq!(acl.default_action, Action::Drop);
}

#[test]
fn test_create_network_json_output() {
    let dir = tempfile::tempdir().unwrap();
    let domain_id = create_domain(dir.path(), "long-enough-pass");

    let output = run_create_network(
        dir.path(),
        &domain_id,
        "office-net",
        "long-enough-pass",
        "accept",
        true,
    );

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["trust_domain_id"], domain_id);
    assert_eq!(value["network_local_id"], "office-net");
    assert_eq!(value["version"], 1);
    assert_eq!(value["default_action"], "accept");
    assert!(Path::new(value["path"].as_str().unwrap()).is_dir());
}

#[test]
fn test_create_network_passphrase_file_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let domain_id = create_domain(dir.path(), "long-enough-pass");
    let passphrase_dir = tempfile::tempdir().unwrap();
    let passphrase_file = passphrase_dir.path().join("management-passphrase.txt");
    std::fs::write(&passphrase_file, "long-enough-pass\n").unwrap();

    let output = cli()
        .env("XDG_CONFIG_HOME", config_home(dir.path()))
        .env_remove("PNW_ROOT_PASSPHRASE")
        .arg("trust")
        .arg("create-network")
        .arg(&domain_id)
        .arg("file-pass-net")
        .arg("--passphrase-file")
        .arg(&passphrase_file)
        .arg("--json")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["network_local_id"], "file-pass-net");
}

#[test]
fn test_create_network_missing_passphrase_non_tty_reports_management_password() {
    let dir = tempfile::tempdir().unwrap();
    let domain_id = create_domain(dir.path(), "long-enough-pass");

    let output = cli()
        .env("XDG_CONFIG_HOME", config_home(dir.path()))
        .env_remove("PNW_ROOT_PASSPHRASE")
        .arg("trust")
        .arg("create-network")
        .arg(&domain_id)
        .arg("missing-pass-net")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("management password"), "stderr={stderr}");
    assert!(stderr.contains("TTY"), "stderr={stderr}");
}
