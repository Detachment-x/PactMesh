use std::{path::Path, process::Command};

use easytier::trust::network_bootstrap::NetworkBootstrap;
use serde_json::Value;
use url::Url;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_easytier-cli"))
}

fn config_home(root: &Path) -> std::path::PathBuf {
    root.join("xdg")
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
    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
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
    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
}

fn setup_domain_with_network(root: &Path) -> String {
    let domain_id = create_domain(root);
    create_network(root, &domain_id);
    domain_id
}

fn invite_cmd(root: &Path, domain_id: &str) -> Command {
    let mut cmd = cli();
    cmd.env("XDG_CONFIG_HOME", config_home(root))
        .arg("trust")
        .arg("invite")
        .arg(domain_id)
        .arg("office-net");
    cmd
}

#[test]
fn test_invite_url_format() {
    let dir = tempfile::tempdir().unwrap();
    let domain_id = setup_domain_with_network(dir.path());

    let output = invite_cmd(dir.path(), &domain_id)
        .arg("--seed")
        .arg("tcp://203.0.113.10:11010")
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let url = Url::parse(stdout.trim()).unwrap();
    let bootstrap = NetworkBootstrap::from_url(&url).unwrap();
    assert_eq!(bootstrap.trust_domain_id.to_string(), domain_id);
    assert_eq!(bootstrap.network_local_id.to_string(), "office-net");
    assert_eq!(bootstrap.bootstrap_seeds.len(), 1);
}

#[test]
fn test_invite_qr_format_svg() {
    let dir = tempfile::tempdir().unwrap();
    let domain_id = setup_domain_with_network(dir.path());

    let output = invite_cmd(dir.path(), &domain_id)
        .arg("--seed")
        .arg("tcp://203.0.113.10:11010")
        .arg("--format")
        .arg("qr")
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("<svg"));
    assert!(stdout.contains("path"));
}

#[test]
fn test_invite_file_format_pem() {
    let dir = tempfile::tempdir().unwrap();
    let domain_id = setup_domain_with_network(dir.path());
    let out = dir.path().join("invite.pem");

    let output = invite_cmd(dir.path(), &domain_id)
        .arg("--seed")
        .arg("tcp://203.0.113.10:11010")
        .arg("--format")
        .arg("file")
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let pem = std::fs::read_to_string(out).unwrap();
    assert!(pem.contains("BEGIN PNW-NETWORK-BOOTSTRAP"));
    let bootstrap = NetworkBootstrap::from_pem(&pem).unwrap();
    assert_eq!(bootstrap.trust_domain_id.to_string(), domain_id);
}

#[test]
fn test_invite_no_seed_rejected_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let domain_id = setup_domain_with_network(dir.path());

    let output = invite_cmd(dir.path(), &domain_id).output().unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("at least one --seed is required"));
}

#[test]
fn test_invite_multiple_seeds_encoded() {
    let dir = tempfile::tempdir().unwrap();
    let domain_id = setup_domain_with_network(dir.path());

    let output = invite_cmd(dir.path(), &domain_id)
        .arg("--seed")
        .arg("tcp://203.0.113.10:11010")
        .arg("--seed")
        .arg("udp://198.51.100.2:22020")
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let url = Url::parse(stdout.trim()).unwrap();
    let bootstrap = NetworkBootstrap::from_url(&url).unwrap();
    assert_eq!(bootstrap.bootstrap_seeds.len(), 2);
    assert_eq!(bootstrap.bootstrap_seeds[0].as_str(), "tcp://203.0.113.10:11010");
    assert_eq!(bootstrap.bootstrap_seeds[1].as_str(), "udp://198.51.100.2:22020");
}
