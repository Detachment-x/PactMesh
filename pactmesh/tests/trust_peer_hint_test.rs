use std::{path::Path, process::Command};

use pactmesh::trust::{SignedNetworkState, TrustDomainRoot};
use serde_json::Value;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pactmesh"))
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
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn read_state(root: &Path, domain_id: &str) -> SignedNetworkState {
    let pem = std::fs::read_to_string(
        trust_domains_dir(root)
            .join(domain_id)
            .join("networks")
            .join("office-net")
            .join("network_state.cbor.pem"),
    )
    .unwrap();
    SignedNetworkState::from_pem(&pem).unwrap()
}

fn run_peer_hint(root: &Path, args: &[&str]) -> std::process::Output {
    let mut cmd = cli();
    cmd.env("XDG_CONFIG_HOME", config_home(root))
        .env("PNW_ROOT_PASSPHRASE", "long-enough-pass")
        .arg("trust")
        .arg("peer-hint");
    for arg in args {
        cmd.arg(arg);
    }
    cmd.output().unwrap()
}

#[test]
fn test_peer_hint_add_list_remove_json() {
    let dir = tempfile::tempdir().unwrap();
    let domain_id = create_domain(dir.path());
    create_network(dir.path(), &domain_id);

    let add = run_peer_hint(
        dir.path(),
        &[
            "add",
            &domain_id,
            "office-net",
            "tcp://203.0.113.10:11010",
            "--label",
            "public-a",
            "--capability",
            "relay-capable",
            "--capability",
            "public-reachable",
            "--expires-at",
            "2000000000",
            "--json",
        ],
    );
    assert!(
        add.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&add.stderr)
    );
    let added: Value = serde_json::from_slice(&add.stdout).unwrap();
    assert_eq!(added["status"], "peer-hint-added");
    assert_eq!(added["old_version"], 1);
    assert_eq!(added["new_version"], 2);

    let list = run_peer_hint(dir.path(), &["list", &domain_id, "office-net", "--json"]);
    assert!(list.status.success());
    let rows: Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["url"], "tcp://203.0.113.10:11010");
    assert_eq!(rows[0]["label"], "public-a");
    assert_eq!(rows[0]["capabilities"][0], "public-reachable");
    assert_eq!(rows[0]["capabilities"][1], "relay-capable");

    let state = read_state(dir.path(), &domain_id);
    let root = TrustDomainRoot::load_from_file(
        &trust_domains_dir(dir.path())
            .join(&domain_id)
            .join("sk_root.age"),
        "long-enough-pass",
    )
    .unwrap();
    assert_eq!(state.verify(&root.public_key().into()), Ok(()));
    assert_eq!(state.details.payload.peer_hints.len(), 1);

    let remove = run_peer_hint(
        dir.path(),
        &[
            "remove",
            &domain_id,
            "office-net",
            "tcp://203.0.113.10:11010",
            "--json",
        ],
    );
    assert!(remove.status.success());
    let removed: Value = serde_json::from_slice(&remove.stdout).unwrap();
    assert_eq!(removed["status"], "peer-hint-removed");

    let state = read_state(dir.path(), &domain_id);
    assert!(state.details.payload.peer_hints.is_empty());
}

#[test]
fn test_peer_hint_invalid_url_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let domain_id = create_domain(dir.path());
    create_network(dir.path(), &domain_id);

    let output = run_peer_hint(
        dir.path(),
        &["add", &domain_id, "office-net", "not-a-url", "--json"],
    );

    assert!(!output.status.success());
}

#[test]
fn test_list_members_does_not_render_peer_hints() {
    let dir = tempfile::tempdir().unwrap();
    let domain_id = create_domain(dir.path());
    create_network(dir.path(), &domain_id);
    let add = run_peer_hint(
        dir.path(),
        &["add", &domain_id, "office-net", "tcp://203.0.113.10:11010"],
    );
    assert!(add.status.success());

    let output = cli()
        .env("XDG_CONFIG_HOME", config_home(dir.path()))
        .arg("trust")
        .arg("list-members")
        .arg(&domain_id)
        .arg("office-net")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("203.0.113.10"));
}
