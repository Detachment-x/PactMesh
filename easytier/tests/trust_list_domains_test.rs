use std::{path::Path, process::Command};

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

fn write_domain(root: &Path, id: &str, label: &str, created_at: &str, root_holder: bool, networks: &[&str]) {
    let domain_dir = trust_domains_dir(root).join(id);
    std::fs::create_dir_all(&domain_dir).unwrap();
    std::fs::write(
        domain_dir.join("meta.toml"),
        format!("label = \"{label}\"\ncreated_at = \"{created_at}\"\ncurve = \"ed25519\"\n"),
    )
    .unwrap();
    if root_holder {
        std::fs::write(domain_dir.join("sk_root.age"), "encrypted-root").unwrap();
    }
    for network in networks {
        std::fs::create_dir_all(domain_dir.join("networks").join(network)).unwrap();
    }
}

fn run_list(root: &Path, json: bool) -> std::process::Output {
    let mut cmd = cli();
    cmd.env("XDG_CONFIG_HOME", config_home(root))
        .arg("trust")
        .arg("list-domains");
    if json {
        cmd.arg("--json");
    }
    cmd.output().unwrap()
}

#[test]
fn test_list_empty() {
    let dir = tempfile::tempdir().unwrap();
    let output = run_list(dir.path(), false);

    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("(no trust domains)"));
}

#[test]
fn test_list_one_domain_table_format() {
    let dir = tempfile::tempdir().unwrap();
    write_domain(dir.path(), "abcdef012345", "home", "123", true, &["lan"]);

    let output = run_list(dir.path(), false);
    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("trust_domain_id\tlabel\tcreated_at\tnetwork_count\tis_root_holder"));
    assert!(stdout.contains("abcdef01\thome\t123\t1\ttrue"));
}

#[test]
fn test_list_three_domains_with_networks() {
    let dir = tempfile::tempdir().unwrap();
    write_domain(dir.path(), "cccccccc0000", "gamma", "3", false, &["a", "b"]);
    write_domain(dir.path(), "aaaaaaaa0000", "alpha", "1", true, &[]);
    write_domain(dir.path(), "bbbbbbbb0000", "beta", "2", false, &["n1"]);

    let output = run_list(dir.path(), false);
    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("aaaaaaaa\talpha\t1\t0\ttrue"));
    assert!(stdout.contains("bbbbbbbb\tbeta\t2\t1\tfalse"));
    assert!(stdout.contains("cccccccc\tgamma\t3\t2\tfalse"));
}

#[test]
fn test_list_json_format() {
    let dir = tempfile::tempdir().unwrap();
    write_domain(dir.path(), "abcdef012345", "json", "42", true, &["n1", "n2"]);

    let output = run_list(dir.path(), true);
    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let rows = value.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["trust_domain_id"], "abcdef012345");
    assert_eq!(rows[0]["label"], "json");
    assert_eq!(rows[0]["created_at"], "42");
    assert_eq!(rows[0]["network_count"], 2);
    assert_eq!(rows[0]["is_root_holder"], true);
}
