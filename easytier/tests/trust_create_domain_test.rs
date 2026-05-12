use std::{path::Path, process::Command};

use serde_json::Value;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_easytier-cli"))
}

fn run_create(out_dir: &Path, label: &str, passphrase: &str, json: bool) -> std::process::Output {
    let mut cmd = cli();
    cmd.env("PNW_ROOT_PASSPHRASE", passphrase)
        .arg("trust")
        .arg("create-domain")
        .arg("--label")
        .arg(label)
        .arg("--out-dir")
        .arg(out_dir);
    if json {
        cmd.arg("--json");
    }
    cmd.output().unwrap()
}

fn created_domain_dir(out_dir: &Path) -> std::path::PathBuf {
    let mut entries = std::fs::read_dir(out_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    entries.sort();
    assert_eq!(entries.len(), 1);
    entries.remove(0)
}

#[test]
fn test_create_basic_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let output = run_create(dir.path(), "home", "long-enough-pass", false);

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Created trust domain"));
}

#[test]
fn test_create_existing_dir_fails() {
    let dir = tempfile::tempdir().unwrap();
    let occupied = dir.path().join("occupied");
    std::fs::write(&occupied, "not a directory").unwrap();

    let output = cli()
        .env("PNW_ROOT_PASSPHRASE", "long-enough-pass")
        .arg("trust")
        .arg("create-domain")
        .arg("--label")
        .arg("home")
        .arg("--out-dir")
        .arg(&occupied)
        .output()
        .unwrap();

    assert!(!output.status.success());
}

#[test]
fn test_create_writes_three_files() {
    let dir = tempfile::tempdir().unwrap();
    let output = run_create(dir.path(), "office", "long-enough-pass", false);
    assert!(output.status.success());

    let domain_dir = created_domain_dir(dir.path());
    assert!(domain_dir.join("sk_root.age").is_file());
    assert!(domain_dir.join("pk_root.pem").is_file());
    assert!(domain_dir.join("meta.toml").is_file());
}

#[test]
fn test_create_json_output_parseable() {
    let dir = tempfile::tempdir().unwrap();
    let output = run_create(dir.path(), "json-net", "long-enough-pass", true);
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(value["trust_domain_id"].as_str().unwrap().len() > 8);
    assert!(Path::new(value["path"].as_str().unwrap()).is_dir());
}

#[test]
fn test_create_short_passphrase_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let output = run_create(dir.path(), "bad", "short", false);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("passphrase"));
}
