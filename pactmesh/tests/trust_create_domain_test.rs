use std::{path::Path, process::Command};

use serde_json::Value;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pactmesh"))
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
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Created trust domain"));
    assert!(stdout.contains("Backup required"));
    assert!(stdout.contains("sk_root.age"));
    assert!(stdout.contains("management password"));
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
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Backup required"));
}

#[test]
fn test_create_short_passphrase_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let output = run_create(dir.path(), "bad", "short", false);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("passphrase"));
}

#[test]
fn test_create_passphrase_file_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let passphrase_dir = tempfile::tempdir().unwrap();
    let passphrase_file = passphrase_dir.path().join("management-passphrase.txt");
    std::fs::write(&passphrase_file, "long-enough-pass\n").unwrap();

    let output = cli()
        .arg("trust")
        .arg("create-domain")
        .arg("--label")
        .arg("file-pass")
        .arg("--out-dir")
        .arg(dir.path())
        .arg("--passphrase-file")
        .arg(&passphrase_file)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(created_domain_dir(dir.path()).join("sk_root.age").is_file());
}

#[test]
fn test_create_missing_passphrase_non_tty_reports_management_password() {
    let dir = tempfile::tempdir().unwrap();

    let output = cli()
        .env_remove("PNW_ROOT_PASSPHRASE")
        .arg("trust")
        .arg("create-domain")
        .arg("--label")
        .arg("missing-pass")
        .arg("--out-dir")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("management password"), "stderr={stderr}");
    assert!(stderr.contains("TTY"), "stderr={stderr}");
}
