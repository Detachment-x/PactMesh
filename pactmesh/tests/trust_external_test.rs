use std::{path::Path, process::Command};

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pactmesh"))
}

fn write_config(root: &Path, body: &str) -> std::path::PathBuf {
    let path = root.join("pactmesh.toml");
    std::fs::write(&path, body).unwrap();
    path
}

fn run_list_external(config: &Path, json: bool) -> std::process::Output {
    let mut cmd = cli();
    cmd.arg("trust")
        .arg("list-external")
        .arg("--config")
        .arg(config);
    if json {
        cmd.arg("--json");
    }
    cmd.output().unwrap()
}

#[test]
fn test_list_external_without_trust_domain_is_empty_json() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "[network_identity]\nnetwork_name = \"test\"\n");

    let output = run_list_external(&config, true);

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value.as_array().unwrap().len(), 0);
}

#[test]
fn test_list_external_from_relay_serving_config_json() {
    let dir = tempfile::tempdir().unwrap();
    let domain_dir = dir.path().join("domain");
    let meta = dir.path().join("foreign_meta.pem");
    let state = dir.path().join("foreign_state.pem");
    let bootstrap = dir.path().join("foreign_bootstrap.cbor");
    let config = write_config(
        dir.path(),
        &format!(
            r#"[network_identity]
network_name = "test"

[trust_domain]
domain_dir = "{}"
network_local_id = "office-net"
sk_self_password_env = "PNW_DEVICE_PASSPHRASE"

[[trust_domain.relay_serving]]
foreign_root_pk_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
foreign_trust_domain_meta_pem = "{}"
foreign_network_state_pem = "{}"
foreign_bootstrap_cbor = "{}"
can_relay_data = true
can_assist_holepunch = false
expires_at = 1800000000
"#,
            domain_dir.display(),
            meta.display(),
            state.display(),
            bootstrap.display()
        ),
    );

    let output = run_list_external(&config, true);

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let row = &value.as_array().unwrap()[0];
    assert_eq!(row["role"], "external");
    assert_eq!(
        row["foreign_root_pk_hex"],
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(row["can_relay_data"], true);
    assert_eq!(row["can_assist_holepunch"], false);
    assert_eq!(row["expires_at"], 1800000000u64);
    assert_eq!(
        row["foreign_trust_domain_meta_pem"],
        meta.display().to_string()
    );
    assert_eq!(
        row["foreign_network_state_pem"],
        state.display().to_string()
    );
    assert_eq!(
        row["foreign_bootstrap_cbor"],
        bootstrap.display().to_string()
    );
}

#[test]
fn test_list_external_table_output() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(
        dir.path(),
        &format!(
            r#"[network_identity]
network_name = "test"

[trust_domain]
domain_dir = "{}"
network_local_id = "office-net"
sk_self_password_env = "PNW_DEVICE_PASSPHRASE"

[[trust_domain.relay_serving]]
foreign_root_pk_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
can_relay_data = false
can_assist_holepunch = true
expires_at = 1900000000
"#,
            dir.path().join("domain").display()
        ),
    );

    let output = run_list_external(&config, false);

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("foreign_root_pk"));
    assert!(stdout.contains("external"));
    assert!(stdout.contains("bbbbbbbbbbbb"));
    assert!(stdout.contains("1900000000"));
}
