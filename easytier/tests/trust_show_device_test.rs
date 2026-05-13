use std::{collections::BTreeMap, path::Path, process::Command};

use easytier::trust::{
    ACL_SCHEMA_VERSION, AclPolicy, AclRule, Action, Capabilities, DeviceFingerprint, MemberCert,
    MemberCertIndexEntry, NetworkLocalId, NetworkStatePayload, PortSpec, Proto, RevocationReason,
    Selector, SignKey, SignedNetworkState, TagName, TrustDomainRoot, UnsignedMemberCert,
    UnsignedNetworkState, to_canonical_cbor,
};
use ed25519_dalek::VerifyingKey;
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

fn network_dir(root: &Path, domain_id: &str, network_id: &str) -> std::path::PathBuf {
    trust_domains_dir(root)
        .join(domain_id)
        .join("networks")
        .join(network_id)
}

fn encode_device_id(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn member_cert(
    root: &TrustDomainRoot,
    network_id: &str,
    relay_data: bool,
    label: &str,
) -> MemberCert {
    let sk = SignKey::generate();
    let device_pk = VerifyingKey::from_bytes(&sk.verify_key().0).unwrap();
    UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str(network_id).unwrap(),
        device_pk,
        device_label: label.to_owned(),
        not_before: 10,
        expires_at: u64::MAX,
        capabilities: Capabilities {
            can_relay_data: relay_data,
            can_relay_control: false,
            can_proxy_subnet: Vec::new(),
        },
        network_state_version_ref: 1,
        hostname: None,
    }
    .sign(root)
}

fn write_fixture(root_dir: &Path) -> (String, String, Vec<String>) {
    let root = TrustDomainRoot::generate();
    let domain_id = root.id().to_string();
    let network_id = "office-net".to_owned();
    let domain_dir = trust_domains_dir(root_dir).join(&domain_id);
    let network_path = network_dir(root_dir, &domain_id, &network_id);
    let cert_dir = network_path.join("member_certs");
    std::fs::create_dir_all(&cert_dir).unwrap();
    root.save_to_file(&domain_dir.join("sk_root.age"), "long-enough-pass")
        .unwrap();
    std::fs::write(
        domain_dir.join("pk_root.pem"),
        easytier::trust::wrap_armored("PNW-PK-ROOT", root.public_key().as_bytes()),
    )
    .unwrap();
    std::fs::write(
        domain_dir.join("meta.toml"),
        "label = \"home\"\ncreated_at = \"1\"\ncurve = \"ed25519\"\n",
    )
    .unwrap();

    let certs = vec![
        member_cert(&root, &network_id, true, "alpha"),
        member_cert(&root, &network_id, false, "bravo"),
    ];
    for cert in &certs {
        std::fs::write(
            cert_dir.join(format!("{}.pem", cert.fingerprint())),
            cert.to_pem(),
        )
        .unwrap();
    }
    let ids = certs
        .iter()
        .map(|cert| encode_device_id(cert.details.device_pk.as_bytes()))
        .collect::<Vec<_>>();
    let acl = AclPolicy {
        tags: BTreeMap::new(),
        rules: Vec::new(),
        default_action: Action::Accept,
        schema_version: ACL_SCHEMA_VERSION,
    };
    let state = UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str(&network_id).unwrap(),
        version: 1,
        payload: NetworkStatePayload {
            member_cert_index: certs
                .iter()
                .map(|cert| MemberCertIndexEntry {
                    fingerprint: cert.fingerprint(),
                    device_label: cert.details.device_label.clone(),
                    issued_at: cert.details.not_before,
                    expires_at: cert.details.expires_at,
                })
                .collect(),
            revoked_certs: Vec::new(),
            disabled_certs: Vec::new(),
            acl: to_canonical_cbor(&acl),
            routes: Vec::new(),
            peer_hints: Vec::new(),
        },
    }
    .sign(&root);
    std::fs::write(network_path.join("network_state.cbor.pem"), state.to_pem()).unwrap();
    (domain_id, network_id, ids)
}

fn run_show(
    root: &Path,
    domain_id: &str,
    network_id: &str,
    device_id: &str,
    json: bool,
) -> std::process::Output {
    let mut cmd = cli();
    cmd.env("XDG_CONFIG_HOME", config_home(root))
        .arg("trust")
        .arg("show-device")
        .arg(domain_id)
        .arg(network_id)
        .arg(device_id);
    if json {
        cmd.arg("--json");
    }
    cmd.output().unwrap()
}

fn run_rename(
    root: &Path,
    domain_id: &str,
    network_id: &str,
    device_id: &str,
    label: &str,
    json: bool,
) -> std::process::Output {
    let mut cmd = cli();
    cmd.env("XDG_CONFIG_HOME", config_home(root))
        .env("PNW_ROOT_PASSPHRASE", "long-enough-pass")
        .arg("trust")
        .arg("rename-device")
        .arg(domain_id)
        .arg(network_id)
        .arg(device_id)
        .arg("--label")
        .arg(label);
    if json {
        cmd.arg("--json");
    }
    cmd.output().unwrap()
}

fn run_tag(root: &Path, args: &[&str], json: bool) -> std::process::Output {
    let mut cmd = cli();
    cmd.env("XDG_CONFIG_HOME", config_home(root))
        .env("PNW_ROOT_PASSPHRASE", "long-enough-pass")
        .arg("trust")
        .arg("tag");
    for arg in args {
        cmd.arg(arg);
    }
    if json {
        cmd.arg("--json");
    }
    cmd.output().unwrap()
}

fn run_trust_acl(root: &Path, args: &[&str], json: bool) -> std::process::Output {
    let mut cmd = cli();
    cmd.env("XDG_CONFIG_HOME", config_home(root))
        .arg("trust")
        .arg("acl");
    for arg in args {
        cmd.arg(arg);
    }
    if json {
        cmd.arg("--json");
    }
    cmd.output().unwrap()
}

fn run_list_json(root: &Path, domain_id: &str, network_id: &str) -> Value {
    let output = cli()
        .env("XDG_CONFIG_HOME", config_home(root))
        .arg("trust")
        .arg("list-members")
        .arg(domain_id)
        .arg(network_id)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn read_state(root: &Path, domain_id: &str, network_id: &str) -> SignedNetworkState {
    let pem = std::fs::read_to_string(
        network_dir(root, domain_id, network_id).join("network_state.cbor.pem"),
    )
    .unwrap();
    SignedNetworkState::from_pem(&pem).unwrap()
}

fn write_acl_policy(root: &Path, domain_id: &str, network_id: &str, policy: AclPolicy) {
    let state = read_state(root, domain_id, network_id);
    let root_key = TrustDomainRoot::load_from_file(
        &trust_domains_dir(root).join(domain_id).join("sk_root.age"),
        "long-enough-pass",
    )
    .unwrap();
    let mut details = state.details.clone();
    details.payload.acl = to_canonical_cbor(&policy);
    let signed = details.sign(&root_key);
    std::fs::write(
        network_dir(root, domain_id, network_id).join("network_state.cbor.pem"),
        signed.to_pem(),
    )
    .unwrap();
}

fn fingerprint_from_state(
    root: &Path,
    domain_id: &str,
    network_id: &str,
    idx: usize,
) -> DeviceFingerprint {
    DeviceFingerprint(
        read_state(root, domain_id, network_id)
            .details
            .payload
            .member_cert_index[idx]
            .fingerprint
            .0,
    )
}

fn tag(name: &str) -> TagName {
    TagName::try_from_str(name).unwrap()
}

fn explain_json(
    root: &Path,
    domain_id: &str,
    network_id: &str,
    src: &str,
    dst: &str,
    extra: &[&str],
) -> Value {
    let mut args = vec!["explain", domain_id, network_id, src, dst];
    args.extend_from_slice(extra);
    let output = run_trust_acl(root, &args, true);
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn test_show_device_full_id_json() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, ids) = write_fixture(dir.path());

    let output = run_show(dir.path(), &domain_id, &network_id, &ids[0], true);

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["device_id"], ids[0]);
    assert_eq!(value["device_label"], "alpha");
    assert_eq!(value["role"], "member");
    assert_eq!(value["network_local_id"], "office-net");
    assert_eq!(value["status"], "active");
}

#[test]
fn test_show_device_unique_prefix_human() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, ids) = write_fixture(dir.path());

    let output = run_show(dir.path(), &domain_id, &network_id, &ids[0][..16], false);

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("device_id:"));
    assert!(stdout.contains("device_label: alpha"));
    assert!(stdout.contains("capabilities: relay-data"));
}

#[test]
fn test_show_device_ambiguous_prefix_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, _ids) = write_fixture(dir.path());

    let output = run_show(dir.path(), &domain_id, &network_id, "", false);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ambiguous"));
    assert!(stderr.contains("candidates"));
}

#[test]
fn test_show_device_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, _ids) = write_fixture(dir.path());

    let output = run_show(dir.path(), &domain_id, &network_id, "no-such-device", false);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not found"));
}

#[test]
fn test_rename_device_updates_list_and_show() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, ids) = write_fixture(dir.path());

    let output = run_rename(
        dir.path(),
        &domain_id,
        &network_id,
        &ids[0],
        "alpha-new",
        true,
    );

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rename: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rename["status"], "renamed");
    assert_eq!(rename["device_label"], "alpha-new");
    assert_ne!(rename["old_fingerprint"], rename["new_fingerprint"]);

    let show_output = run_show(dir.path(), &domain_id, &network_id, &ids[0], true);
    assert!(
        show_output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&show_output.stderr)
    );
    let shown: Value = serde_json::from_slice(&show_output.stdout).unwrap();
    assert_eq!(shown["device_id"], ids[0]);
    assert_eq!(shown["device_label"], "alpha-new");

    let listed = run_list_json(dir.path(), &domain_id, &network_id);
    let active_rows = listed.as_array().unwrap();
    assert_eq!(
        active_rows
            .iter()
            .filter(|row| row["device_id"] == ids[0] && row["status"] == "active")
            .count(),
        1
    );
    assert!(
        active_rows
            .iter()
            .any(|row| row["device_id"] == ids[0] && row["device_label"] == "alpha-new")
    );
    assert!(
        active_rows
            .iter()
            .all(|row| row["device_id"] != ids[0] || row["device_label"] != "alpha")
    );

    let state = read_state(dir.path(), &domain_id, &network_id);
    assert_eq!(state.details.version, 2);
    assert!(state.details.payload.revoked_certs.iter().any(|revoked| {
        revoked.cert_fingerprint.to_string() == rename["old_fingerprint"].as_str().unwrap()
            && revoked.reason_code == RevocationReason::Superseded
    }));
}

#[test]
fn test_rename_device_ambiguous_prefix_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, _ids) = write_fixture(dir.path());

    let output = run_rename(dir.path(), &domain_id, &network_id, "", "new-name", false);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ambiguous"));
    assert!(stderr.contains("candidates"));
}

#[test]
fn test_rename_device_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, _ids) = write_fixture(dir.path());

    let output = run_rename(
        dir.path(),
        &domain_id,
        &network_id,
        "no-such-device",
        "new-name",
        false,
    );

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not found"));
}

#[test]
fn test_tag_add_list_remove_updates_device_view() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, ids) = write_fixture(dir.path());

    let add = run_tag(
        dir.path(),
        &["add", &domain_id, &network_id, &ids[0], "ops"],
        true,
    );
    assert!(
        add.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&add.stderr)
    );
    let add_json: Value = serde_json::from_slice(&add.stdout).unwrap();
    assert_eq!(add_json["status"], "tag-added");
    assert_eq!(add_json["tag"], "ops");

    let show_output = run_show(dir.path(), &domain_id, &network_id, &ids[0], true);
    assert!(
        show_output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&show_output.stderr)
    );
    let shown: Value = serde_json::from_slice(&show_output.stdout).unwrap();
    assert_eq!(shown["tags"], serde_json::json!(["ops"]));
    assert_eq!(shown["role"], "member");
    assert_eq!(shown["capabilities"]["relay_data"], true);

    let list = run_tag(dir.path(), &["list", &domain_id, &network_id], true);
    assert!(
        list.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&list.stderr)
    );
    let tags: Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(tags.as_array().unwrap().len(), 1);
    assert_eq!(tags[0]["tag"], "ops");

    let remove = run_tag(
        dir.path(),
        &["remove", &domain_id, &network_id, &ids[0], "ops"],
        true,
    );
    assert!(
        remove.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&remove.stderr)
    );
    let shown_after = run_show(dir.path(), &domain_id, &network_id, &ids[0], true);
    let shown_after: Value = serde_json::from_slice(&shown_after.stdout).unwrap();
    assert_eq!(shown_after["tags"], serde_json::json!([]));
}

#[test]
fn test_tag_invalid_name_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, ids) = write_fixture(dir.path());

    let output = run_tag(
        dir.path(),
        &["add", &domain_id, &network_id, &ids[0], "bad:name"],
        false,
    );

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid byte"));
}

#[test]
fn test_acl_explain_allows_by_device_rule() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, ids) = write_fixture(dir.path());
    let fp0 = fingerprint_from_state(dir.path(), &domain_id, &network_id, 0);
    let fp1 = fingerprint_from_state(dir.path(), &domain_id, &network_id, 1);
    write_acl_policy(
        dir.path(),
        &domain_id,
        &network_id,
        AclPolicy {
            tags: BTreeMap::new(),
            rules: vec![AclRule {
                action: Action::Accept,
                src: vec![Selector::Device(fp0)],
                dst: vec![Selector::Device(fp1)],
                proto: Proto::Tcp,
                ports: Some(vec![PortSpec::Single(22)]),
            }],
            default_action: Action::Drop,
            schema_version: ACL_SCHEMA_VERSION,
        },
    );

    let value = explain_json(
        dir.path(),
        &domain_id,
        &network_id,
        &ids[0],
        &ids[1],
        &["--proto", "tcp", "--port", "22"],
    );

    assert_eq!(value["action"], "accept");
    assert_eq!(value["matched_rule"], 0);
    assert!(value["reason"].as_str().unwrap().contains("device:"));
}

#[test]
fn test_acl_explain_drops_by_tag_rule() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, ids) = write_fixture(dir.path());
    let fp0 = fingerprint_from_state(dir.path(), &domain_id, &network_id, 0);
    let fp1 = fingerprint_from_state(dir.path(), &domain_id, &network_id, 1);
    let mut tags = BTreeMap::new();
    tags.insert(tag("ops"), vec![fp0]);
    tags.insert(tag("server"), vec![fp1]);
    write_acl_policy(
        dir.path(),
        &domain_id,
        &network_id,
        AclPolicy {
            tags,
            rules: vec![AclRule {
                action: Action::Drop,
                src: vec![Selector::Tag(tag("ops"))],
                dst: vec![Selector::Tag(tag("server"))],
                proto: Proto::Tcp,
                ports: Some(vec![PortSpec::Single(5432)]),
            }],
            default_action: Action::Accept,
            schema_version: ACL_SCHEMA_VERSION,
        },
    );

    let value = explain_json(
        dir.path(),
        &domain_id,
        &network_id,
        &ids[0],
        &ids[1],
        &["--proto", "tcp", "--port", "5432"],
    );

    assert_eq!(value["action"], "drop");
    assert_eq!(value["matched_rule"], 0);
    assert_eq!(value["src_tags"], serde_json::json!(["ops"]));
    assert_eq!(value["dst_tags"], serde_json::json!(["server"]));
    assert!(value["reason"].as_str().unwrap().contains("tag:ops"));
}

#[test]
fn test_acl_explain_port_mismatch_falls_back_default() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, ids) = write_fixture(dir.path());
    let fp0 = fingerprint_from_state(dir.path(), &domain_id, &network_id, 0);
    let fp1 = fingerprint_from_state(dir.path(), &domain_id, &network_id, 1);
    write_acl_policy(
        dir.path(),
        &domain_id,
        &network_id,
        AclPolicy {
            tags: BTreeMap::new(),
            rules: vec![AclRule {
                action: Action::Accept,
                src: vec![Selector::Device(fp0)],
                dst: vec![Selector::Device(fp1)],
                proto: Proto::Tcp,
                ports: Some(vec![PortSpec::Single(22)]),
            }],
            default_action: Action::Drop,
            schema_version: ACL_SCHEMA_VERSION,
        },
    );

    let value = explain_json(
        dir.path(),
        &domain_id,
        &network_id,
        &ids[0],
        &ids[1],
        &["--proto", "tcp", "--port", "80"],
    );

    assert_eq!(value["action"], "drop");
    assert!(value["matched_rule"].is_null());
    assert_eq!(value["reason"], "default policy");
}

#[test]
fn test_acl_explain_default_accept_human_output() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, ids) = write_fixture(dir.path());

    let output = run_trust_acl(
        dir.path(),
        &[
            "explain",
            &domain_id,
            &network_id,
            &ids[0],
            &ids[1],
            "--proto",
            "udp",
            "--port",
            "53",
        ],
        false,
    );

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("action: accept"));
    assert!(stdout.contains("default policy applies"));
}
