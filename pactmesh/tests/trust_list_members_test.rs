use std::{collections::BTreeMap, net::IpAddr, path::Path, process::Command, str::FromStr};

use ed25519_dalek::SigningKey;
use pactmesh::trust::{
    ACL_SCHEMA_VERSION, AclPolicy, Action, Capabilities, HostnameLabel, MemberCertFingerprint,
    MemberCertIndexEntry, NetworkLocalId, NetworkStatePayload, RevocationReason, TrustDomainRoot,
    UnsignedMemberCert, UnsignedNetworkState, to_canonical_cbor,
};
use pnet::ipnetwork::IpNetwork as IpNet;
use rand::rngs::OsRng;
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

fn fingerprint(byte: u8) -> MemberCertFingerprint {
    MemberCertFingerprint([byte; 32])
}

fn network_dir(root: &Path, domain_id: &str, network_id: &str) -> std::path::PathBuf {
    trust_domains_dir(root)
        .join(domain_id)
        .join("networks")
        .join(network_id)
}

fn write_domain_state(
    root_dir: &Path,
    entries: Vec<MemberCertIndexEntry>,
    revoked: Vec<MemberCertFingerprint>,
    disabled: Vec<MemberCertFingerprint>,
) -> (TrustDomainRoot, String, String) {
    let root = TrustDomainRoot::generate();
    let domain_id = root.id().to_string();
    let network_id = "office-net".to_owned();
    let domain_dir = trust_domains_dir(root_dir).join(&domain_id);
    let network_dir = network_dir(root_dir, &domain_id, &network_id);
    std::fs::create_dir_all(&network_dir).unwrap();
    root.save_to_file(&domain_dir.join("sk_root.age"), "long-enough-pass")
        .unwrap();
    std::fs::write(
        domain_dir.join("pk_root.pem"),
        pactmesh::trust::wrap_armored("PNW-PK-ROOT", root.public_key().as_bytes()),
    )
    .unwrap();
    std::fs::write(
        domain_dir.join("meta.toml"),
        "label = \"home\"\ncreated_at = \"1\"\ncurve = \"ed25519\"\n",
    )
    .unwrap();

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
            member_cert_index: entries,
            revoked_certs: revoked
                .into_iter()
                .map(|cert_fingerprint| pactmesh::trust::RevokedCert {
                    cert_fingerprint,
                    revoked_at: 10,
                    reason_code: RevocationReason::Removed,
                    reason_note: None,
                })
                .collect(),
            disabled_certs: disabled
                .into_iter()
                .map(|cert_fingerprint| pactmesh::trust::DisabledCert {
                    cert_fingerprint,
                    disabled_at: 10,
                    expected_until: None,
                    reason_note: None,
                })
                .collect(),
            acl: to_canonical_cbor(&acl),
            routes: Vec::new(),
            peer_hints: Vec::new(),
            admin_grants: Vec::new(),
        },
    }
    .sign(&root);
    std::fs::write(network_dir.join("network_state.cbor.pem"), state.to_pem()).unwrap();
    (root, domain_id, network_id)
}

fn index_entry(fp: MemberCertFingerprint, label: &str) -> MemberCertIndexEntry {
    MemberCertIndexEntry {
        fingerprint: fp,
        device_label: label.to_owned(),
        issued_at: 10,
        expires_at: 100,
    }
}

fn run_list(
    root: &Path,
    domain_id: &str,
    network_id: &str,
    extra: &[&str],
) -> std::process::Output {
    let mut cmd = cli();
    cmd.env("XDG_CONFIG_HOME", config_home(root))
        .arg("trust")
        .arg("list-members")
        .arg(domain_id)
        .arg(network_id);
    for arg in extra {
        cmd.arg(arg);
    }
    cmd.output().unwrap()
}

#[test]
fn test_list_members_empty() {
    let dir = tempfile::tempdir().unwrap();
    let (_root, domain_id, network_id) =
        write_domain_state(dir.path(), Vec::new(), Vec::new(), Vec::new());

    let output = run_list(dir.path(), &domain_id, &network_id, &[]);

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("(no members)"));
}

#[test]
fn test_list_members_mixed_statuses() {
    let dir = tempfile::tempdir().unwrap();
    let active = fingerprint(1);
    let disabled = fingerprint(2);
    let revoked = fingerprint(3);
    let expired = fingerprint(4);
    let (_root, domain_id, network_id) = write_domain_state(
        dir.path(),
        vec![
            MemberCertIndexEntry {
                expires_at: u64::MAX,
                ..index_entry(active, "active")
            },
            MemberCertIndexEntry {
                expires_at: u64::MAX,
                ..index_entry(disabled, "disabled")
            },
            MemberCertIndexEntry {
                expires_at: u64::MAX,
                ..index_entry(revoked, "revoked")
            },
            index_entry(expired, "expired"),
        ],
        vec![revoked],
        vec![disabled],
    );

    let output = run_list(dir.path(), &domain_id, &network_id, &["--include", "all"]);

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("active"));
    assert!(stdout.contains("disabled"));
    assert!(stdout.contains("revoked"));
    assert!(stdout.contains("expired"));
    assert!(stdout.contains("role"));
    assert!(stdout.contains("network_local_id"));
    assert!(stdout.contains("device_id"));
}

#[test]
fn test_list_members_capability_rendering() {
    let dir = tempfile::tempdir().unwrap();
    let root = TrustDomainRoot::generate();
    let domain_id = root.id().to_string();
    let network_id = "office-net".to_owned();
    let domain_dir = trust_domains_dir(dir.path()).join(&domain_id);
    let network_path = network_dir(dir.path(), &domain_id, &network_id);
    std::fs::create_dir_all(&network_path).unwrap();
    root.save_to_file(&domain_dir.join("sk_root.age"), "long-enough-pass")
        .unwrap();
    std::fs::write(
        domain_dir.join("pk_root.pem"),
        pactmesh::trust::wrap_armored("PNW-PK-ROOT", root.public_key().as_bytes()),
    )
    .unwrap();
    std::fs::write(
        domain_dir.join("meta.toml"),
        "label = \"home\"\ncreated_at = \"1\"\ncurve = \"ed25519\"\n",
    )
    .unwrap();
    let sk = SigningKey::generate(&mut OsRng);
    let cert = UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str(&network_id).unwrap(),
        device_pk: sk.verifying_key(),
        device_label: "relay".to_owned(),
        not_before: 10,
        expires_at: u64::MAX,
        capabilities: Capabilities {
            can_relay_data: true,
            can_relay_control: true,
            can_proxy_subnet: vec![IpNet::new(IpAddr::from_str("10.0.0.0").unwrap(), 24).unwrap()],
        },
        network_state_version_ref: 1,
        hostname: Some(HostnameLabel::try_from_str("relay-1").unwrap()),
    }
    .sign(&root);
    let fp = cert.fingerprint();
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
            member_cert_index: vec![MemberCertIndexEntry {
                expires_at: u64::MAX,
                ..index_entry(fp, "relay")
            }],
            revoked_certs: Vec::new(),
            disabled_certs: Vec::new(),
            acl: to_canonical_cbor(&acl),
            routes: Vec::new(),
            peer_hints: Vec::new(),
            admin_grants: Vec::new(),
        },
    }
    .sign(&root);
    std::fs::write(network_path.join("network_state.cbor.pem"), state.to_pem()).unwrap();
    std::fs::write(network_path.join("member_cert.pem"), cert.to_pem()).unwrap();

    let output = run_list(dir.path(), &domain_id, &network_id, &[]);

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("relay-data"));
    assert!(stdout.contains("relay-control"));
    assert!(stdout.contains("proxy-subnet:10.0.0.0/24"));
    assert!(stdout.contains("relay-1"));
}

#[test]
fn test_list_members_status_filter() {
    let dir = tempfile::tempdir().unwrap();
    let active = fingerprint(1);
    let disabled = fingerprint(2);
    let (_root, domain_id, network_id) = write_domain_state(
        dir.path(),
        vec![
            index_entry(active, "active"),
            index_entry(disabled, "disabled"),
        ],
        Vec::new(),
        vec![disabled],
    );

    let output = run_list(
        dir.path(),
        &domain_id,
        &network_id,
        &["--include", "disabled"],
    );

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("disabled"));
    assert!(!stdout.contains("\tactive\t"));
}

#[test]
fn test_list_members_expired_filter() {
    let dir = tempfile::tempdir().unwrap();
    let active = fingerprint(1);
    let expired = fingerprint(2);
    let (_root, domain_id, network_id) = write_domain_state(
        dir.path(),
        vec![
            MemberCertIndexEntry {
                expires_at: u64::MAX,
                ..index_entry(active, "active")
            },
            index_entry(expired, "expired"),
        ],
        Vec::new(),
        Vec::new(),
    );

    let output = run_list(
        dir.path(),
        &domain_id,
        &network_id,
        &["--include", "expired"],
    );

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("expired"));
    assert!(!stdout.contains("\tactive\t"));
}

#[test]
fn test_list_members_json_format() {
    let dir = tempfile::tempdir().unwrap();
    let active = fingerprint(1);
    let (_root, domain_id, network_id) = write_domain_state(
        dir.path(),
        vec![MemberCertIndexEntry {
            expires_at: u64::MAX,
            ..index_entry(active, "active")
        }],
        Vec::new(),
        Vec::new(),
    );

    let output = run_list(dir.path(), &domain_id, &network_id, &["--json"]);

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let rows = value.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["device_label"], "active");
    assert_eq!(rows[0]["status"], "active");
    assert_eq!(rows[0]["device_id"], "unknown");
    assert_eq!(rows[0]["role"], "member");
    assert_eq!(rows[0]["network_local_id"], "office-net");
    assert!(rows[0]["capabilities"].is_object());
    assert_eq!(rows[0]["capabilities"]["relay_data"], false);
}
