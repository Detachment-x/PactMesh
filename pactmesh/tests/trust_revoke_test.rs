use std::{collections::BTreeMap, path::Path, process::Command};

use pactmesh::trust::{
    ACL_SCHEMA_VERSION, AclPolicy, Action, MemberCertFingerprint, MemberCertIndexEntry,
    NetworkLocalId, NetworkStatePayload, RevocationReason, SignedNetworkState, TrustDomainRoot,
    UnsignedNetworkState, to_canonical_cbor,
};

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

fn setup_network(root_dir: &Path, version: u64) -> (String, String, MemberCertFingerprint) {
    let root = TrustDomainRoot::generate();
    let domain_id = root.id().to_string();
    let network_id = "office-net".to_owned();
    let domain_dir = trust_domains_dir(root_dir).join(&domain_id);
    let network_dir = domain_dir.join("networks").join(&network_id);
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

    let fp = fingerprint(7);
    let acl = AclPolicy {
        tags: BTreeMap::new(),
        rules: Vec::new(),
        default_action: Action::Accept,
        schema_version: ACL_SCHEMA_VERSION,
    };
    let state = UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str(&network_id).unwrap(),
        version,
        payload: NetworkStatePayload {
            member_cert_index: vec![MemberCertIndexEntry {
                fingerprint: fp,
                device_label: "laptop".to_owned(),
                issued_at: 10,
                expires_at: 100,
            }],
            revoked_certs: Vec::new(),
            disabled_certs: Vec::new(),
            acl: to_canonical_cbor(&acl),
            routes: Vec::new(),
            peer_hints: Vec::new(),
            ip_assignments: Vec::new(),
            capability_grants: Vec::new(),
            hostname_bindings: Vec::new(),
        },
    }
    .sign(&root);
    std::fs::write(network_dir.join("network_state.cbor.pem"), state.to_pem()).unwrap();
    (domain_id, network_id, fp)
}

fn run_revoke(
    root: &Path,
    domain_id: &str,
    network_id: &str,
    fp: MemberCertFingerprint,
    extra: &[&str],
) -> std::process::Output {
    let mut cmd = cli();
    cmd.env("XDG_CONFIG_HOME", config_home(root))
        .env("PNW_ROOT_PASSPHRASE", "long-enough-pass")
        .arg("trust")
        .arg("revoke")
        .arg(domain_id)
        .arg(network_id)
        .arg(fp.to_string());
    for arg in extra {
        cmd.arg(arg);
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
fn test_revoke_basic() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, fp) = setup_network(dir.path(), 1);

    let output = run_revoke(
        dir.path(),
        &domain_id,
        &network_id,
        fp,
        &["--reason", "removed", "--note", "left"],
    );

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let state = read_state(dir.path(), &domain_id, &network_id);
    assert_eq!(state.details.payload.revoked_certs.len(), 1);
    assert_eq!(state.details.payload.revoked_certs[0].cert_fingerprint, fp);
    assert_eq!(
        state.details.payload.revoked_certs[0]
            .reason_note
            .as_deref(),
        Some("left")
    );
}

#[test]
fn test_revoke_unknown_fingerprint_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, _fp) = setup_network(dir.path(), 1);

    let output = run_revoke(dir.path(), &domain_id, &network_id, fingerprint(9), &[]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("fingerprint not found"));
}

#[test]
fn test_revoke_version_monotonic() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, fp) = setup_network(dir.path(), 4);

    let output = run_revoke(dir.path(), &domain_id, &network_id, fp, &[]);
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let network_dir = trust_domains_dir(dir.path())
        .join(&domain_id)
        .join("networks")
        .join(&network_id);
    assert!(network_dir.join("network_state.v4.cbor.pem").is_file());
    let state = read_state(dir.path(), &domain_id, &network_id);
    assert_eq!(state.details.version, 5);
}

#[test]
fn test_revoke_reason_code_default_unspecified() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, fp) = setup_network(dir.path(), 1);

    let output = run_revoke(dir.path(), &domain_id, &network_id, fp, &[]);
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let state = read_state(dir.path(), &domain_id, &network_id);
    assert_eq!(
        state.details.payload.revoked_certs[0].reason_code,
        RevocationReason::Unspecified
    );
}
