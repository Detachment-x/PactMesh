use std::{collections::BTreeMap, path::Path, process::Command};

use easytier::trust::{
    ACL_SCHEMA_VERSION, AclPolicy, Action, MemberCertFingerprint, MemberCertIndexEntry,
    NetworkLocalId, NetworkStatePayload, RevocationReason, SignedNetworkState, TrustDomainRoot,
    UnsignedNetworkState, to_canonical_cbor,
};
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

fn fingerprint(byte: u8) -> MemberCertFingerprint {
    MemberCertFingerprint([byte; 32])
}

fn write_state(
    root_dir: &Path,
    root: &TrustDomainRoot,
    domain_id: &str,
    network_id: &str,
    state: SignedNetworkState,
) {
    let network_dir = trust_domains_dir(root_dir)
        .join(domain_id)
        .join("networks")
        .join(network_id);
    std::fs::create_dir_all(&network_dir).unwrap();
    root.save_to_file(
        &trust_domains_dir(root_dir)
            .join(domain_id)
            .join("sk_root.age"),
        "long-enough-pass",
    )
    .unwrap();
    std::fs::write(
        trust_domains_dir(root_dir)
            .join(domain_id)
            .join("pk_root.pem"),
        easytier::trust::wrap_armored("PNW-PK-ROOT", root.public_key().as_bytes()),
    )
    .unwrap();
    std::fs::write(
        trust_domains_dir(root_dir)
            .join(domain_id)
            .join("meta.toml"),
        "label = \"home\"\ncreated_at = \"1\"\ncurve = \"ed25519\"\n",
    )
    .unwrap();
    std::fs::write(network_dir.join("network_state.cbor.pem"), state.to_pem()).unwrap();
}

fn setup_network(root_dir: &Path) -> (String, String, MemberCertFingerprint) {
    let root = TrustDomainRoot::generate();
    let domain_id = root.id().to_string();
    let network_id = "office-net".to_owned();
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
        version: 1,
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
        },
    }
    .sign(&root);
    write_state(root_dir, &root, &domain_id, &network_id, state);
    (domain_id, network_id, fp)
}

fn run_trust(root: &Path, args: &[&str]) -> std::process::Output {
    let mut cmd = cli();
    cmd.env("XDG_CONFIG_HOME", config_home(root))
        .env("PNW_ROOT_PASSPHRASE", "long-enough-pass")
        .arg("trust");
    for arg in args {
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
fn test_disable_basic() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, fp) = setup_network(dir.path());

    let output = run_trust(
        dir.path(),
        &[
            "disable",
            &domain_id,
            &network_id,
            &fp.to_string(),
            "--note",
            "maintenance",
        ],
    );

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let state = read_state(dir.path(), &domain_id, &network_id);
    assert_eq!(state.details.version, 2);
    assert_eq!(state.details.payload.disabled_certs.len(), 1);
    assert_eq!(state.details.payload.disabled_certs[0].cert_fingerprint, fp);
    assert_eq!(
        state.details.payload.disabled_certs[0]
            .reason_note
            .as_deref(),
        Some("maintenance")
    );
}

#[test]
fn test_disable_with_until() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, fp) = setup_network(dir.path());

    let output = run_trust(
        dir.path(),
        &[
            "disable",
            &domain_id,
            &network_id,
            &fp.to_string(),
            "--until",
            "2030-01-01T00:00:00Z",
        ],
    );

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let state = read_state(dir.path(), &domain_id, &network_id);
    assert_eq!(
        state.details.payload.disabled_certs[0].expected_until,
        Some(1_893_456_000)
    );
}

#[test]
fn test_enable_restores() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, fp) = setup_network(dir.path());
    assert!(
        run_trust(
            dir.path(),
            &["disable", &domain_id, &network_id, &fp.to_string()]
        )
        .status
        .success()
    );

    let output = run_trust(
        dir.path(),
        &["enable", &domain_id, &network_id, &fp.to_string()],
    );

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let state = read_state(dir.path(), &domain_id, &network_id);
    assert_eq!(state.details.payload.disabled_certs.len(), 0);
    assert_eq!(state.details.version, 3);
}

#[test]
fn test_enable_without_prior_disable_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, fp) = setup_network(dir.path());

    let output = run_trust(
        dir.path(),
        &["enable", &domain_id, &network_id, &fp.to_string()],
    );

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not disabled"));
}

#[test]
fn test_disable_already_revoked_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, fp) = setup_network(dir.path());
    assert!(
        run_trust(
            dir.path(),
            &["revoke", &domain_id, &network_id, &fp.to_string()]
        )
        .status
        .success()
    );

    let output = run_trust(
        dir.path(),
        &["disable", &domain_id, &network_id, &fp.to_string()],
    );

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("permanently revoked"));
    let state = read_state(dir.path(), &domain_id, &network_id);
    assert_eq!(
        state.details.payload.revoked_certs[0].reason_code,
        RevocationReason::Unspecified
    );
}

#[test]
fn test_disable_json_output() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, fp) = setup_network(dir.path());

    let output = run_trust(
        dir.path(),
        &[
            "disable",
            &domain_id,
            &network_id,
            &fp.to_string(),
            "--json",
        ],
    );

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["fingerprint"], fp.to_string());
    assert_eq!(value["old_version"], 1);
    assert_eq!(value["new_version"], 2);
    assert_eq!(value["status"], "disabled");
}
