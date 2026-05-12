use std::{collections::BTreeMap, net::IpAddr, path::Path, process::Command, str::FromStr};

use easytier::trust::{
    ACL_SCHEMA_VERSION, AclPolicy, Action, Capabilities, HostnameLabel, MemberCertIndexEntry,
    NetworkLocalId, NetworkStatePayload, RevocationReason, SignedNetworkState, TrustDomainRoot,
    UnsignedMemberCert, UnsignedNetworkState, to_canonical_cbor,
};
use ed25519_dalek::SigningKey;
use pnet::ipnetwork::IpNetwork as IpNet;
use rand::rngs::OsRng;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_easytier-cli"))
}

fn config_home(root: &Path) -> std::path::PathBuf {
    root.join("xdg")
}

fn trust_domains_dir(root: &Path) -> std::path::PathBuf {
    config_home(root).join("privateNetwork/trust-domains")
}

fn build_state(
    root: &TrustDomainRoot,
    network_id: &str,
    certs: Vec<UnsignedMemberCert>,
) -> SignedNetworkState {
    let acl = AclPolicy {
        tags: BTreeMap::new(),
        rules: Vec::new(),
        default_action: Action::Accept,
        schema_version: ACL_SCHEMA_VERSION,
    };
    UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str(network_id).unwrap(),
        version: 1,
        payload: NetworkStatePayload {
            member_cert_index: certs
                .iter()
                .map(|cert| MemberCertIndexEntry {
                    fingerprint: cert.clone().sign(root).fingerprint(),
                    device_label: cert.device_label.clone(),
                    issued_at: cert.not_before,
                    expires_at: cert.expires_at,
                })
                .collect(),
            revoked_certs: Vec::new(),
            disabled_certs: Vec::new(),
            acl: to_canonical_cbor(&acl),
            routes: Vec::new(),
        },
    }
    .sign(root)
}

fn create_domain(root_dir: &Path, root: &TrustDomainRoot) -> String {
    let domain_id = root.id().to_string();
    let domain_dir = trust_domains_dir(root_dir).join(&domain_id);
    std::fs::create_dir_all(&domain_dir).unwrap();
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
    domain_id
}

fn write_network(
    root_dir: &Path,
    root: &TrustDomainRoot,
    network_id: &str,
    state: &SignedNetworkState,
    certs: &[UnsignedMemberCert],
) {
    let domain_id = root.id().to_string();
    let network_dir = trust_domains_dir(root_dir)
        .join(&domain_id)
        .join("networks")
        .join(network_id);
    let cert_dir = network_dir.join("member_certs");
    std::fs::create_dir_all(&cert_dir).unwrap();
    std::fs::write(network_dir.join("network_state.cbor.pem"), state.to_pem()).unwrap();
    for cert in certs {
        let signed = cert.clone().sign(root);
        std::fs::write(
            cert_dir.join(format!("{}.pem", signed.fingerprint())),
            signed.to_pem(),
        )
        .unwrap();
    }
}

fn setup_network(
    root_dir: &Path,
) -> (
    String,
    String,
    TrustDomainRoot,
    easytier::trust::MemberCertFingerprint,
    easytier::trust::MemberCertFingerprint,
) {
    let root = TrustDomainRoot::generate();
    let domain_id = create_domain(root_dir, &root);
    let network_id = "office-net".to_owned();
    let sk_a = SigningKey::generate(&mut OsRng);
    let sk_b = SigningKey::generate(&mut OsRng);
    let cert_a = UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str(&network_id).unwrap(),
        device_pk: sk_a.verifying_key(),
        device_label: "laptop-a".to_owned(),
        not_before: 10,
        expires_at: 100,
        capabilities: Capabilities {
            can_relay_data: true,
            can_relay_control: false,
            can_proxy_subnet: vec![IpNet::new(IpAddr::from_str("10.0.0.0").unwrap(), 24).unwrap()],
        },
        network_state_version_ref: 1,
        hostname: Some(HostnameLabel::try_from_str("laptop").unwrap()),
    };
    let cert_b = UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str(&network_id).unwrap(),
        device_pk: sk_b.verifying_key(),
        device_label: "server-b".to_owned(),
        not_before: 10,
        expires_at: 100,
        capabilities: Capabilities {
            can_relay_data: true,
            can_relay_control: true,
            can_proxy_subnet: vec![],
        },
        network_state_version_ref: 1,
        hostname: Some(HostnameLabel::try_from_str("server").unwrap()),
    };
    let state = build_state(&root, &network_id, vec![cert_a.clone(), cert_b.clone()]);
    write_network(root_dir, &root, &network_id, &state, &[cert_a, cert_b]);
    (
        domain_id,
        network_id,
        root,
        state.details.payload.member_cert_index[0].fingerprint,
        state.details.payload.member_cert_index[1].fingerprint,
    )
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
fn test_set_hostname_basic_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, root, fp_a, _) = setup_network(dir.path());

    let output = run_trust(
        dir.path(),
        &[
            "set-hostname",
            &domain_id,
            &network_id,
            &fp_a.to_string(),
            "MACBOOK",
        ],
    );
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let state = read_state(dir.path(), &domain_id, &network_id);
    assert_eq!(state.details.version, 2);
    assert_eq!(
        state.details.payload.revoked_certs[0].reason_code,
        RevocationReason::Superseded
    );
    let reissued = std::fs::read_dir(
        trust_domains_dir(dir.path())
            .join(&domain_id)
            .join("networks")
            .join(&network_id)
            .join("member_certs"),
    )
    .unwrap()
    .count();
    assert_eq!(reissued, 3);
    assert!(
        state
            .details
            .payload
            .member_cert_index
            .iter()
            .any(|entry| entry.fingerprint != fp_a)
    );
    let _ = root;
}

#[test]
fn test_set_hostname_already_taken_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, _root, fp_a, fp_b) = setup_network(dir.path());

    let output = run_trust(
        dir.path(),
        &[
            "set-hostname",
            &domain_id,
            &network_id,
            &fp_b.to_string(),
            "laptop",
        ],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already taken"));
    let state = read_state(dir.path(), &domain_id, &network_id);
    assert_eq!(state.details.version, 1);
    assert!(state.details.payload.revoked_certs.is_empty());
    let _ = fp_a;
}

#[test]
fn test_set_hostname_idempotent_same_name_same_fp() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, _root, fp_a, _) = setup_network(dir.path());

    let output = run_trust(
        dir.path(),
        &[
            "set-hostname",
            &domain_id,
            &network_id,
            &fp_a.to_string(),
            "laptop",
        ],
    );
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let state = read_state(dir.path(), &domain_id, &network_id);
    assert_eq!(state.details.version, 1);
}

#[test]
fn test_set_hostname_invalid_label_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, _root, fp_a, _) = setup_network(dir.path());

    let output = run_trust(
        dir.path(),
        &[
            "set-hostname",
            &domain_id,
            &network_id,
            &fp_a.to_string(),
            "BAD_NAME",
        ],
    );
    assert!(!output.status.success());
}

#[test]
fn test_unset_hostname_removes_assignment() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, _root, fp_a, _) = setup_network(dir.path());

    let output = run_trust(
        dir.path(),
        &["unset-hostname", &domain_id, &network_id, &fp_a.to_string()],
    );
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let state = read_state(dir.path(), &domain_id, &network_id);
    assert!(
        state
            .details
            .payload
            .member_cert_index
            .iter()
            .any(|entry| entry.fingerprint != fp_a)
    );
    assert_eq!(
        state.details.payload.revoked_certs[0].reason_code,
        RevocationReason::Superseded
    );
}

#[test]
fn test_set_after_unset_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, _root, fp_a, fp_b) = setup_network(dir.path());
    assert!(
        run_trust(
            dir.path(),
            &["unset-hostname", &domain_id, &network_id, &fp_a.to_string()]
        )
        .status
        .success()
    );

    let output = run_trust(
        dir.path(),
        &[
            "set-hostname",
            &domain_id,
            &network_id,
            &fp_b.to_string(),
            "laptop",
        ],
    );
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_set_writes_revoked_old_cert() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, _root, fp_a, _) = setup_network(dir.path());

    let output = run_trust(
        dir.path(),
        &[
            "set-hostname",
            &domain_id,
            &network_id,
            &fp_a.to_string(),
            "macbook",
            "--note",
            "rename",
        ],
    );
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let state = read_state(dir.path(), &domain_id, &network_id);
    assert!(
        state
            .details
            .payload
            .revoked_certs
            .iter()
            .any(|revoked| revoked.cert_fingerprint == fp_a
                && revoked.reason_code == RevocationReason::Superseded)
    );
}
