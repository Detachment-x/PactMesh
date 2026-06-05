use std::{net::IpAddr, path::Path, process::Command, str::FromStr};

use ed25519_dalek::SigningKey;
use pactmesh::trust::{
    ACL_SCHEMA_VERSION, AclPolicy, Action, Capabilities, HostnameLabel, MemberCert,
    MemberCertIndexEntry, NetworkLocalId, NetworkStatePayload, RevocationReason,
    SignedNetworkState, TrustDomainRoot, UnsignedMemberCert, UnsignedNetworkState,
    to_canonical_cbor,
};
use pnet::ipnetwork::IpNetwork as IpNet;
use rand::rngs::OsRng;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pactmesh"))
}

fn config_home(root: &Path) -> std::path::PathBuf {
    root.join("xdg")
}

fn trust_domains_dir(root: &Path) -> std::path::PathBuf {
    config_home(root).join("privateNetwork/trust-domains")
}

fn create_domain(root_dir: &Path, root: &TrustDomainRoot) -> String {
    let domain_id = root.id().to_string();
    let domain_dir = trust_domains_dir(root_dir).join(&domain_id);
    std::fs::create_dir_all(&domain_dir).unwrap();
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
    domain_id
}

fn build_state(
    root: &TrustDomainRoot,
    network_id: &str,
    certs: Vec<UnsignedMemberCert>,
) -> SignedNetworkState {
    let acl = AclPolicy {
        tags: Default::default(),
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
                .map(|cert| {
                    let cert = cert.clone().sign(root);
                    MemberCertIndexEntry {
                        fingerprint: cert.fingerprint(),
                        device_label: cert.details.device_label,
                        issued_at: cert.details.not_before,
                        expires_at: cert.details.expires_at,
                    }
                })
                .collect(),
            revoked_certs: Vec::new(),
            disabled_certs: Vec::new(),
            acl: to_canonical_cbor(&acl),
            routes: Vec::new(),
            peer_hints: Vec::new(),
        },
    }
    .sign(root)
}

fn setup_network(
    root_dir: &Path,
) -> (
    String,
    String,
    pactmesh::trust::MemberCertFingerprint,
    std::path::PathBuf,
) {
    let root = TrustDomainRoot::generate();
    let domain_id = create_domain(root_dir, &root);
    let network_id = "office-net".to_owned();
    let sk = SigningKey::generate(&mut OsRng);
    let cert = UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str(&network_id).unwrap(),
        device_pk: sk.verifying_key(),
        device_label: "node-a".to_owned(),
        not_before: 10,
        expires_at: 100,
        capabilities: Capabilities {
            can_be_exit_node: false,
            can_relay_data: false,
            can_relay_control: false,
            can_proxy_subnet: Vec::new(),
        },
        network_state_version_ref: 1,
        hostname: Some(HostnameLabel::try_from_str("node-a").unwrap()),
    };
    let state = build_state(&root, &network_id, vec![cert.clone()]);
    let network_dir = trust_domains_dir(root_dir)
        .join(&domain_id)
        .join("networks")
        .join(&network_id);
    let cert_dir = network_dir.join("member_certs");
    std::fs::create_dir_all(&cert_dir).unwrap();
    std::fs::write(network_dir.join("network_state.cbor.pem"), state.to_pem()).unwrap();
    let signed = cert.sign(&root);
    std::fs::write(
        cert_dir.join(format!("{}.pem", signed.fingerprint())),
        signed.to_pem(),
    )
    .unwrap();
    (domain_id, network_id, signed.fingerprint(), network_dir)
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

fn read_cert(network_dir: &Path, fp: pactmesh::trust::MemberCertFingerprint) -> MemberCert {
    let pem = std::fs::read_to_string(network_dir.join("member_certs").join(format!("{}.pem", fp)))
        .unwrap();
    MemberCert::from_pem(&pem).unwrap()
}

#[test]
fn test_capability_set_reissues_member_cert() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, old_fp, network_dir) = setup_network(dir.path());

    let output = run_trust(
        dir.path(),
        &[
            "capability",
            "set",
            &domain_id,
            &network_id,
            &old_fp.to_string(),
            "--relay-data",
            "true",
            "--proxy-subnet",
            "10.42.0.0/24",
            "--json",
        ],
    );
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "capability-updated");
    assert_eq!(value["capabilities"]["relay_data"], true);
    assert_eq!(value["capabilities"]["proxy_subnet"][0], "10.42.0.0/24");

    let state = read_state(dir.path(), &domain_id, &network_id);
    assert_eq!(state.details.version, 2);
    assert_eq!(
        state.details.payload.revoked_certs[0].reason_code,
        RevocationReason::Superseded
    );
    assert_eq!(
        state.details.payload.revoked_certs[0].cert_fingerprint,
        old_fp
    );
    let new_fp = state.details.payload.member_cert_index[0].fingerprint;
    assert_ne!(new_fp, old_fp);
    let cert = read_cert(&network_dir, new_fp);
    assert!(cert.details.capabilities.can_relay_data);
    assert_eq!(
        cert.details.capabilities.can_proxy_subnet,
        vec![IpNet::new(IpAddr::from_str("10.42.0.0").unwrap(), 24).unwrap()]
    );
}

#[test]
fn test_capability_set_requires_change() {
    let dir = tempfile::tempdir().unwrap();
    let (domain_id, network_id, old_fp, _) = setup_network(dir.path());

    let output = run_trust(
        dir.path(),
        &[
            "capability",
            "set",
            &domain_id,
            &network_id,
            &old_fp.to_string(),
        ],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no capability change requested"));
}
