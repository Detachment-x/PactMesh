use std::{path::Path, process::Command};

use pactmesh::trust::{
    JoinRequest, NetworkBootstrap, NetworkLocalId, TrustDomainRoot, from_cbor, unwrap_armored,
    wrap_armored,
};
use url::Url;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pactmesh"))
}

fn config_home(root: &Path) -> std::path::PathBuf {
    root.join("xdg")
}

fn trust_domains_dir(root: &Path) -> std::path::PathBuf {
    config_home(root).join("privateNetwork/trust-domains")
}

fn devices_dir(root: &Path) -> std::path::PathBuf {
    config_home(root).join("privateNetwork/devices")
}

fn bootstrap(root: &TrustDomainRoot) -> NetworkBootstrap {
    NetworkBootstrap {
        trust_domain_id: root.id(),
        pk_root: root.public_key(),
        network_local_id: NetworkLocalId::try_from_str("office-net").unwrap(),
        bootstrap_seeds: vec![Url::parse("tcp://203.0.113.10:11010").unwrap()],
        trust_domain_label: Some("home".to_owned()),
        network_name: Some("office".to_owned()),
        description: None,
    }
}

fn run_accept(root: &Path, source: &str, passphrase: &str) -> std::process::Output {
    cli()
        .env("XDG_CONFIG_HOME", config_home(root))
        .env("PNW_DEVICE_PASSPHRASE", passphrase)
        .arg("trust")
        .arg("accept-invite")
        .arg(source)
        .arg("--device-label")
        .arg("laptop")
        .arg("--hint")
        .arg("desk")
        .output()
        .unwrap()
}

fn run_accept_default_key(root: &Path, source: &str) -> std::process::Output {
    cli()
        .env("XDG_CONFIG_HOME", config_home(root))
        .arg("trust")
        .arg("accept-invite")
        .arg(source)
        .arg("--device-label")
        .arg("laptop")
        .arg("--hint")
        .arg("desk")
        .output()
        .unwrap()
}

#[test]
fn test_accept_invite_url_succeeds_with_mock_root() {
    let dir = tempfile::tempdir().unwrap();
    let root = TrustDomainRoot::generate();
    let bootstrap = bootstrap(&root);
    let url = bootstrap.to_url().unwrap();

    let output = run_accept_default_key(dir.path(), url.as_str());

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let domain_dir = trust_domains_dir(dir.path()).join(root.id().to_string());
    assert!(domain_dir.join("pk_root.pem").is_file());
    assert!(
        devices_dir(dir.path())
            .join("default/sk_self.raw")
            .is_file()
    );
    assert!(
        devices_dir(dir.path())
            .join("default/pk_self.pem")
            .is_file()
    );
    assert!(domain_dir.join("networks/office-net/sk_self.raw").is_file());
    let join_path = domain_dir.join("networks/office-net/pending_join_request.cbor.pem");
    let armored = std::fs::read_to_string(join_path).unwrap();
    let payload = unwrap_armored(&armored, "PNW-JOIN-REQUEST").unwrap();
    let jr: JoinRequest = from_cbor(&payload).unwrap();
    assert_eq!(jr.trust_domain_id, root.id());
    assert_eq!(jr.network_local_id.as_str(), "office-net");
    assert_eq!(jr.device_label, "laptop");
    assert_eq!(jr.hint, "desk");
    jr.verify_self_signature().unwrap();
}

#[test]
fn test_accept_invite_with_device_passphrase_keeps_encrypted_key() {
    let dir = tempfile::tempdir().unwrap();
    let root = TrustDomainRoot::generate();
    let bootstrap = bootstrap(&root);
    let url = bootstrap.to_url().unwrap();

    let output = run_accept(dir.path(), url.as_str(), "long-enough-pass");

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let domain_dir = trust_domains_dir(dir.path()).join(root.id().to_string());
    assert!(
        devices_dir(dir.path())
            .join("default/sk_self.age")
            .is_file()
    );
    assert!(domain_dir.join("networks/office-net/sk_self.age").is_file());
}

#[test]
fn test_accept_invite_unknown_pk_root_mismatch_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let root = TrustDomainRoot::generate();
    let other = TrustDomainRoot::generate();
    let domain_dir = trust_domains_dir(dir.path()).join(root.id().to_string());
    std::fs::create_dir_all(&domain_dir).unwrap();
    std::fs::write(
        domain_dir.join("pk_root.pem"),
        wrap_armored("PNW-PK-ROOT", other.public_key().as_bytes()),
    )
    .unwrap();
    let url = bootstrap(&root).to_url().unwrap();

    let output = run_accept(dir.path(), url.as_str(), "long-enough-pass");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not match invite"));
}

#[test]
fn test_accept_invite_file_source_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let root = TrustDomainRoot::generate();
    let pem_path = dir.path().join("invite.pem");
    std::fs::write(&pem_path, bootstrap(&root).to_pem()).unwrap();

    let output = run_accept(dir.path(), pem_path.to_str().unwrap(), "long-enough-pass");

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        trust_domains_dir(dir.path())
            .join(root.id().to_string())
            .join("networks/office-net/pending_join_request.cbor.pem")
            .is_file()
    );
}

#[test]
fn test_accept_invite_short_passphrase_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let root = TrustDomainRoot::generate();
    let url = bootstrap(&root).to_url().unwrap();

    let output = run_accept(dir.path(), url.as_str(), "short");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("device passphrase"));
}

#[test]
fn test_accept_invite_timeout_after_1h() {
    let dir = tempfile::tempdir().unwrap();
    let root = TrustDomainRoot::generate();
    let url = bootstrap(&root).to_url().unwrap();

    let output = run_accept(dir.path(), url.as_str(), "long-enough-pass");

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("T-134b"));
}

#[test]
fn test_accept_invite_reuses_global_device_identity_across_domains() {
    let dir = tempfile::tempdir().unwrap();
    let root_a = TrustDomainRoot::generate();
    let root_b = TrustDomainRoot::generate();

    let out_a = run_accept(
        dir.path(),
        bootstrap(&root_a).to_url().unwrap().as_str(),
        "long-enough-pass",
    );
    assert!(
        out_a.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out_a.stderr)
    );
    let out_b = run_accept(
        dir.path(),
        bootstrap(&root_b).to_url().unwrap().as_str(),
        "long-enough-pass",
    );
    assert!(
        out_b.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out_b.stderr)
    );

    let read_jr = |root: &TrustDomainRoot| -> JoinRequest {
        let path = trust_domains_dir(dir.path())
            .join(root.id().to_string())
            .join("networks/office-net/pending_join_request.cbor.pem");
        let armored = std::fs::read_to_string(path).unwrap();
        let payload = unwrap_armored(&armored, "PNW-JOIN-REQUEST").unwrap();
        from_cbor(&payload).unwrap()
    };
    let jr_a = read_jr(&root_a);
    let jr_b = read_jr(&root_b);

    assert_eq!(jr_a.applicant_pk, jr_b.applicant_pk);
    assert_ne!(jr_a.trust_domain_id, jr_b.trust_domain_id);
    assert!(
        devices_dir(dir.path())
            .join("default/sk_self.age")
            .is_file()
    );
    assert_eq!(
        std::fs::read_dir(devices_dir(dir.path())).unwrap().count(),
        1
    );
    assert_eq!(
        std::fs::read_to_string(
            trust_domains_dir(dir.path())
                .join(root_a.id().to_string())
                .join("networks/office-net/device_id")
        )
        .unwrap(),
        std::fs::read_to_string(
            trust_domains_dir(dir.path())
                .join(root_b.id().to_string())
                .join("networks/office-net/device_id")
        )
        .unwrap()
    );
}
