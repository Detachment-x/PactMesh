#![allow(dead_code)]

use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use easytier::{
    common::config::{ConfigLoader, NetworkIdentity, TomlConfigLoader, TrustDomainConfig},
    instance::instance::Instance,
    proto::{
        api::config::{FetchPendingMemberCertRequest, SubmitJoinRequestRequest},
        rpc_types::controller::BaseController,
    },
    rpc_service::InstanceRpcService,
    trust::{
        JoinRequest, MemberCert, MemberCertIndexEntry, NetworkBootstrap, NetworkLocalId,
        NetworkStatePayload, SignedNetworkState, TrustDomainPool, TrustDomainRoot,
        UnsignedNetworkState, from_cbor, to_canonical_cbor, unwrap_armored,
    },
};
use serde_json::Value;
use tokio::sync::RwLock;

pub const NETWORK_LOCAL_ID: &str = "office-net";
pub const ROOT_PASSPHRASE: &str = "long-enough-pass";
pub const DEVICE_PASSPHRASE: &str = "long-enough-device-pass";

pub fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_easytier-cli"))
}

pub fn config_home(root: &Path) -> PathBuf {
    root.join("xdg")
}

pub fn trust_domains_dir(root: &Path) -> PathBuf {
    config_home(root).join("privateNetwork/trust-domains")
}

pub fn domain_dir(root: &Path, trust_domain_id: &str) -> PathBuf {
    trust_domains_dir(root).join(trust_domain_id)
}

pub fn network_dir(root: &Path, trust_domain_id: &str) -> PathBuf {
    domain_dir(root, trust_domain_id)
        .join("networks")
        .join(NETWORK_LOCAL_ID)
}

pub fn create_domain(root: &Path) -> String {
    let output = cli()
        .env("XDG_CONFIG_HOME", config_home(root))
        .env("PNW_ROOT_PASSPHRASE", ROOT_PASSPHRASE)
        .arg("trust")
        .arg("create-domain")
        .arg("--label")
        .arg("e2e-root")
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    value["trust_domain_id"].as_str().unwrap().to_owned()
}

pub fn create_network(root: &Path, trust_domain_id: &str) {
    let output = cli()
        .env("XDG_CONFIG_HOME", config_home(root))
        .env("PNW_ROOT_PASSPHRASE", ROOT_PASSPHRASE)
        .arg("trust")
        .arg("create-network")
        .arg(trust_domain_id)
        .arg(NETWORK_LOCAL_ID)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn invite_url(root: &Path, trust_domain_id: &str) -> String {
    let output = cli()
        .env("XDG_CONFIG_HOME", config_home(root))
        .arg("trust")
        .arg("invite")
        .arg(trust_domain_id)
        .arg(NETWORK_LOCAL_ID)
        .arg("--seed")
        .arg("tcp://203.0.113.10:11010")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

pub fn accept_invite(root: &Path, invite: &str, device_label: &str) -> JoinRequest {
    let output = cli()
        .env("XDG_CONFIG_HOME", config_home(root))
        .env("PNW_DEVICE_PASSPHRASE", DEVICE_PASSPHRASE)
        .arg("trust")
        .arg("accept-invite")
        .arg(invite)
        .arg("--device-label")
        .arg(device_label)
        .arg("--hint")
        .arg("three-node-e2e")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    read_join_request(root, invite)
}

pub fn read_bootstrap(invite: &str) -> NetworkBootstrap {
    let url = url::Url::parse(invite).unwrap();
    NetworkBootstrap::from_url(&url).unwrap()
}

pub fn read_join_request(root: &Path, invite: &str) -> JoinRequest {
    let bootstrap = read_bootstrap(invite);
    let join_path = network_dir(root, &bootstrap.trust_domain_id.to_string())
        .join("pending_join_request.cbor.pem");
    let armored = std::fs::read_to_string(join_path).unwrap();
    let payload = unwrap_armored(&armored, "PNW-JOIN-REQUEST").unwrap();
    from_cbor(&payload).unwrap()
}

pub fn read_network_state(root: &Path, trust_domain_id: &str) -> SignedNetworkState {
    let pem =
        std::fs::read_to_string(network_dir(root, trust_domain_id).join("network_state.cbor.pem"))
            .unwrap();
    SignedNetworkState::from_pem(&pem).unwrap()
}

pub fn trust_pool(root: &Path, trust_domain_id: &str) -> Arc<RwLock<TrustDomainPool>> {
    let domain = domain_dir(root, trust_domain_id);
    let root =
        TrustDomainRoot::load_from_file(&domain.join("sk_root.age"), ROOT_PASSPHRASE).unwrap();
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    pool.apply_network_state(read_network_state(root_parent(&domain), trust_domain_id))
        .unwrap();
    Arc::new(RwLock::new(pool))
}

fn root_parent(domain: &Path) -> &Path {
    domain
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .and_then(Path::parent)
        .unwrap()
}

pub fn root_instance(root: &Path, trust_domain_id: &str) -> Instance {
    unsafe { std::env::set_var("PNW_ROOT_PASSPHRASE", ROOT_PASSPHRASE) };
    let cfg = TomlConfigLoader::default();
    cfg.set_inst_name("root-r".to_owned());
    cfg.set_network_identity(NetworkIdentity::new("three-node-e2e".to_owned()));
    cfg.set_trust_domain(Some(TrustDomainConfig {
        domain_dir: domain_dir(root, trust_domain_id),
        network_local_id: NETWORK_LOCAL_ID.to_owned(),
        sk_self_password_env: "PNW_DEVICE_PASSPHRASE".to_owned(),
        relay_serving: Vec::new(),
    }));
    Instance::new_with_trust_pool(cfg, Some(trust_pool(root, trust_domain_id)))
}

pub async fn approve_join(instance: &Instance, jr: &JoinRequest) -> MemberCert {
    let api = instance.get_api_rpc_service();
    let service = api.get_trust_join_manage_service();
    service
        .submit_join_request(
            BaseController::default(),
            SubmitJoinRequestRequest {
                instance: None,
                join_request_cbor: to_canonical_cbor(jr),
                ttl: 6,
            },
        )
        .await
        .unwrap();

    let expected = instance
        .get_join_forward_service()
        .unwrap()
        .pending
        .lock()
        .unwrap()
        .approve(&jr.applicant_pk.0);

    let response = service
        .fetch_pending_member_cert(
            BaseController::default(),
            FetchPendingMemberCertRequest {
                instance: None,
                trust_domain_id: jr.trust_domain_id.0.to_vec(),
                network_local_id: jr.network_local_id.as_str().to_owned(),
                applicant_pk: jr.applicant_pk.0.to_vec(),
            },
        )
        .await
        .unwrap();
    assert!(response.found);
    let fetched: MemberCert = from_cbor(&response.member_cert_cbor).unwrap();
    assert_eq!(fetched, expected);
    fetched
}

pub fn write_member_cert(root: &Path, trust_domain_id: &str, cert: &MemberCert) {
    std::fs::write(
        network_dir(root, trust_domain_id).join("member_cert.pem"),
        cert.to_pem(),
    )
    .unwrap();
}

pub fn rewrite_network_state_with_members(
    root: &Path,
    trust_domain_id: &str,
    certs: &[MemberCert],
) {
    let domain = domain_dir(root, trust_domain_id);
    let root_key =
        TrustDomainRoot::load_from_file(&domain.join("sk_root.age"), ROOT_PASSPHRASE).unwrap();
    let current = read_network_state(root, trust_domain_id);
    let payload = NetworkStatePayload {
        member_cert_index: certs
            .iter()
            .map(|cert| MemberCertIndexEntry {
                fingerprint: cert.fingerprint(),
                device_label: cert.details.device_label.clone(),
                issued_at: cert.details.not_before,
                expires_at: cert.details.expires_at,
            })
            .collect(),
        revoked_certs: current.details.payload.revoked_certs,
        disabled_certs: current.details.payload.disabled_certs,
        acl: current.details.payload.acl,
        routes: current.details.payload.routes,
        peer_hints: current.details.payload.peer_hints,
    };
    let state = UnsignedNetworkState {
        trust_domain_id: current.details.trust_domain_id,
        network_local_id: current.details.network_local_id,
        version: current.details.version + 1,
        payload,
    }
    .sign(&root_key);
    std::fs::write(
        network_dir(root, trust_domain_id).join("network_state.cbor.pem"),
        state.to_pem(),
    )
    .unwrap();
}

pub fn revoke_member(root: &Path, trust_domain_id: &str, cert: &MemberCert) {
    let output = cli()
        .env("XDG_CONFIG_HOME", config_home(root))
        .env("PNW_ROOT_PASSPHRASE", ROOT_PASSPHRASE)
        .arg("trust")
        .arg("revoke")
        .arg(trust_domain_id)
        .arg(NETWORK_LOCAL_ID)
        .arg(cert.fingerprint().to_string())
        .arg("--reason")
        .arg("removed")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn assert_member_matches_join(cert: &MemberCert, jr: &JoinRequest, device_label: &str) {
    assert_eq!(cert.details.trust_domain_id, jr.trust_domain_id);
    assert_eq!(
        cert.details.network_local_id,
        NetworkLocalId::try_from_str(NETWORK_LOCAL_ID).unwrap()
    );
    assert_eq!(cert.details.device_pk.to_bytes(), jr.applicant_pk.0);
    assert_eq!(cert.details.device_label, device_label);
    jr.verify_self_signature().unwrap();
}
