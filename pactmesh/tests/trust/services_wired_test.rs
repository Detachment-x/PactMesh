use std::sync::{Arc, LazyLock, Mutex};

use pactmesh::{
    common::config::{ConfigLoader, NetworkIdentity, TomlConfigLoader},
    instance::instance::Instance,
    proto::{
        peer_rpc::{ForwardJoinRequestRequest, JoinForwardRpc},
        rpc_types::controller::BaseController,
    },
    trust::{
        JoinRequest, NetworkLocalId, SignKey, TrustDomainPool, TrustDomainRoot, to_canonical_cbor,
        wrap_armored,
    },
};
use tokio::sync::RwLock;

static ROOT_PASSPHRASE_ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn test_config(network_name: &str) -> TomlConfigLoader {
    let cfg = TomlConfigLoader::default();
    cfg.set_network_identity(NetworkIdentity::new(network_name.to_owned()));
    cfg.set_inst_name(format!("{network_name}-inst"));
    cfg
}

fn test_pool() -> Arc<RwLock<TrustDomainPool>> {
    let root = TrustDomainRoot::generate();
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    Arc::new(RwLock::new(pool))
}

fn trust_config(
    network_name: &str,
    domain_dir: &std::path::Path,
    network_local_id: &str,
) -> TomlConfigLoader {
    let cfg = test_config(network_name);
    cfg.set_trust_domain(Some(pactmesh::common::config::TrustDomainConfig {
        domain_dir: domain_dir.to_path_buf(),
        network_local_id: network_local_id.to_owned(),
        sk_self_password_env: "PNW_SK_SELF_PASSWORD_UNUSED".to_owned(),
        relay_serving: Vec::new(),
    }));
    cfg
}

fn write_root_files(domain_dir: &std::path::Path, root: &TrustDomainRoot, passphrase: &str) {
    std::fs::create_dir_all(domain_dir).unwrap();
    root.save_to_file(&domain_dir.join("sk_root.age"), passphrase)
        .unwrap();
    std::fs::write(
        domain_dir.join("pk_root.pem"),
        wrap_armored("PNW-PK-ROOT", root.public_key().as_bytes()),
    )
    .unwrap();
}

fn join_request(root: &TrustDomainRoot, network_local_id: &str) -> JoinRequest {
    JoinRequest::new_signed(
        root.id(),
        NetworkLocalId::try_from_str(network_local_id).unwrap(),
        &SignKey::from_bytes([0x51; 32]),
        "device-a".to_owned(),
        "pending".to_owned(),
    )
}

#[tokio::test]
async fn test_instance_wires_config_sync_service_when_trust_pool_present() {
    let instance = Instance::new_with_trust_pool(test_config("svc-net"), Some(test_pool()));

    assert!(instance.get_config_sync_service().is_some());
}

#[tokio::test]
async fn test_instance_wires_join_forward_service_when_trust_pool_present() {
    let instance = Instance::new_with_trust_pool(test_config("svc-net"), Some(test_pool()));

    assert!(instance.get_join_forward_service().is_some());
}

#[tokio::test]
async fn test_instance_skips_trust_services_without_trust_pool() {
    let instance = Instance::new(test_config("plain-net"));

    assert!(instance.get_config_sync_service().is_none());
    assert!(instance.get_join_forward_service().is_none());
}

#[tokio::test]
async fn test_join_forward_service_uses_real_root_when_available() {
    let dir = tempfile::tempdir().unwrap();
    let root = TrustDomainRoot::generate();
    let network_local_id = "office-net";
    write_root_files(dir.path(), &root, "long-enough-pass");

    let instance = {
        let _guard = ROOT_PASSPHRASE_ENV_LOCK.lock().unwrap();
        // SAFETY: this test sets a process env var consumed synchronously by Instance::new.
        unsafe { std::env::set_var("PNW_ROOT_PASSPHRASE", "long-enough-pass") };
        let instance = Instance::new_with_trust_pool(
            trust_config("svc-net", dir.path(), network_local_id),
            Some(test_pool()),
        );
        // SAFETY: cleanup for the process env var set above.
        unsafe { std::env::remove_var("PNW_ROOT_PASSPHRASE") };
        instance
    };

    let service = instance.get_join_forward_service().unwrap();
    let jr = join_request(&root, network_local_id);
    service
        .forward_join_request(
            BaseController::default(),
            ForwardJoinRequestRequest {
                inner_cbor: to_canonical_cbor(&jr),
                ttl: 6,
                seen_node_pks: Vec::new(),
            },
        )
        .await
        .unwrap();

    let cert = service.pending.lock().unwrap().approve(&jr.applicant_pk.0);
    cert.verify(&root.public_key()).unwrap();
    assert_eq!(cert.details.trust_domain_id, root.id());
    assert_eq!(cert.details.network_local_id.as_str(), network_local_id);
}

#[tokio::test]
async fn test_join_forward_service_without_sk_root_enqueues_but_cannot_sign() {
    let dir = tempfile::tempdir().unwrap();
    let root = TrustDomainRoot::generate();
    let network_local_id = "office-net";
    std::fs::create_dir_all(dir.path()).unwrap();
    std::fs::write(
        dir.path().join("pk_root.pem"),
        wrap_armored("PNW-PK-ROOT", root.public_key().as_bytes()),
    )
    .unwrap();

    let instance = {
        let _guard = ROOT_PASSPHRASE_ENV_LOCK.lock().unwrap();
        // SAFETY: this test verifies the pk_root-only path with no daemon-held root secret.
        unsafe { std::env::remove_var("PNW_ROOT_PASSPHRASE") };
        Instance::new_with_trust_pool(
            trust_config("svc-net", dir.path(), network_local_id),
            Some(test_pool()),
        )
    };

    let service = instance.get_join_forward_service().unwrap();
    let jr = join_request(&root, network_local_id);
    service
        .forward_join_request(
            BaseController::default(),
            ForwardJoinRequestRequest {
                inner_cbor: to_canonical_cbor(&jr),
                ttl: 0,
                seen_node_pks: Vec::new(),
            },
        )
        .await
        .unwrap();

    let queued = service.pending.lock().unwrap().list();
    assert_eq!(queued, vec![jr]);
    assert!(!service.can_sign_pending_certs);
}
