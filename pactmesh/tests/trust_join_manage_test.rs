use pactmesh::{
    common::config::{ConfigLoader, NetworkIdentity, TomlConfigLoader},
    instance::instance::Instance,
    proto::{
        api::config::{
            ApproveJoinRequestRequest, FetchPendingMemberCertRequest,
            ListPendingJoinRequestsRequest, RejectJoinRequestRequest, SubmitJoinRequestRequest,
        },
        rpc_types::controller::BaseController,
    },
    rpc_service::InstanceRpcService,
    trust::{
        Capabilities, JoinRequest, MemberCert, NetworkLocalId, NetworkStatePayload, SignKey,
        SignedNetworkState, TrustDomainPool, TrustDomainRoot, UnsignedMemberCert,
        UnsignedNetworkState, from_cbor, to_canonical_cbor, wrap_armored,
    },
};
use tokio::sync::RwLock;

use std::sync::{Arc, LazyLock, Mutex};

const NETWORK_NAME: &str = "trust-join-manage-test";
const NETWORK_LOCAL_ID: &str = "office-net";
const ROOT_PASSPHRASE: &str = "long-enough-pass";

static ROOT_PASSPHRASE_ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn write_root_files(domain_dir: &std::path::Path, root: &TrustDomainRoot) {
    std::fs::create_dir_all(domain_dir).unwrap();
    root.save_to_file(&domain_dir.join("sk_root.age"), ROOT_PASSPHRASE)
        .unwrap();
    std::fs::write(
        domain_dir.join("pk_root.pem"),
        wrap_armored("PNW-PK-ROOT", root.public_key().as_bytes()),
    )
    .unwrap();
}

fn test_config(domain_dir: &std::path::Path) -> TomlConfigLoader {
    let cfg = TomlConfigLoader::default();
    cfg.set_network_identity(NetworkIdentity::new(NETWORK_NAME.to_owned()));
    cfg.set_inst_name("trust-join-manage".to_owned());
    cfg.set_trust_domain(Some(pactmesh::common::config::TrustDomainConfig {
        domain_dir: domain_dir.to_path_buf(),
        network_local_id: NETWORK_LOCAL_ID.to_owned(),
        sk_self_password_env: "PNW_SK_SELF_PASSWORD_UNUSED".to_owned(),
        relay_serving: Vec::new(),
    }));
    cfg
}

fn test_pool(root: &TrustDomainRoot) -> Arc<RwLock<TrustDomainPool>> {
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    pool.apply_network_state(network_state(root)).unwrap();
    Arc::new(RwLock::new(pool))
}

fn network_state(root: &TrustDomainRoot) -> SignedNetworkState {
    UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str(NETWORK_LOCAL_ID).unwrap(),
        version: 1,
        payload: NetworkStatePayload {
            member_cert_index: Vec::new(),
            revoked_certs: Vec::new(),
            disabled_certs: Vec::new(),
            acl: Vec::new(),
            routes: Vec::new(),
            peer_hints: Vec::new(),
            admin_grants: Vec::new(),
        },
    }
    .sign(root)
}

fn join_request(root: &TrustDomainRoot) -> JoinRequest {
    JoinRequest::new_signed(
        root.id(),
        NetworkLocalId::try_from_str(NETWORK_LOCAL_ID).unwrap(),
        &SignKey::from_bytes([0x62; 32]),
        "device-a".to_owned(),
        "pending".to_owned(),
    )
}

fn root_capable_instance(domain_dir: &std::path::Path, root: &TrustDomainRoot) -> Instance {
    let _guard = ROOT_PASSPHRASE_ENV_LOCK.lock().unwrap();
    // SAFETY: all tests in this file use the same passphrase value; Instance construction reads it synchronously.
    unsafe { std::env::set_var("PNW_ROOT_PASSPHRASE", ROOT_PASSPHRASE) };
    Instance::new_with_trust_pool(test_config(domain_dir), Some(test_pool(root)))
}

fn root_metadata_only_instance(domain_dir: &std::path::Path, root: &TrustDomainRoot) -> Instance {
    let _guard = ROOT_PASSPHRASE_ENV_LOCK.lock().unwrap();
    // SAFETY: Instance construction reads this environment variable synchronously.
    unsafe { std::env::set_var("PNW_ROOT_PASSPHRASE", "wrong-root-passphrase") };
    Instance::new_with_trust_pool(test_config(domain_dir), Some(test_pool(root)))
}

fn member_cert_for_request(root: &TrustDomainRoot, jr: &JoinRequest) -> MemberCert {
    let device_pk = ed25519_dalek::VerifyingKey::from_bytes(&jr.applicant_pk.0).unwrap();
    UnsignedMemberCert {
        trust_domain_id: jr.trust_domain_id,
        network_local_id: jr.network_local_id.clone(),
        device_pk,
        device_label: jr.device_label.clone(),
        not_before: 1,
        expires_at: 4_102_444_800,
        capabilities: Capabilities {
            can_relay_data: false,
            can_relay_control: false,
            can_proxy_subnet: Vec::new(),
        },
        network_state_version_ref: 1,
        hostname: None,
    }
    .sign(root)
}

fn network_state_with_member(root: &TrustDomainRoot, cert: &MemberCert) -> SignedNetworkState {
    let mut state = network_state(root).details;
    state.version = state.version.saturating_add(1);
    state
        .payload
        .member_cert_index
        .push(pactmesh::trust::MemberCertIndexEntry {
            fingerprint: cert.fingerprint(),
            device_label: cert.details.device_label.clone(),
            issued_at: cert.details.not_before,
            expires_at: cert.details.expires_at,
        });
    state.sign(root)
}

async fn submit(instance: &Instance, jr: &JoinRequest) {
    let api = instance.get_api_rpc_service();
    api.get_trust_join_manage_service()
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
}

#[tokio::test]
async fn test_submit_join_request_enqueues_on_root_capable_instance() {
    let dir = tempfile::tempdir().unwrap();
    let root = TrustDomainRoot::generate();
    write_root_files(dir.path(), &root);
    let instance = root_capable_instance(dir.path(), &root);
    let jr = join_request(&root);

    submit(&instance, &jr).await;

    let queued = instance
        .get_join_forward_service()
        .unwrap()
        .pending
        .lock()
        .unwrap()
        .list();
    assert_eq!(queued, vec![jr]);
}

#[tokio::test]
async fn test_fetch_pending_member_cert_returns_not_found_before_approve() {
    let dir = tempfile::tempdir().unwrap();
    let root = TrustDomainRoot::generate();
    write_root_files(dir.path(), &root);
    let instance = root_capable_instance(dir.path(), &root);
    let jr = join_request(&root);
    let api = instance.get_api_rpc_service();

    let response = api
        .get_trust_join_manage_service()
        .fetch_pending_member_cert(
            BaseController::default(),
            FetchPendingMemberCertRequest {
                instance: None,
                trust_domain_id: root.id().0.to_vec(),
                network_local_id: NETWORK_LOCAL_ID.to_owned(),
                applicant_pk: jr.applicant_pk.0.to_vec(),
            },
        )
        .await
        .unwrap();

    assert!(!response.found);
    assert!(response.member_cert_cbor.is_empty());
    assert!(response.network_state_cbor.is_empty());
}

#[tokio::test]
async fn test_fetch_pending_member_cert_returns_cert_after_approve() {
    let dir = tempfile::tempdir().unwrap();
    let root = TrustDomainRoot::generate();
    write_root_files(dir.path(), &root);
    let instance = root_capable_instance(dir.path(), &root);
    let jr = join_request(&root);
    submit(&instance, &jr).await;

    let expected = instance
        .get_join_forward_service()
        .unwrap()
        .pending
        .lock()
        .unwrap()
        .approve(&jr.applicant_pk.0);

    let api = instance.get_api_rpc_service();
    let response = api
        .get_trust_join_manage_service()
        .fetch_pending_member_cert(
            BaseController::default(),
            FetchPendingMemberCertRequest {
                instance: None,
                trust_domain_id: root.id().0.to_vec(),
                network_local_id: NETWORK_LOCAL_ID.to_owned(),
                applicant_pk: jr.applicant_pk.0.to_vec(),
            },
        )
        .await
        .unwrap();

    assert!(response.found);
    let decoded: MemberCert = from_cbor(&response.member_cert_cbor).unwrap();
    assert_eq!(decoded, expected);
    let decoded_state: SignedNetworkState = from_cbor(&response.network_state_cbor).unwrap();
    assert_eq!(decoded_state, network_state(&root));
}

#[tokio::test]
async fn test_approve_join_request_via_rpc_signs_and_returns_cert() {
    let dir = tempfile::tempdir().unwrap();
    let root = TrustDomainRoot::generate();
    write_root_files(dir.path(), &root);
    let instance = root_capable_instance(dir.path(), &root);
    let jr = join_request(&root);
    submit(&instance, &jr).await;

    let api = instance.get_api_rpc_service();
    let response = api
        .get_trust_join_manage_service()
        .approve_join_request(
            BaseController::default(),
            ApproveJoinRequestRequest {
                instance: None,
                trust_domain_id: root.id().0.to_vec(),
                network_local_id: NETWORK_LOCAL_ID.to_owned(),
                applicant_pk: jr.applicant_pk.0.to_vec(),
                member_cert_cbor: None,
                network_state_cbor: None,
            },
        )
        .await
        .unwrap();

    let cert: MemberCert = from_cbor(&response.member_cert_cbor).unwrap();
    assert_eq!(cert.details.trust_domain_id, root.id());
    assert_eq!(cert.details.device_pk.as_bytes(), &jr.applicant_pk.0);
    assert_eq!(cert.details.device_label, jr.device_label);

    let remaining = instance
        .get_join_forward_service()
        .unwrap()
        .pending
        .lock()
        .unwrap()
        .list();
    assert!(remaining.is_empty(), "approve must dequeue the request");

    let fetched = api
        .get_trust_join_manage_service()
        .fetch_pending_member_cert(
            BaseController::default(),
            FetchPendingMemberCertRequest {
                instance: None,
                trust_domain_id: root.id().0.to_vec(),
                network_local_id: NETWORK_LOCAL_ID.to_owned(),
                applicant_pk: jr.applicant_pk.0.to_vec(),
            },
        )
        .await
        .unwrap();
    assert!(fetched.found);
    let fetched_cert: MemberCert = from_cbor(&fetched.member_cert_cbor).unwrap();
    assert_eq!(fetched_cert, cert);
    let fetched_state: SignedNetworkState = from_cbor(&fetched.network_state_cbor).unwrap();
    assert_eq!(fetched_state, network_state(&root));
}

#[tokio::test]
async fn test_approve_join_request_accepts_cli_signed_cert_without_daemon_root_key() {
    let dir = tempfile::tempdir().unwrap();
    let root = TrustDomainRoot::generate();
    write_root_files(dir.path(), &root);
    let instance = root_metadata_only_instance(dir.path(), &root);
    let jr = join_request(&root);
    submit(&instance, &jr).await;

    let supplied_cert = member_cert_for_request(&root, &jr);
    let api = instance.get_api_rpc_service();
    let response = api
        .get_trust_join_manage_service()
        .approve_join_request(
            BaseController::default(),
            ApproveJoinRequestRequest {
                instance: None,
                trust_domain_id: root.id().0.to_vec(),
                network_local_id: NETWORK_LOCAL_ID.to_owned(),
                applicant_pk: jr.applicant_pk.0.to_vec(),
                member_cert_cbor: Some(to_canonical_cbor(&supplied_cert)),
                network_state_cbor: None,
            },
        )
        .await
        .unwrap();

    let returned_cert: MemberCert = from_cbor(&response.member_cert_cbor).unwrap();
    assert_eq!(returned_cert, supplied_cert);

    let remaining = instance
        .get_join_forward_service()
        .unwrap()
        .pending
        .lock()
        .unwrap()
        .list();
    assert!(remaining.is_empty(), "approve must dequeue the request");

    let fetched = api
        .get_trust_join_manage_service()
        .fetch_pending_member_cert(
            BaseController::default(),
            FetchPendingMemberCertRequest {
                instance: None,
                trust_domain_id: root.id().0.to_vec(),
                network_local_id: NETWORK_LOCAL_ID.to_owned(),
                applicant_pk: jr.applicant_pk.0.to_vec(),
            },
        )
        .await
        .unwrap();
    assert!(fetched.found);
    let fetched_cert: MemberCert = from_cbor(&fetched.member_cert_cbor).unwrap();
    assert_eq!(fetched_cert, supplied_cert);
}

#[tokio::test]
async fn test_approve_join_request_applies_supplied_network_state_to_root_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let root = TrustDomainRoot::generate();
    write_root_files(dir.path(), &root);
    let instance = root_metadata_only_instance(dir.path(), &root);
    let jr = join_request(&root);
    submit(&instance, &jr).await;

    let supplied_cert = member_cert_for_request(&root, &jr);
    let supplied_state = network_state_with_member(&root, &supplied_cert);
    let api = instance.get_api_rpc_service();
    api.get_trust_join_manage_service()
        .approve_join_request(
            BaseController::default(),
            ApproveJoinRequestRequest {
                instance: None,
                trust_domain_id: root.id().0.to_vec(),
                network_local_id: NETWORK_LOCAL_ID.to_owned(),
                applicant_pk: jr.applicant_pk.0.to_vec(),
                member_cert_cbor: Some(to_canonical_cbor(&supplied_cert)),
                network_state_cbor: Some(to_canonical_cbor(&supplied_state)),
            },
        )
        .await
        .unwrap();

    let fetched = api
        .get_trust_join_manage_service()
        .fetch_pending_member_cert(
            BaseController::default(),
            FetchPendingMemberCertRequest {
                instance: None,
                trust_domain_id: root.id().0.to_vec(),
                network_local_id: NETWORK_LOCAL_ID.to_owned(),
                applicant_pk: jr.applicant_pk.0.to_vec(),
            },
        )
        .await
        .unwrap();
    let fetched_state: SignedNetworkState = from_cbor(&fetched.network_state_cbor).unwrap();
    assert_eq!(fetched_state, supplied_state);
    assert_eq!(fetched_state.details.version, 2);
    assert_eq!(fetched_state.details.payload.member_cert_index.len(), 1);
}

#[tokio::test]
async fn test_approve_join_request_without_daemon_root_key_rejects_daemon_signing() {
    let dir = tempfile::tempdir().unwrap();
    let root = TrustDomainRoot::generate();
    write_root_files(dir.path(), &root);
    let instance = root_metadata_only_instance(dir.path(), &root);
    let jr = join_request(&root);
    submit(&instance, &jr).await;

    let api = instance.get_api_rpc_service();
    let err = api
        .get_trust_join_manage_service()
        .approve_join_request(
            BaseController::default(),
            ApproveJoinRequestRequest {
                instance: None,
                trust_domain_id: root.id().0.to_vec(),
                network_local_id: NETWORK_LOCAL_ID.to_owned(),
                applicant_pk: jr.applicant_pk.0.to_vec(),
                member_cert_cbor: None,
                network_state_cbor: None,
            },
        )
        .await
        .unwrap_err();

    assert!(
        err.to_string().contains("root signing key is not unlocked"),
        "got unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_approve_join_request_unknown_applicant_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let root = TrustDomainRoot::generate();
    write_root_files(dir.path(), &root);
    let instance = root_capable_instance(dir.path(), &root);

    let api = instance.get_api_rpc_service();
    let err = api
        .get_trust_join_manage_service()
        .approve_join_request(
            BaseController::default(),
            ApproveJoinRequestRequest {
                instance: None,
                trust_domain_id: root.id().0.to_vec(),
                network_local_id: NETWORK_LOCAL_ID.to_owned(),
                applicant_pk: vec![0xAB; 32],
                member_cert_cbor: None,
                network_state_cbor: None,
            },
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("no pending join request"),
        "got unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_reject_join_request_removes_and_does_not_sign() {
    let dir = tempfile::tempdir().unwrap();
    let root = TrustDomainRoot::generate();
    write_root_files(dir.path(), &root);
    let instance = root_capable_instance(dir.path(), &root);
    let jr = join_request(&root);
    submit(&instance, &jr).await;

    let api = instance.get_api_rpc_service();
    api.get_trust_join_manage_service()
        .reject_join_request(
            BaseController::default(),
            RejectJoinRequestRequest {
                instance: None,
                trust_domain_id: root.id().0.to_vec(),
                network_local_id: NETWORK_LOCAL_ID.to_owned(),
                applicant_pk: jr.applicant_pk.0.to_vec(),
            },
        )
        .await
        .unwrap();

    let remaining = instance
        .get_join_forward_service()
        .unwrap()
        .pending
        .lock()
        .unwrap()
        .list();
    assert!(remaining.is_empty(), "reject must dequeue the request");

    let fetched = api
        .get_trust_join_manage_service()
        .fetch_pending_member_cert(
            BaseController::default(),
            FetchPendingMemberCertRequest {
                instance: None,
                trust_domain_id: root.id().0.to_vec(),
                network_local_id: NETWORK_LOCAL_ID.to_owned(),
                applicant_pk: jr.applicant_pk.0.to_vec(),
            },
        )
        .await
        .unwrap();
    assert!(
        !fetched.found,
        "rejected request must not produce a signed cert"
    );
}

#[tokio::test]
async fn test_list_pending_join_requests_returns_summary() {
    let dir = tempfile::tempdir().unwrap();
    let root = TrustDomainRoot::generate();
    write_root_files(dir.path(), &root);
    let instance = root_capable_instance(dir.path(), &root);
    let jr = join_request(&root);
    submit(&instance, &jr).await;

    let api = instance.get_api_rpc_service();
    let response = api
        .get_trust_join_manage_service()
        .list_pending_join_requests(
            BaseController::default(),
            ListPendingJoinRequestsRequest {
                instance: None,
                trust_domain_id: Vec::new(),
                network_local_id: String::new(),
            },
        )
        .await
        .unwrap();

    assert_eq!(response.requests.len(), 1);
    let summary = &response.requests[0];
    assert_eq!(summary.applicant_pk, jr.applicant_pk.0.to_vec());
    assert_eq!(summary.trust_domain_id, root.id().0.to_vec());
    assert_eq!(summary.network_local_id, NETWORK_LOCAL_ID);
    assert_eq!(summary.device_label, jr.device_label);
}
