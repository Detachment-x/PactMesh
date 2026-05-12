use std::{pin::Pin, sync::Arc, time::Duration};

use ed25519_dalek::VerifyingKey;
use easytier::{
    common::{PeerId, error::Error as CommonError, new_peer_id},
    peers::peer_rpc::{PeerRpcManager, PeerRpcManagerTransport},
    proto::{
        peer_rpc::{
            ConfigResourceSelector, ConfigSyncRpc, FetchConfigRequest, FetchConfigResponse,
            NetworkStateKey, PendingCertKey, QueryConfigVersionRequest,
            QueryConfigVersionResponse, ResourceVersion, config_resource_selector,
        },
        rpc_types::{self, controller::BaseController},
    },
    trust::{
        Capabilities, MemberCert, NetworkLocalId, NetworkStatePayload, SignedNetworkState,
        SignedTrustDomainMeta, SignKey, TrustDomainPool, TrustDomainRoot, UnsignedMemberCert,
        UnsignedNetworkState, UnsignedTrustDomainMeta, from_cbor, to_canonical_cbor,
    },
    tunnel::{Tunnel, ZCPacketSink, ZCPacketStream, packet_def::ZCPacket, ring::create_ring_tunnel_pair},
};
use futures::{SinkExt, StreamExt};
use pnet::ipnetwork::IpNetwork as IpNet;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};

use easytier::trust::config_sync_client::ConfigSyncClient;
use easytier::trust::config_sync_service::ConfigSyncService;

const NETWORK_NAME: &str = "config-sync-test";
const NETWORK_LOCAL_ID: &str = "office-net";
const CERT_NOT_BEFORE: u64 = 1_715_000_000;
const CERT_EXPIRES_AT: u64 = 4_102_444_800;

struct MockTransport {
    sink: Arc<Mutex<Pin<Box<dyn ZCPacketSink>>>>,
    stream: Arc<Mutex<Pin<Box<dyn ZCPacketStream>>>>,
    my_peer_id: PeerId,
}

#[async_trait::async_trait]
impl PeerRpcManagerTransport for MockTransport {
    fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    async fn send(&self, msg: ZCPacket, _dst_peer_id: PeerId) -> Result<(), CommonError> {
        self.sink.lock().await.send(msg).await.unwrap();
        Ok(())
    }

    async fn recv(&self) -> Result<ZCPacket, CommonError> {
        self.stream.lock().await.next().await.unwrap().map_err(Into::into)
    }
}

fn sample_member_cert(
    root: &TrustDomainRoot,
    sk_self: &SignKey,
    device_label: &str,
    network_state_version_ref: u64,
) -> MemberCert {
    let device_pk =
        VerifyingKey::from_bytes(&sk_self.verify_key().0).expect("verify key bytes valid");
    UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str(NETWORK_LOCAL_ID).unwrap(),
        device_pk,
        device_label: device_label.to_owned(),
        not_before: CERT_NOT_BEFORE,
        expires_at: CERT_EXPIRES_AT,
        capabilities: Capabilities {
            can_relay_data: true,
            can_relay_control: true,
            can_proxy_subnet: vec!["10.0.0.0/24".parse::<IpNet>().unwrap()],
        },
        network_state_version_ref,
        hostname: None,
    }
    .sign(root)
}

fn sample_network_state(root: &TrustDomainRoot, cert: &MemberCert, version: u64) -> SignedNetworkState {
    UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: cert.details.network_local_id.clone(),
        version,
        payload: NetworkStatePayload {
            member_cert_index: Vec::new(),
            revoked_certs: Vec::new(),
            disabled_certs: Vec::new(),
            acl: vec![version as u8],
            routes: Vec::new(),
        },
    }
    .sign(root)
}

fn sample_trust_domain_meta(root: &TrustDomainRoot, version: u64) -> SignedTrustDomainMeta {
    UnsignedTrustDomainMeta {
        trust_domain_id: root.id(),
        version,
        active_relays: Vec::new(),
        outbound_grants: Vec::new(),
    }
    .sign(root)
}

fn build_pool(
    root: &TrustDomainRoot,
    state: Option<SignedNetworkState>,
    meta: Option<SignedTrustDomainMeta>,
) -> Arc<RwLock<TrustDomainPool>> {
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    if let Some(state) = state {
        pool.apply_network_state(state).unwrap();
    }
    if let Some(meta) = meta {
        pool.apply_trust_domain_meta(meta).unwrap();
    }
    Arc::new(RwLock::new(pool))
}

fn state_selector(root: &TrustDomainRoot) -> ConfigResourceSelector {
    ConfigResourceSelector {
        selector: Some(config_resource_selector::Selector::NetworkState(NetworkStateKey {
            trust_domain_id: root.id().0.to_vec(),
            network_local_id: NETWORK_LOCAL_ID.to_owned(),
        })),
    }
}

fn meta_selector(root: &TrustDomainRoot) -> ConfigResourceSelector {
    ConfigResourceSelector {
        selector: Some(config_resource_selector::Selector::TrustDomainMetaId(
            root.id().0.to_vec(),
        )),
    }
}

fn pending_selector(cert: &MemberCert) -> ConfigResourceSelector {
    ConfigResourceSelector {
        selector: Some(config_resource_selector::Selector::PendingCertFor(PendingCertKey {
            trust_domain_id: cert.details.trust_domain_id.0.to_vec(),
            network_local_id: cert.details.network_local_id.as_str().to_owned(),
            applicant_pk: cert.details.device_pk.to_bytes().to_vec(),
        })),
    }
}

fn digest_of<T: minicbor::Encode<()>>(value: &T) -> Vec<u8> {
    Sha256::digest(to_canonical_cbor(value)).to_vec()
}

fn rpc_mgr_pair() -> (Arc<PeerRpcManager>, Arc<PeerRpcManager>, PeerId, PeerId) {
    let (left_tunnel, right_tunnel) = create_ring_tunnel_pair();
    let (left_stream, left_sink) = left_tunnel.split();
    let (right_stream, right_sink) = right_tunnel.split();
    let server_id = new_peer_id();
    let client_id = new_peer_id();

    let server_mgr = Arc::new(PeerRpcManager::new(MockTransport {
        sink: Arc::new(Mutex::new(left_sink)),
        stream: Arc::new(Mutex::new(left_stream)),
        my_peer_id: server_id,
    }));
    let client_mgr = Arc::new(PeerRpcManager::new(MockTransport {
        sink: Arc::new(Mutex::new(right_sink)),
        stream: Arc::new(Mutex::new(right_stream)),
        my_peer_id: client_id,
    }));

    server_mgr.run();
    client_mgr.run();
    (server_mgr, client_mgr, server_id, client_id)
}

#[tokio::test]
async fn test_query_returns_local_versions() {
    let root = TrustDomainRoot::generate();
    let sk_self = SignKey::generate();
    let cert = sample_member_cert(&root, &sk_self, "device-a", 7);
    let state = sample_network_state(&root, &cert, 7);
    let meta = sample_trust_domain_meta(&root, 9);
    let pool = build_pool(&root, Some(state.clone()), Some(meta.clone()));
    let service = ConfigSyncService::new(pool, NETWORK_NAME.to_owned());

    let response = service
        .query_config_version(
            BaseController::default(),
            QueryConfigVersionRequest {
                resources: vec![state_selector(&root), meta_selector(&root)],
            },
        )
        .await
        .unwrap();

    assert_eq!(response.versions.len(), 2);
    assert_eq!(response.versions[0].version, 7);
    assert_eq!(response.versions[0].content_digest, digest_of(&state));
    assert_eq!(response.versions[1].version, 9);
    assert_eq!(response.versions[1].content_digest, digest_of(&meta));
}

#[tokio::test]
async fn test_fetch_network_state_with_valid_caller_cert() {
    let root = TrustDomainRoot::generate();
    let sk_self = SignKey::generate();
    let cert = sample_member_cert(&root, &sk_self, "device-a", 42);
    let state = sample_network_state(&root, &cert, 42);
    let pool = build_pool(&root, Some(state.clone()), None);
    let service = ConfigSyncService::new(pool, NETWORK_NAME.to_owned());

    let response = service
        .fetch_config(
            BaseController::default(),
            FetchConfigRequest {
                selector: Some(state_selector(&root)),
                caller_member_cert_bytes: to_canonical_cbor(&cert),
            },
        )
        .await
        .unwrap();

    let decoded: SignedNetworkState = from_cbor(&response.payload_cbor).unwrap();
    assert_eq!(response.version, 42);
    assert_eq!(decoded, state);
}

#[tokio::test]
async fn test_fetch_network_state_caller_cert_revoked_rejected() {
    let root = TrustDomainRoot::generate();
    let sk_self = SignKey::generate();
    let cert = sample_member_cert(&root, &sk_self, "device-a", 42);
    let mut revoked_state = sample_network_state(&root, &cert, 42);
    revoked_state.details.payload.revoked_certs.push(easytier::trust::RevokedCert {
        cert_fingerprint: cert.fingerprint(),
        revoked_at: CERT_NOT_BEFORE + 10,
        reason_code: easytier::trust::RevocationReason::Removed,
        reason_note: None,
    });
    let revoked_state = revoked_state.details.sign(&root);
    let pool = build_pool(&root, Some(revoked_state), None);
    let service = ConfigSyncService::new(pool, NETWORK_NAME.to_owned());

    let err = service
        .fetch_config(
            BaseController::default(),
            FetchConfigRequest {
                selector: Some(state_selector(&root)),
                caller_member_cert_bytes: to_canonical_cbor(&cert),
            },
        )
        .await
        .unwrap_err();

    assert!(format!("{err:#}").contains("caller member cert verify failed"));
}

#[tokio::test]
async fn test_fetch_network_state_caller_cert_wrong_root_rejected() {
    let root = TrustDomainRoot::generate();
    let wrong_root = TrustDomainRoot::generate();
    let server_sk = SignKey::generate();
    let caller_sk = SignKey::generate();
    let server_cert = sample_member_cert(&root, &server_sk, "server", 9);
    let caller_cert = sample_member_cert(&wrong_root, &caller_sk, "caller", 9);
    let state = sample_network_state(&root, &server_cert, 9);
    let pool = build_pool(&root, Some(state), None);
    let service = ConfigSyncService::new(pool, NETWORK_NAME.to_owned());

    let err = service
        .fetch_config(
            BaseController::default(),
            FetchConfigRequest {
                selector: Some(state_selector(&root)),
                caller_member_cert_bytes: to_canonical_cbor(&caller_cert),
            },
        )
        .await
        .unwrap_err();

    assert!(format!("{err:#}").contains("caller member cert verify failed"));
}

#[tokio::test]
async fn test_fetch_pending_cert_no_caller_cert_required() {
    let root = TrustDomainRoot::generate();
    let sk_self = SignKey::generate();
    let cert = sample_member_cert(&root, &sk_self, "pending-device", 1);
    let pool = build_pool(&root, None, None);
    let service = ConfigSyncService::new(pool, NETWORK_NAME.to_owned());
    service.pending_cert_cache().lock().unwrap().insert(cert.clone());

    let response = service
        .fetch_config(
            BaseController::default(),
            FetchConfigRequest {
                selector: Some(pending_selector(&cert)),
                caller_member_cert_bytes: Vec::new(),
            },
        )
        .await
        .unwrap();

    let decoded: MemberCert = from_cbor(&response.payload_cbor).unwrap();
    assert_eq!(response.version, 1);
    assert_eq!(decoded, cert);
}

#[tokio::test]
async fn test_pull_loop_advances_local_version() {
    let root = TrustDomainRoot::generate();
    let sk_self = SignKey::generate();
    let cert = sample_member_cert(&root, &sk_self, "device-a", 1);
    let server_state = sample_network_state(&root, &cert, 2);
    let client_state = sample_network_state(&root, &cert, 1);
    let server_pool = build_pool(&root, Some(server_state), None);
    let client_pool = build_pool(&root, Some(client_state), None);
    let service = ConfigSyncService::new(server_pool, NETWORK_NAME.to_owned());
    let (server_mgr, client_mgr, server_id, client_id) = rpc_mgr_pair();
    service.register(&server_mgr);

    let client = ConfigSyncClient::new(client_mgr, client_id, client_pool.clone(), NETWORK_NAME.to_owned())
        .with_known_peers(vec![server_id])
        .with_caller_member_cert(&cert)
        .with_tick_intervals(Duration::from_millis(20), Duration::from_secs(60));

    let handle = client.pull_loop();
    tokio::time::sleep(Duration::from_millis(120)).await;
    handle.abort();

    let guard = client_pool.read().await;
    let updated = guard
        .network_state(&root.id(), &cert.details.network_local_id)
        .unwrap();
    assert_eq!(updated.details.version, 2);
}

#[derive(Clone)]
struct CountingDigestMismatchService {
    selector: ConfigResourceSelector,
    fetch_payload: Vec<u8>,
    fetch_count: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait::async_trait]
impl ConfigSyncRpc for CountingDigestMismatchService {
    type Controller = BaseController;

    async fn query_config_version(
        &self,
        _ctrl: Self::Controller,
        _input: QueryConfigVersionRequest,
    ) -> rpc_types::error::Result<QueryConfigVersionResponse> {
        Ok(QueryConfigVersionResponse {
            versions: vec![ResourceVersion {
                selector: Some(self.selector.clone()),
                version: 5,
                content_digest: vec![0xAA; 32],
            }],
        })
    }

    async fn fetch_config(
        &self,
        _ctrl: Self::Controller,
        _input: FetchConfigRequest,
    ) -> rpc_types::error::Result<FetchConfigResponse> {
        self.fetch_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(FetchConfigResponse {
            payload_cbor: self.fetch_payload.clone(),
            version: 5,
        })
    }
}

#[tokio::test]
async fn test_anti_entropy_full_sync_after_120s() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let root = TrustDomainRoot::generate();
    let sk_self = SignKey::generate();
    let cert = sample_member_cert(&root, &sk_self, "device-a", 5);
    let local_state = sample_network_state(&root, &cert, 5);
    let local_pool = build_pool(&root, Some(local_state.clone()), None);
    let (server_mgr, client_mgr, server_id, client_id) = rpc_mgr_pair();
    let fetch_count = Arc::new(AtomicUsize::new(0));
    server_mgr.rpc_server().registry().register(
        easytier::proto::peer_rpc::ConfigSyncRpcServer::new(CountingDigestMismatchService {
            selector: state_selector(&root),
            fetch_payload: to_canonical_cbor(&local_state),
            fetch_count: fetch_count.clone(),
        }),
        NETWORK_NAME,
    );

    let client = ConfigSyncClient::new(client_mgr, client_id, local_pool, NETWORK_NAME.to_owned())
        .with_known_peers(vec![server_id])
        .with_caller_member_cert(&cert);

    client.sync_once(false).await.unwrap();
    assert_eq!(fetch_count.load(Ordering::Relaxed), 0);

    client.sync_once(true).await.unwrap();
    assert_eq!(fetch_count.load(Ordering::Relaxed), 1);
}

#[derive(Clone)]
struct InvalidPayloadService {
    selector: ConfigResourceSelector,
    query_version: u64,
    payload_cbor: Vec<u8>,
}

#[async_trait::async_trait]
impl ConfigSyncRpc for InvalidPayloadService {
    type Controller = BaseController;

    async fn query_config_version(
        &self,
        _ctrl: Self::Controller,
        _input: QueryConfigVersionRequest,
    ) -> rpc_types::error::Result<QueryConfigVersionResponse> {
        Ok(QueryConfigVersionResponse {
            versions: vec![ResourceVersion {
                selector: Some(self.selector.clone()),
                version: self.query_version,
                content_digest: Sha256::digest(&self.payload_cbor).to_vec(),
            }],
        })
    }

    async fn fetch_config(
        &self,
        _ctrl: Self::Controller,
        _input: FetchConfigRequest,
    ) -> rpc_types::error::Result<FetchConfigResponse> {
        Ok(FetchConfigResponse {
            payload_cbor: self.payload_cbor.clone(),
            version: self.query_version,
        })
    }
}

#[tokio::test]
async fn test_signature_invalid_payload_rejected_after_fetch() {
    let root = TrustDomainRoot::generate();
    let sk_self = SignKey::generate();
    let cert = sample_member_cert(&root, &sk_self, "device-a", 1);
    let local_state = sample_network_state(&root, &cert, 1);
    let mut invalid_state = sample_network_state(&root, &cert, 2);
    invalid_state.details.payload.acl.push(0xFF);
    let local_pool = build_pool(&root, Some(local_state), None);
    let (server_mgr, client_mgr, server_id, client_id) = rpc_mgr_pair();
    server_mgr.rpc_server().registry().register(
        easytier::proto::peer_rpc::ConfigSyncRpcServer::new(InvalidPayloadService {
            selector: state_selector(&root),
            query_version: 2,
            payload_cbor: to_canonical_cbor(&invalid_state),
        }),
        NETWORK_NAME,
    );

    let client = ConfigSyncClient::new(client_mgr, client_id, local_pool.clone(), NETWORK_NAME.to_owned())
        .with_known_peers(vec![server_id])
        .with_caller_member_cert(&cert);

    client.sync_once(false).await.unwrap();

    let guard = local_pool.read().await;
    let state = guard
        .network_state(&root.id(), &cert.details.network_local_id)
        .unwrap();
    assert_eq!(state.details.version, 1);
}
