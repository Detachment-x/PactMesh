use std::{collections::HashMap, sync::{Arc, Mutex, Weak}};

use easytier::{
    common::{PeerId, error::Error as CommonError, new_peer_id},
    peers::peer_rpc::{PeerRpcManager, PeerRpcManagerTransport},
    proto::{
        peer_rpc::{
            ConfigResourceSelector, ConfigSyncRpc, FetchConfigRequest,
            ForwardJoinRequestRequest, JoinForwardRpc, PendingCertKey, config_resource_selector,
        },
        rpc_types::controller::BaseController,
    },
    trust::{
        JoinRequest, MemberCert, NetworkLocalId, SignKey, TrustDomainPool,
        TrustDomainRoot, config_sync_service::ConfigSyncService,
        join_dedup::JoinDedup, join_forward_service::JoinForwardService,
        pending_cert_queue::PendingCertQueue, from_cbor, to_canonical_cbor,
    },
    tunnel::packet_def::ZCPacket,
};
use tokio::sync::{RwLock, mpsc};

const NETWORK_NAME: &str = "join-forward-test";
const NETWORK_LOCAL_ID: &str = "office-net";

#[derive(Clone, Default)]
struct RpcBus {
    peers: Arc<Mutex<HashMap<PeerId, mpsc::Sender<ZCPacket>>>>,
}

impl RpcBus {
    fn register(&self, peer_id: PeerId) -> mpsc::Receiver<ZCPacket> {
        let (tx, rx) = mpsc::channel(64);
        self.peers.lock().unwrap().insert(peer_id, tx);
        rx
    }

    async fn send(&self, dst_peer_id: PeerId, msg: ZCPacket) -> Result<(), CommonError> {
        let sender = self
            .peers
            .lock()
            .unwrap()
            .get(&dst_peer_id)
            .cloned()
            .ok_or(CommonError::NotFound)?;
        sender.send(msg).await.map_err(|_| CommonError::NotFound)
    }
}

struct BusTransport {
    my_peer_id: PeerId,
    bus: RpcBus,
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<ZCPacket>>>,
}

#[async_trait::async_trait]
impl PeerRpcManagerTransport for BusTransport {
    fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    async fn send(&self, msg: ZCPacket, dst_peer_id: PeerId) -> Result<(), CommonError> {
        self.bus.send(dst_peer_id, msg).await
    }

    async fn recv(&self) -> Result<ZCPacket, CommonError> {
        self.rx.lock().await.recv().await.ok_or(CommonError::NotFound)
    }
}

fn sample_applicant_sk(seed: u8) -> SignKey {
    SignKey::from_bytes([seed; 32])
}

fn sample_join_request(root: &TrustDomainRoot, applicant_seed: u8) -> JoinRequest {
    JoinRequest::new_signed(
        root.id(),
        NetworkLocalId::try_from_str(NETWORK_LOCAL_ID).unwrap(),
        &sample_applicant_sk(applicant_seed),
        format!("device-{applicant_seed}"),
        "pending".to_owned(),
    )
}

fn build_pool(root: &TrustDomainRoot) -> Arc<RwLock<TrustDomainPool>> {
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    Arc::new(RwLock::new(pool))
}

fn pending_selector(jr: &JoinRequest) -> ConfigResourceSelector {
    ConfigResourceSelector {
        selector: Some(config_resource_selector::Selector::PendingCertFor(PendingCertKey {
            trust_domain_id: jr.trust_domain_id.0.to_vec(),
            network_local_id: jr.network_local_id.as_str().to_owned(),
            applicant_pk: jr.applicant_pk.0.to_vec(),
        })),
    }
}

fn request_for(jr: &JoinRequest, ttl: u32, seen_node_pks: Vec<Vec<u8>>) -> ForwardJoinRequestRequest {
    ForwardJoinRequestRequest {
        inner_cbor: to_canonical_cbor(jr),
        ttl,
        seen_node_pks,
    }
}

fn build_pending_queue(root: &TrustDomainRoot) -> Arc<Mutex<PendingCertQueue>> {
    Arc::new(Mutex::new(PendingCertQueue::new(root.clone())))
}

fn build_service(
    root: &TrustDomainRoot,
    peer_rpc_mgr: Arc<PeerRpcManager>,
    my_peer_id: PeerId,
    my_fingerprint: [u8; 32],
    am_root: bool,
) -> (JoinForwardService, Arc<Mutex<PendingCertQueue>>) {
    let pending = build_pending_queue(root);
    let service = JoinForwardService::new(
        Arc::new(Mutex::new(JoinDedup::new())),
        pending.clone(),
        my_fingerprint,
        if am_root {
            vec![(
                root.id(),
                NetworkLocalId::try_from_str(NETWORK_LOCAL_ID).unwrap(),
            )]
        } else {
            Vec::new()
        },
        Weak::new(),
        peer_rpc_mgr,
        my_peer_id,
        NETWORK_NAME.to_owned(),
    );
    (service, pending)
}

fn make_rpc_mgr(bus: &RpcBus, peer_id: PeerId) -> Arc<PeerRpcManager> {
    let mgr = Arc::new(PeerRpcManager::new(BusTransport {
        my_peer_id: peer_id,
        bus: bus.clone(),
        rx: Arc::new(tokio::sync::Mutex::new(bus.register(peer_id))),
    }));
    mgr.run();
    mgr
}

#[tokio::test]
async fn test_join_request_signature_invalid_dropped() {
    let root = TrustDomainRoot::generate();
    let peer_id = new_peer_id();
    let rpc_mgr = make_rpc_mgr(&RpcBus::default(), peer_id);
    let (service, pending) = build_service(&root, rpc_mgr, peer_id, [0x11; 32], true);
    let mut jr = sample_join_request(&root, 11);
    jr.device_label.push_str("-tampered");

    let response = service
        .forward_join_request(BaseController::default(), request_for(&jr, 6, Vec::new()))
        .await
        .unwrap();

    assert_eq!(response.hop_count, 0);
    assert!(pending.lock().unwrap().list().is_empty());
}

#[tokio::test]
async fn test_dedup_blocks_replay() {
    let root = TrustDomainRoot::generate();
    let peer_id = new_peer_id();
    let rpc_mgr = make_rpc_mgr(&RpcBus::default(), peer_id);
    let (service, pending) = build_service(&root, rpc_mgr, peer_id, [0x22; 32], true);
    let jr = sample_join_request(&root, 12);
    let req = request_for(&jr, 6, Vec::new());

    service
        .forward_join_request(BaseController::default(), req.clone())
        .await
        .unwrap();
    service
        .forward_join_request(BaseController::default(), req)
        .await
        .unwrap();

    assert_eq!(pending.lock().unwrap().list().len(), 1);
}

#[tokio::test]
async fn test_seen_node_pks_prevents_loop() {
    let root = TrustDomainRoot::generate();
    let peer_id = new_peer_id();
    let rpc_mgr = make_rpc_mgr(&RpcBus::default(), peer_id);
    let (service, pending) = build_service(&root, rpc_mgr, peer_id, [0x33; 32], true);
    let jr = sample_join_request(&root, 13);

    let response = service
        .forward_join_request(
            BaseController::default(),
            request_for(&jr, 6, vec![vec![0x33; 32]]),
        )
        .await
        .unwrap();

    assert_eq!(response.hop_count, 0);
    assert!(pending.lock().unwrap().list().is_empty());
}

#[tokio::test]
async fn test_ttl_zero_stops_forwarding() {
    let bus = RpcBus::default();
    let root = TrustDomainRoot::generate();
    let relay_peer_id = new_peer_id();
    let target_peer_id = new_peer_id();
    let relay_mgr = make_rpc_mgr(&bus, relay_peer_id);
    let target_mgr = make_rpc_mgr(&bus, target_peer_id);
    let (relay_service, _) = build_service(&root, relay_mgr, relay_peer_id, [0x44; 32], false);
    let relay_service = relay_service.with_known_peers(vec![target_peer_id]);
    let (target_service, target_pending) = build_service(&root, target_mgr.clone(), target_peer_id, [0x55; 32], true);
    target_service.register(&target_mgr);
    let jr = sample_join_request(&root, 14);

    let response = relay_service
        .forward_join_request(BaseController::default(), request_for(&jr, 0, Vec::new()))
        .await
        .unwrap();

    assert_eq!(response.hop_count, 0);
    assert!(target_pending.lock().unwrap().list().is_empty());
}

#[tokio::test]
async fn test_root_device_enqueues_to_pending() {
    let root = TrustDomainRoot::generate();
    let peer_id = new_peer_id();
    let rpc_mgr = make_rpc_mgr(&RpcBus::default(), peer_id);
    let (service, pending) = build_service(&root, rpc_mgr, peer_id, [0x66; 32], true);
    let jr = sample_join_request(&root, 15);

    service
        .forward_join_request(BaseController::default(), request_for(&jr, 6, Vec::new()))
        .await
        .unwrap();

    let queued = pending.lock().unwrap().list();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0], jr);
}

#[tokio::test]
async fn test_non_root_forwards_to_neighbors_excluding_source() {
    let bus = RpcBus::default();
    let root = TrustDomainRoot::generate();
    let relay_peer_id = new_peer_id();
    let target_peer_id = new_peer_id();
    let relay_mgr = make_rpc_mgr(&bus, relay_peer_id);
    let target_mgr = make_rpc_mgr(&bus, target_peer_id);

    let (relay_service, _) = build_service(&root, relay_mgr, relay_peer_id, [0x77; 32], false);
    let relay_service = relay_service.with_known_peers(vec![target_peer_id]);
    let (target_service, target_pending) = build_service(&root, target_mgr.clone(), target_peer_id, [0x88; 32], true);
    target_service.register(&target_mgr);

    let jr = sample_join_request(&root, 16);
    let response = relay_service
        .forward_join_request(BaseController::default(), request_for(&jr, 1, Vec::new()))
        .await
        .unwrap();

    assert!(response.hop_count >= 1);
    let queued = target_pending.lock().unwrap().list();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0], jr);
}

#[tokio::test]
async fn test_pending_cert_after_approve_is_fetchable_via_config_sync() {
    let root = TrustDomainRoot::generate();
    let service = ConfigSyncService::new(build_pool(&root), NETWORK_NAME.to_owned());
    let pending_cache = service.pending_cert_cache();
    let mut queue = PendingCertQueue::new(root.clone()).with_pending_cert_cache(pending_cache);
    let jr = sample_join_request(&root, 17);
    queue.enqueue(jr.clone());

    let cert = queue.approve(&jr.applicant_pk.0);
    let response = service
        .fetch_config(
            BaseController::default(),
            FetchConfigRequest {
                selector: Some(pending_selector(&jr)),
                caller_member_cert_bytes: Vec::new(),
            },
        )
        .await
        .unwrap();
    let decoded: MemberCert = from_cbor(&response.payload_cbor).unwrap();

    assert_eq!(decoded, cert);
}
