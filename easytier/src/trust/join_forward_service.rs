use std::{panic::{AssertUnwindSafe, catch_unwind}, sync::{Arc, Mutex, Weak}};

use tokio::sync::RwLock;

use crate::{
    common::PeerId,
    peers::{peer_manager::PeerManager, peer_rpc::PeerRpcManager},
    proto::{
        peer_rpc::{
            ForwardJoinRequestRequest, ForwardJoinRequestResponse, JoinForwardRpc,
            JoinForwardRpcClientFactory, JoinForwardRpcServer,
        },
        rpc_types::{self, controller::BaseController},
    },
    trust::{JoinRequest, NetworkLocalId, TrustDomainId, from_cbor},
};

use super::{join_dedup::{DupError, JoinDedup}, pending_cert_queue::PendingCertQueue};

#[derive(Clone)]
pub struct JoinForwardService {
    pub dedup: Arc<Mutex<JoinDedup>>,
    pub pending: Arc<Mutex<PendingCertQueue>>,
    pub my_pk_fingerprint: [u8; 32],
    pub am_root_for: Vec<(TrustDomainId, NetworkLocalId)>,
    pub peer_mgr: Weak<PeerManager>,
    pub peer_rpc_mgr: Arc<PeerRpcManager>,
    pub my_peer_id: PeerId,
    pub network_name: String,
    known_peers: Arc<RwLock<Vec<PeerId>>>,
}

impl JoinForwardService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dedup: Arc<Mutex<JoinDedup>>,
        pending: Arc<Mutex<PendingCertQueue>>,
        my_pk_fingerprint: [u8; 32],
        am_root_for: Vec<(TrustDomainId, NetworkLocalId)>,
        peer_mgr: Weak<PeerManager>,
        peer_rpc_mgr: Arc<PeerRpcManager>,
        my_peer_id: PeerId,
        network_name: String,
    ) -> Self {
        Self {
            dedup,
            pending,
            my_pk_fingerprint,
            am_root_for,
            peer_mgr,
            peer_rpc_mgr,
            my_peer_id,
            network_name,
            known_peers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn with_known_peers(mut self, known_peers: Vec<PeerId>) -> Self {
        self.known_peers = Arc::new(RwLock::new(known_peers));
        self
    }

    pub fn register(&self, peer_rpc_mgr: &PeerRpcManager) {
        peer_rpc_mgr.rpc_server().registry().register(
            JoinForwardRpcServer::new(self.clone()),
            &self.network_name,
        );
    }

    fn is_root_for(&self, jr: &JoinRequest) -> bool {
        self.am_root_for.iter().any(|(trust_domain_id, network_local_id)| {
            trust_domain_id == &jr.trust_domain_id && network_local_id == &jr.network_local_id
        })
    }

    async fn neighbor_peer_ids(&self) -> Vec<PeerId> {
        if let Some(peer_mgr) = self.peer_mgr.upgrade() {
            return peer_mgr
                .get_peer_map()
                .list_peers_with_conn()
                .await
                .into_iter()
                .filter(|peer_id| *peer_id != self.my_peer_id)
                .collect();
        }

        self.known_peers
            .read()
            .await
            .iter()
            .copied()
            .filter(|peer_id| *peer_id != self.my_peer_id)
            .collect()
    }

    fn decode_verified_join(req: &ForwardJoinRequestRequest) -> Option<JoinRequest> {
        let jr: JoinRequest = from_cbor(&req.inner_cbor).ok()?;
        let verified = catch_unwind(AssertUnwindSafe(|| jr.verify_self_signature()));
        match verified {
            Ok(Ok(())) => Some(jr),
            Ok(Err(_)) | Err(_) => None,
        }
    }

    async fn forward_to_neighbors(&self, req: ForwardJoinRequestRequest) -> u32 {
        let mut hop_count = 0u32;
        for peer_id in self.neighbor_peer_ids().await {
            let stub = self
                .peer_rpc_mgr
                .rpc_client()
                .scoped_client::<JoinForwardRpcClientFactory<BaseController>>(
                    self.my_peer_id,
                    peer_id,
                    self.network_name.clone(),
                );
            if let Ok(resp) = stub
                .forward_join_request(BaseController::default(), req.clone())
                .await
            {
                hop_count = hop_count.saturating_add(1).saturating_add(resp.hop_count);
            }
        }
        hop_count
    }
}

#[async_trait::async_trait]
impl JoinForwardRpc for JoinForwardService {
    type Controller = BaseController;

    async fn forward_join_request(
        &self,
        _ctrl: Self::Controller,
        req: ForwardJoinRequestRequest,
    ) -> rpc_types::error::Result<ForwardJoinRequestResponse> {
        let Some(jr) = Self::decode_verified_join(&req) else {
            return Ok(ForwardJoinRequestResponse { hop_count: 0 });
        };

        if req
            .seen_node_pks
            .iter()
            .any(|fingerprint| fingerprint.as_slice() == self.my_pk_fingerprint)
        {
            return Ok(ForwardJoinRequestResponse { hop_count: 0 });
        }

        if matches!(
            self.dedup
                .lock()
                .unwrap()
                .record_or_drop(&jr.applicant_pk.0, &jr.nonce),
            Err(DupError::Duplicate)
        ) {
            return Ok(ForwardJoinRequestResponse { hop_count: 0 });
        }

        if self.is_root_for(&jr) {
            self.pending.lock().unwrap().enqueue(jr);
            return Ok(ForwardJoinRequestResponse { hop_count: 0 });
        }

        if req.ttl == 0 {
            return Ok(ForwardJoinRequestResponse { hop_count: 0 });
        }

        let mut seen_node_pks = req.seen_node_pks.clone();
        seen_node_pks.push(self.my_pk_fingerprint.to_vec());
        let next_req = ForwardJoinRequestRequest {
            inner_cbor: req.inner_cbor,
            ttl: req.ttl - 1,
            seen_node_pks,
        };

        Ok(ForwardJoinRequestResponse {
            hop_count: self.forward_to_neighbors(next_req).await,
        })
    }
}
