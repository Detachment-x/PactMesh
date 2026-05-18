use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context;
use tokio::{sync::RwLock, task::JoinHandle};

use crate::{
    common::PeerId,
    peers::peer_rpc::PeerRpcManager,
    proto::{
        peer_rpc::{
            ConfigResourceSelector, ConfigSyncRpc, ConfigSyncRpcClientFactory, FetchConfigRequest,
            QueryConfigVersionRequest, ResourceVersion, config_resource_selector,
        },
        rpc_types::controller::BaseController,
    },
    trust::{
        MemberCert, NetworkLocalId, SignedNetworkState, SignedTrustDomainMeta, TrustDomainId,
        TrustDomainPool, from_cbor, receive_network_state, receive_trust_domain_meta,
        to_canonical_cbor,
    },
};

use super::config_sync_service::PendingCertCache;

const DEFAULT_TICK_INTERVAL: Duration = Duration::from_secs(15);
const DEFAULT_FULL_SYNC_INTERVAL: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub struct ConfigSyncClient {
    pub peer_rpc_mgr: Arc<PeerRpcManager>,
    pub my_peer_id: PeerId,
    pub trust_pool: Arc<RwLock<TrustDomainPool>>,
    pub network_name: String,
    known_peers: Arc<RwLock<Vec<PeerId>>>,
    caller_member_cert_bytes: Option<Vec<u8>>,
    network_state_persist_domain_dir: Option<PathBuf>,
    tick_interval: Duration,
    full_sync_interval: Duration,
}

impl ConfigSyncClient {
    pub fn new(
        peer_rpc_mgr: Arc<PeerRpcManager>,
        my_peer_id: PeerId,
        trust_pool: Arc<RwLock<TrustDomainPool>>,
        network_name: String,
    ) -> Self {
        Self {
            peer_rpc_mgr,
            my_peer_id,
            trust_pool,
            network_name,
            known_peers: Arc::new(RwLock::new(Vec::new())),
            caller_member_cert_bytes: None,
            network_state_persist_domain_dir: None,
            tick_interval: DEFAULT_TICK_INTERVAL,
            full_sync_interval: DEFAULT_FULL_SYNC_INTERVAL,
        }
    }

    pub fn with_known_peers(mut self, known_peers: Vec<PeerId>) -> Self {
        self.known_peers = Arc::new(RwLock::new(known_peers));
        self
    }

    pub fn with_caller_member_cert(mut self, cert: &MemberCert) -> Self {
        self.caller_member_cert_bytes = Some(to_canonical_cbor(cert));
        self
    }

    pub fn with_network_state_persist_domain_dir(mut self, domain_dir: PathBuf) -> Self {
        self.network_state_persist_domain_dir = Some(domain_dir);
        self
    }

    pub fn with_tick_intervals(
        mut self,
        tick_interval: Duration,
        full_sync_interval: Duration,
    ) -> Self {
        self.tick_interval = tick_interval;
        self.full_sync_interval = full_sync_interval;
        self
    }

    pub fn pull_loop(self) -> JoinHandle<()> {
        self.pull_loop_with_hook(|| {})
    }

    pub fn pull_loop_with_hook<F>(self, mut after_sync: F) -> JoinHandle<()>
    where
        F: FnMut() + Send + 'static,
    {
        tokio::spawn(async move {
            if self.sync_once(true).await.is_ok() {
                after_sync();
            }
            let mut interval = tokio::time::interval(self.tick_interval);
            let mut last_full_sync = tokio::time::Instant::now();

            loop {
                interval.tick().await;
                let force_full_sync = last_full_sync.elapsed() >= self.full_sync_interval;
                if self.sync_once(force_full_sync).await.is_ok() {
                    after_sync();
                }
                if force_full_sync {
                    last_full_sync = tokio::time::Instant::now();
                }
            }
        })
    }

    pub async fn sync_once(&self, force_full_sync: bool) -> anyhow::Result<()> {
        let selectors = self.local_selectors_snapshot().await;
        if selectors.is_empty() {
            return Ok(());
        }

        for peer_id in self.known_peer_ids().await {
            if peer_id == self.my_peer_id {
                continue;
            }

            let stub = self
                .peer_rpc_mgr
                .rpc_client()
                .scoped_client::<ConfigSyncRpcClientFactory<BaseController>>(
                    self.my_peer_id,
                    peer_id,
                    self.network_name.clone(),
                );

            let response = stub
                .query_config_version(
                    BaseController::default(),
                    QueryConfigVersionRequest {
                        resources: selectors.clone(),
                    },
                )
                .await
                .with_context(|| format!("query_config_version failed for peer {peer_id}"))?;

            for version in response.versions {
                if self.should_fetch(&version, force_full_sync).await?
                    && let Some(selector) = version.selector
                {
                    let _ = self.fetch_and_apply(peer_id, selector).await;
                }
            }
        }

        Ok(())
    }

    async fn known_peer_ids(&self) -> Vec<PeerId> {
        let known = self.known_peers.read().await;
        if !known.is_empty() {
            return known.clone();
        }

        self.peer_rpc_mgr
            .rpc_client()
            .peer_info_table()
            .iter()
            .map(|entry| *entry.key())
            .collect()
    }

    async fn local_selectors_snapshot(&self) -> Vec<ConfigResourceSelector> {
        let pool = self.trust_pool.read().await;
        let mut selectors = Vec::new();

        for trust_domain_id in pool.ids() {
            selectors.push(selector_for_meta(trust_domain_id));
            for network_local_id in pool.network_local_ids(trust_domain_id) {
                selectors.push(selector_for_state(trust_domain_id, &network_local_id));
            }
        }

        selectors
    }

    async fn should_fetch(
        &self,
        remote: &ResourceVersion,
        force_full_sync: bool,
    ) -> anyhow::Result<bool> {
        let Some(selector) = remote.selector.as_ref() else {
            return Ok(false);
        };

        match selector.selector.as_ref() {
            Some(config_resource_selector::Selector::NetworkState(key)) => {
                let trust_domain_id = parse_trust_domain_id(&key.trust_domain_id)?;
                let network_local_id = parse_network_local_id(&key.network_local_id)?;
                let pool = self.trust_pool.read().await;
                let local = pool.network_state(&trust_domain_id, &network_local_id);
                Ok(should_fetch_by_version_and_digest(
                    local.map(|state| {
                        (
                            state.details.version,
                            sha256_bytes(&to_canonical_cbor(state)),
                        )
                    }),
                    remote.version,
                    &remote.content_digest,
                    force_full_sync,
                ))
            }
            Some(config_resource_selector::Selector::TrustDomainMetaId(trust_domain_meta_id)) => {
                let trust_domain_id = parse_trust_domain_id(trust_domain_meta_id)?;
                let pool = self.trust_pool.read().await;
                let local = pool.trust_domain_meta(&trust_domain_id);
                Ok(should_fetch_by_version_and_digest(
                    local
                        .map(|meta| (meta.details.version, sha256_bytes(&to_canonical_cbor(meta)))),
                    remote.version,
                    &remote.content_digest,
                    force_full_sync,
                ))
            }
            Some(config_resource_selector::Selector::PendingCertFor(_)) => Ok(false),
            None => Ok(false),
        }
    }

    async fn fetch_and_apply(
        &self,
        peer_id: PeerId,
        selector: ConfigResourceSelector,
    ) -> anyhow::Result<()> {
        let caller_member_cert_bytes = match selector.selector.as_ref() {
            Some(config_resource_selector::Selector::PendingCertFor(_)) => Vec::new(),
            _ => self.caller_member_cert_bytes.clone().unwrap_or_default(),
        };

        let stub = self
            .peer_rpc_mgr
            .rpc_client()
            .scoped_client::<ConfigSyncRpcClientFactory<BaseController>>(
                self.my_peer_id,
                peer_id,
                self.network_name.clone(),
            );
        let response = stub
            .fetch_config(
                BaseController::default(),
                FetchConfigRequest {
                    selector: Some(selector.clone()),
                    caller_member_cert_bytes,
                },
            )
            .await
            .with_context(|| format!("fetch_config failed for peer {peer_id}"))?;

        match selector.selector.as_ref() {
            Some(config_resource_selector::Selector::NetworkState(key)) => {
                let state: SignedNetworkState = from_cbor(&response.payload_cbor)?;
                let trust_domain_id = parse_trust_domain_id(&key.trust_domain_id)?;
                let network_local_id = parse_network_local_id(&key.network_local_id)?;
                receive_network_state(
                    &self.trust_pool,
                    &trust_domain_id,
                    &network_local_id,
                    state,
                    self.network_state_persist_domain_dir.as_deref(),
                    format!("config-sync:{peer_id}"),
                )
                .await?;
            }
            Some(config_resource_selector::Selector::TrustDomainMetaId(_)) => {
                let meta: SignedTrustDomainMeta = from_cbor(&response.payload_cbor)?;
                let trust_domain_id = parse_trust_domain_id(match selector.selector.as_ref() {
                    Some(config_resource_selector::Selector::TrustDomainMetaId(id)) => id,
                    _ => unreachable!("selector branch already matched trust_domain_meta"),
                })?;
                receive_trust_domain_meta(
                    &self.trust_pool,
                    &trust_domain_id,
                    meta,
                    self.network_state_persist_domain_dir.as_deref(),
                    format!("config-sync:{peer_id}"),
                )
                .await?;
            }
            Some(config_resource_selector::Selector::PendingCertFor(_)) | None => {}
        }

        Ok(())
    }
}

fn selector_for_state(
    trust_domain_id: &TrustDomainId,
    network_local_id: &NetworkLocalId,
) -> ConfigResourceSelector {
    ConfigResourceSelector {
        selector: Some(config_resource_selector::Selector::NetworkState(
            crate::proto::peer_rpc::NetworkStateKey {
                trust_domain_id: trust_domain_id.0.to_vec(),
                network_local_id: network_local_id.as_str().to_owned(),
            },
        )),
    }
}

fn selector_for_meta(trust_domain_id: &TrustDomainId) -> ConfigResourceSelector {
    ConfigResourceSelector {
        selector: Some(config_resource_selector::Selector::TrustDomainMetaId(
            trust_domain_id.0.to_vec(),
        )),
    }
}

fn parse_trust_domain_id(bytes: &[u8]) -> anyhow::Result<TrustDomainId> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("trust_domain_id must be exactly 32 bytes"))?;
    Ok(TrustDomainId(bytes))
}

fn parse_network_local_id(network_local_id: &str) -> anyhow::Result<NetworkLocalId> {
    NetworkLocalId::try_from_str(network_local_id)
        .map_err(|err| anyhow::anyhow!("invalid network_local_id '{network_local_id}': {err}"))
}

fn should_fetch_by_version_and_digest(
    local: Option<(u64, Vec<u8>)>,
    remote_version: u64,
    remote_digest: &[u8],
    force_full_sync: bool,
) -> bool {
    match local {
        None => remote_version > 0,
        Some((local_version, _local_digest)) if remote_version > local_version => true,
        Some((local_version, local_digest)) => {
            force_full_sync
                && remote_version == local_version
                && remote_digest != local_digest.as_slice()
        }
    }
}

fn sha256_bytes(bytes: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    Sha256::digest(bytes).to_vec()
}

#[allow(dead_code)]
fn _assert_future_pending_cache(_: &PendingCertCache) {}
