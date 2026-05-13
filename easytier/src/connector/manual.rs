use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{Arc, Weak},
};

use dashmap::{DashMap, DashSet};
use tokio::{sync::mpsc, task::JoinSet, time::timeout};

const LOCAL_PEER_CACHE_SCHEMA_VERSION: u32 = 1;
const LOCAL_PEER_CACHE_TTL_SECS: u64 = 30 * 24 * 60 * 60;
const LOCAL_PEER_CACHE_MAX_FAILURES: u32 = 3;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct LocalPeerCacheFile {
    schema_version: u32,
    entries: Vec<LocalPeerCacheEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct LocalPeerCacheEntry {
    url: String,
    peer_id: PeerId,
    trust_domain_id: String,
    network_local_id: String,
    last_success: u64,
    failures: u32,
}

use crate::{
    common::{PeerId, config::PeerConfig, dns::socket_addrs, join_joinset_background},
    peers::peer_conn::PeerConnId,
    proto::{
        api::instance::{
            Connector, ConnectorManageRpc, ConnectorStatus, ListConnectorRequest,
            ListConnectorResponse,
        },
        rpc_types::{self, controller::BaseController},
    },
    tunnel::{IpVersion, TunnelConnector},
    utils::weak_upgrade,
};

use crate::{
    common::{
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        netns::NetNS,
    },
    peers::peer_manager::PeerManager,
    trust::{BorrowedRelayProof, BorrowedRelayResolver, NetworkBootstrap},
    use_global_var,
};

fn peer_hint_urls_from_state(state: &crate::trust::SignedNetworkState, now: u64) -> Vec<url::Url> {
    let mut urls = state
        .details
        .payload
        .peer_hints
        .iter()
        .filter(|hint| hint.expires_at.is_none_or(|expires_at| expires_at > now))
        .filter_map(|hint| match url::Url::parse(&hint.url) {
            Ok(url) => Some(url),
            Err(err) => {
                tracing::warn!(source = "signed-peer-hint", url = %hint.url, ?err, "invalid peer hint URL");
                None
            }
        })
        .collect::<Vec<_>>();
    urls.sort();
    urls.dedup();
    urls
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

fn local_peer_cache_base_dir() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(xdg).join("privateNetwork/peer-cache"));
    }
    std::env::var("HOME")
        .ok()
        .map(|home| PathBuf::from(home).join(".config/privateNetwork/peer-cache"))
}

fn local_peer_cache_path(trust_domain_id: &str, network_local_id: &str) -> Option<PathBuf> {
    Some(
        local_peer_cache_base_dir()?
            .join(trust_domain_id)
            .join(format!("{network_local_id}.json")),
    )
}

fn read_local_peer_cache(path: &std::path::Path) -> LocalPeerCacheFile {
    let Ok(text) = std::fs::read_to_string(path) else {
        return LocalPeerCacheFile {
            schema_version: LOCAL_PEER_CACHE_SCHEMA_VERSION,
            entries: Vec::new(),
        };
    };
    serde_json::from_str(&text).unwrap_or_else(|err| {
        tracing::warn!(source = "local-peer-cache", path = %path.display(), ?err, "failed to read local peer cache");
        LocalPeerCacheFile {
            schema_version: LOCAL_PEER_CACHE_SCHEMA_VERSION,
            entries: Vec::new(),
        }
    })
}

fn write_local_peer_cache(path: &std::path::Path, cache: &LocalPeerCacheFile) {
    let Some(parent) = path.parent() else {
        return;
    };
    if let Err(err) = std::fs::create_dir_all(parent) {
        tracing::warn!(source = "local-peer-cache", path = %parent.display(), ?err, "failed to create local peer cache directory");
        return;
    }
    let Ok(text) = serde_json::to_string_pretty(cache) else {
        return;
    };
    if let Err(err) = std::fs::write(path, text) {
        tracing::warn!(source = "local-peer-cache", path = %path.display(), ?err, "failed to write local peer cache");
    }
}

fn valid_local_peer_cache_urls(
    cache: &LocalPeerCacheFile,
    trust_domain_id: &str,
    network_local_id: &str,
    now: u64,
) -> Vec<url::Url> {
    let mut urls = cache
        .entries
        .iter()
        .filter(|entry| entry.trust_domain_id == trust_domain_id)
        .filter(|entry| entry.network_local_id == network_local_id)
        .filter(|entry| entry.failures < LOCAL_PEER_CACHE_MAX_FAILURES)
        .filter(|entry| now.saturating_sub(entry.last_success) <= LOCAL_PEER_CACHE_TTL_SECS)
        .filter_map(|entry| url::Url::parse(&entry.url).ok())
        .collect::<Vec<_>>();
    urls.sort();
    urls.dedup();
    urls
}

use super::create_connector_by_url;

type ConnectorMap = Arc<DashSet<url::Url>>;

#[derive(Debug, Clone)]
struct ReconnResult {
    dead_url: String,
    peer_id: PeerId,
    conn_id: PeerConnId,
}

struct ConnectorManagerData {
    connectors: ConnectorMap,
    reconnecting: DashSet<url::Url>,
    peer_manager: Weak<PeerManager>,
    alive_conn_urls: Arc<DashSet<url::Url>>,
    borrowed_failures: DashMap<url::Url, u32>,
    // user removed connector urls
    removed_conn_urls: Arc<DashSet<url::Url>>,
    net_ns: NetNS,
    global_ctx: ArcGlobalCtx,
}

pub struct ManualConnectorManager {
    global_ctx: ArcGlobalCtx,
    data: Arc<ConnectorManagerData>,
    tasks: JoinSet<()>,
}

impl ManualConnectorManager {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Self {
        let connectors = Arc::new(DashSet::new());
        let tasks = JoinSet::new();

        let mut ret = Self {
            global_ctx: global_ctx.clone(),
            data: Arc::new(ConnectorManagerData {
                connectors,
                reconnecting: DashSet::new(),
                peer_manager: Arc::downgrade(&peer_manager),
                alive_conn_urls: Arc::new(DashSet::new()),
                borrowed_failures: DashMap::new(),
                removed_conn_urls: Arc::new(DashSet::new()),
                net_ns: global_ctx.net_ns.clone(),
                global_ctx,
            }),
            tasks,
        };

        ret.tasks
            .spawn(Self::conn_mgr_reconn_routine(ret.data.clone()));

        ret
    }

    pub fn add_connector<T>(&self, connector: T)
    where
        T: TunnelConnector + 'static,
    {
        tracing::info!("add_connector: {}", connector.remote_url());
        self.data.connectors.insert(connector.remote_url());
    }

    pub async fn add_connector_by_url(&self, url: url::Url) -> Result<(), Error> {
        self.data.connectors.insert(url);
        Ok(())
    }

    pub async fn add_connector_peer_config(&self, peer: PeerConfig) -> Result<(), Error> {
        self.data.connectors.insert(peer.uri);
        Ok(())
    }

    pub async fn remove_connector(&self, url: url::Url) -> Result<(), Error> {
        tracing::info!("remove_connector: {}", url);
        let url = url.into();
        if !self
            .list_connectors()
            .await
            .iter()
            .any(|x| x.url.as_ref() == Some(&url))
        {
            return Err(Error::NotFound);
        }
        self.data.removed_conn_urls.insert(url.into());
        Ok(())
    }

    pub async fn clear_connectors(&self) {
        self.list_connectors().await.iter().for_each(|x| {
            if let Some(url) = &x.url {
                self.data.removed_conn_urls.insert(url.clone().into());
            }
        });
    }

    pub async fn list_connectors(&self) -> Vec<Connector> {
        let dead_urls: BTreeSet<url::Url> = Self::collect_dead_conns(self.data.clone())
            .await
            .into_iter()
            .collect();

        let mut ret = Vec::new();

        for item in self.data.connectors.iter() {
            let conn_url = item.key().clone();
            let mut status = ConnectorStatus::Connected;
            if dead_urls.contains(&conn_url) {
                status = ConnectorStatus::Disconnected;
            }
            ret.insert(
                0,
                Connector {
                    url: Some(conn_url.into()),
                    status: status.into(),
                },
            );
        }

        let reconnecting_urls: BTreeSet<url::Url> =
            self.data.reconnecting.iter().map(|x| x.clone()).collect();

        for conn_url in reconnecting_urls {
            ret.insert(
                0,
                Connector {
                    url: Some(conn_url.into()),
                    status: ConnectorStatus::Connecting.into(),
                },
            );
        }

        ret
    }

    async fn conn_mgr_reconn_routine(data: Arc<ConnectorManagerData>) {
        tracing::warn!("conn_mgr_routine started");
        let mut reconn_interval = tokio::time::interval(std::time::Duration::from_millis(
            use_global_var!(MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS),
        ));
        let (reconn_result_send, mut reconn_result_recv) = mpsc::channel(100);
        let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "connector_reconnect_tasks".to_string());

        loop {
            tokio::select! {
                _ = reconn_interval.tick() => {
                    let dead_urls = Self::collect_dead_conns(data.clone()).await;
                    if dead_urls.is_empty() {
                        continue;
                    }
                    for dead_url in dead_urls {
                        let data_clone = data.clone();
                        let sender = reconn_result_send.clone();
                        data.connectors.remove(&dead_url).unwrap();
                        let insert_succ = data.reconnecting.insert(dead_url.clone());
                        assert!(insert_succ);

                        tasks.lock().unwrap().spawn(async move {
                            let reconn_ret = Self::conn_reconnect(data_clone.clone(), dead_url.clone() ).await;
                            let _ = sender.send(reconn_ret).await;

                            data_clone.reconnecting.remove(&dead_url).unwrap();
                            data_clone.connectors.insert(dead_url.clone());
                        });
                    }
                    tracing::info!("reconn_interval tick, done");
                }

                ret = reconn_result_recv.recv() => {
                    tracing::warn!("reconn_tasks done, reconn result: {:?}", ret);
                }
            }
        }
    }

    fn handle_remove_connector(data: Arc<ConnectorManagerData>) {
        let remove_later = DashSet::new();
        for it in data.removed_conn_urls.iter() {
            let url = it.key();
            if data.connectors.remove(url).is_some() {
                data.borrowed_failures.remove(url);
                data.alive_conn_urls.remove(url);
                tracing::warn!("connector: {}, removed", url);
                continue;
            } else if data.reconnecting.contains(url) {
                tracing::warn!("connector: {}, reconnecting, remove later.", url);
                remove_later.insert(url.clone());
                continue;
            } else {
                tracing::warn!("connector: {}, not found", url);
            }
        }
        data.removed_conn_urls.clear();
        for it in remove_later.iter() {
            data.removed_conn_urls.insert(it.key().clone());
        }
    }

    async fn collect_dead_conns(data: Arc<ConnectorManagerData>) -> BTreeSet<url::Url> {
        Self::handle_remove_connector(data.clone());
        let mut ret = BTreeSet::new();
        let Some(pm) = data.peer_manager.upgrade() else {
            tracing::warn!("peer manager is gone, exit");
            return ret;
        };
        for url in data.connectors.iter().map(|x| x.key().clone()) {
            if data.alive_conn_urls.contains(&url) {
                continue;
            }
            if !pm.get_peer_map().is_client_url_alive(&url)
                && !pm
                    .get_foreign_network_client()
                    .get_peer_map()
                    .is_client_url_alive(&url)
            {
                ret.insert(url.clone());
            } else {
                data.borrowed_failures.remove(&url);
            }
        }
        ret
    }

    async fn conn_reconnect_with_ip_version(
        data: Arc<ConnectorManagerData>,
        dead_url: String,
        ip_version: IpVersion,
    ) -> Result<ReconnResult, Error> {
        let connector =
            create_connector_by_url(&dead_url, &data.global_ctx.clone(), ip_version).await?;

        data.global_ctx
            .issue_event(GlobalCtxEvent::Connecting(connector.remote_url()));
        tracing::info!("reconnect try connect... conn: {:?}", connector);
        let Some(pm) = data.peer_manager.upgrade() else {
            return Err(Error::AnyhowError(anyhow::anyhow!(
                "peer manager is gone, cannot reconnect"
            )));
        };

        let (peer_id, conn_id) = pm.try_direct_connect(connector).await?;
        tracing::info!("reconnect succ: {} {} {}", peer_id, conn_id, dead_url);
        if let Ok(url) = url::Url::parse(&dead_url) {
            Self::record_local_peer_cache_success(data, &url, peer_id).await;
        }
        Ok(ReconnResult {
            dead_url,
            peer_id,
            conn_id,
        })
    }

    fn load_target_bootstrap(path: &std::path::Path) -> Result<NetworkBootstrap, Error> {
        let bytes = std::fs::read(path).map_err(|err| Error::AnyhowError(err.into()))?;
        if let Ok(text) = std::str::from_utf8(&bytes)
            && let Ok(bootstrap) = NetworkBootstrap::from_pem(text)
        {
            return Ok(bootstrap);
        }
        crate::trust::from_cbor(&bytes)
            .map_err(|err| Error::AnyhowError(anyhow::anyhow!(err.to_string())))
    }

    fn peer_config_for_url(data: &ConnectorManagerData, dead_url: &url::Url) -> Option<PeerConfig> {
        data.global_ctx
            .config
            .get_peers()
            .into_iter()
            .find(|peer| peer.uri == *dead_url)
    }

    fn mark_borrowed_conn_alive_until_close(
        data: Arc<ConnectorManagerData>,
        dead_url: url::Url,
        close_notifier: Arc<crate::peers::peer_conn::PeerConnCloseNotify>,
    ) {
        data.alive_conn_urls.insert(dead_url.clone());
        tokio::spawn(async move {
            if let Some(mut waiter) = close_notifier.get_waiter().await {
                let _ = waiter.recv().await;
            }
            data.alive_conn_urls.remove(&dead_url);
        });
    }

    async fn try_borrowed_relay_connect(
        data: Arc<ConnectorManagerData>,
        dead_url: &url::Url,
    ) -> Result<ReconnResult, Error> {
        let Some(peer_cfg) = Self::peer_config_for_url(&data, dead_url) else {
            return Err(Error::AnyhowError(anyhow::anyhow!(
                "connector target not found for {}",
                dead_url
            )));
        };
        let Some(target_bootstrap_path) = peer_cfg.target_bootstrap_path else {
            return Err(Error::AnyhowError(anyhow::anyhow!(
                "target bootstrap path is not configured for {}",
                dead_url
            )));
        };

        let bootstrap = Self::load_target_bootstrap(&target_bootstrap_path)?;
        let Some(pm) = data.peer_manager.upgrade() else {
            return Err(Error::AnyhowError(anyhow::anyhow!(
                "peer manager is gone, cannot reconnect"
            )));
        };
        let Some(trust_pool) = pm.get_trust_pool() else {
            return Err(Error::AnyhowError(anyhow::anyhow!(
                "trust pool is not configured"
            )));
        };
        let candidates = {
            let pool = trust_pool.read().await;
            BorrowedRelayResolver::candidates_for_target(&bootstrap.trust_domain_id, &pool)
        };
        let candidate = candidates.into_iter().next().ok_or_else(|| {
            Error::AnyhowError(anyhow::anyhow!(
                "no borrowed relay candidates for {}",
                bootstrap.trust_domain_id
            ))
        })?;

        let trust_ctx =
            data.global_ctx.get_trust_context().await.ok_or_else(|| {
                Error::AnyhowError(anyhow::anyhow!("trust context not configured"))
            })?;
        let borrowed_proof = BorrowedRelayProof {
            trust_domain_id: trust_ctx.trust_domain_id,
            member_cert: trust_ctx.member_cert.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_secs(),
        };

        let connector = create_connector_by_url(
            candidate.relay_url.as_str(),
            &data.global_ctx.clone(),
            IpVersion::Both,
        )
        .await?;
        data.global_ctx
            .issue_event(GlobalCtxEvent::Connecting(connector.remote_url()));
        let (peer_id, conn_id, close_notifier) = pm
            .try_direct_connect_with_borrowed_proof(connector, borrowed_proof)
            .await?;
        pm.mark_borrowed_relay_used(None, peer_id, candidate.foreign_trust_domain_id);
        Self::mark_borrowed_conn_alive_until_close(data, dead_url.clone(), close_notifier);
        Ok(ReconnResult {
            dead_url: dead_url.to_string(),
            peer_id,
            conn_id,
        })
    }

    async fn signed_peer_hint_urls(data: Arc<ConnectorManagerData>) -> Vec<url::Url> {
        let Some(pm) = data.peer_manager.upgrade() else {
            tracing::warn!(source = "signed-peer-hint", "peer manager is gone");
            return Vec::new();
        };
        let Some(trust_pool) = pm.get_trust_pool() else {
            tracing::debug!(source = "signed-peer-hint", "trust pool is not configured");
            return Vec::new();
        };
        let Some(trust_ctx) = data.global_ctx.get_trust_context().await else {
            tracing::debug!(
                source = "signed-peer-hint",
                "trust context is not configured"
            );
            return Vec::new();
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        let pool = trust_pool.read().await;
        let Some(state) =
            pool.network_state(&trust_ctx.trust_domain_id, &trust_ctx.network_local_id)
        else {
            tracing::debug!(
                source = "signed-peer-hint",
                "network state is not available"
            );
            return Vec::new();
        };

        peer_hint_urls_from_state(state, now)
    }

    async fn try_signed_peer_hint_connect(
        data: Arc<ConnectorManagerData>,
        dead_url: &url::Url,
    ) -> Result<ReconnResult, Error> {
        let candidates = Self::signed_peer_hint_urls(data.clone()).await;
        if candidates.is_empty() {
            return Err(Error::AnyhowError(anyhow::anyhow!(
                "no signed peer hints available"
            )));
        }

        let mut last_error = None;
        for hint_url in candidates {
            if &hint_url == dead_url || data.removed_conn_urls.contains(&hint_url) {
                continue;
            }
            tracing::info!(source = "signed-peer-hint", %dead_url, url = %hint_url, "try reconnect via signed peer hint");
            match Self::conn_reconnect_with_ip_version(
                data.clone(),
                hint_url.to_string(),
                IpVersion::Both,
            )
            .await
            {
                Ok(mut ret) => {
                    data.connectors.insert(hint_url.clone());
                    data.borrowed_failures.remove(dead_url);
                    ret.dead_url = dead_url.to_string();
                    return Ok(ret);
                }
                Err(err) => {
                    data.global_ctx.issue_event(GlobalCtxEvent::ConnectError(
                        hint_url.to_string(),
                        "signed-peer-hint".to_owned(),
                        format!("{:?}", err),
                    ));
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            Error::AnyhowError(anyhow::anyhow!("no usable signed peer hints available"))
        }))
    }

    async fn local_peer_cache_context(
        data: &ConnectorManagerData,
    ) -> Option<(String, String, PathBuf)> {
        let trust_ctx = data.global_ctx.get_trust_context().await?;
        let trust_domain_id = trust_ctx.trust_domain_id.to_string();
        let network_local_id = trust_ctx.network_local_id.to_string();
        let path = local_peer_cache_path(&trust_domain_id, &network_local_id)?;
        Some((trust_domain_id, network_local_id, path))
    }

    async fn record_local_peer_cache_success(
        data: Arc<ConnectorManagerData>,
        url: &url::Url,
        peer_id: PeerId,
    ) {
        let Some((trust_domain_id, network_local_id, path)) =
            Self::local_peer_cache_context(&data).await
        else {
            return;
        };
        let mut cache = read_local_peer_cache(&path);
        cache.schema_version = LOCAL_PEER_CACHE_SCHEMA_VERSION;
        let url = url.to_string();
        if let Some(entry) = cache.entries.iter_mut().find(|entry| {
            entry.url == url
                && entry.trust_domain_id == trust_domain_id
                && entry.network_local_id == network_local_id
        }) {
            entry.peer_id = peer_id;
            entry.last_success = now_unix_secs();
            entry.failures = 0;
        } else {
            cache.entries.push(LocalPeerCacheEntry {
                url,
                peer_id,
                trust_domain_id,
                network_local_id,
                last_success: now_unix_secs(),
                failures: 0,
            });
        }
        cache
            .entries
            .sort_by(|left, right| left.url.cmp(&right.url));
        write_local_peer_cache(&path, &cache);
        tracing::debug!(source = "local-peer-cache", path = %path.display(), "recorded successful peer URL");
    }

    async fn record_local_peer_cache_failure(data: Arc<ConnectorManagerData>, url: &url::Url) {
        let Some((trust_domain_id, network_local_id, path)) =
            Self::local_peer_cache_context(&data).await
        else {
            return;
        };
        let mut cache = read_local_peer_cache(&path);
        let url = url.to_string();
        if let Some(entry) = cache.entries.iter_mut().find(|entry| {
            entry.url == url
                && entry.trust_domain_id == trust_domain_id
                && entry.network_local_id == network_local_id
        }) {
            entry.failures = entry.failures.saturating_add(1);
            write_local_peer_cache(&path, &cache);
            tracing::debug!(source = "local-peer-cache", path = %path.display(), "recorded failed peer URL");
        }
    }

    async fn local_peer_cache_urls(data: Arc<ConnectorManagerData>) -> Vec<url::Url> {
        let Some((trust_domain_id, network_local_id, path)) =
            Self::local_peer_cache_context(&data).await
        else {
            return Vec::new();
        };
        let cache = read_local_peer_cache(&path);
        valid_local_peer_cache_urls(&cache, &trust_domain_id, &network_local_id, now_unix_secs())
    }

    async fn try_local_peer_cache_connect(
        data: Arc<ConnectorManagerData>,
        dead_url: &url::Url,
    ) -> Result<ReconnResult, Error> {
        let candidates = Self::local_peer_cache_urls(data.clone()).await;
        if candidates.is_empty() {
            return Err(Error::AnyhowError(anyhow::anyhow!(
                "no local peer cache candidates available"
            )));
        }

        let mut last_error = None;
        for cached_url in candidates {
            if &cached_url == dead_url || data.removed_conn_urls.contains(&cached_url) {
                continue;
            }
            tracing::info!(source = "local-peer-cache", %dead_url, url = %cached_url, "try reconnect via local peer cache");
            match Self::conn_reconnect_with_ip_version(
                data.clone(),
                cached_url.to_string(),
                IpVersion::Both,
            )
            .await
            {
                Ok(mut ret) => {
                    data.connectors.insert(cached_url.clone());
                    data.borrowed_failures.remove(dead_url);
                    ret.dead_url = dead_url.to_string();
                    return Ok(ret);
                }
                Err(err) => {
                    Self::record_local_peer_cache_failure(data.clone(), &cached_url).await;
                    data.global_ctx.issue_event(GlobalCtxEvent::ConnectError(
                        cached_url.to_string(),
                        "local-peer-cache".to_owned(),
                        format!("{:?}", err),
                    ));
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            Error::AnyhowError(anyhow::anyhow!("no usable local peer cache candidates"))
        }))
    }

    async fn conn_reconnect(
        data: Arc<ConnectorManagerData>,
        dead_url: url::Url,
    ) -> Result<ReconnResult, Error> {
        tracing::info!("reconnect: {}", dead_url);

        let mut ip_versions = vec![];
        if dead_url.scheme() == "ring" || dead_url.scheme() == "txt" || dead_url.scheme() == "srv" {
            ip_versions.push(IpVersion::Both);
        } else {
            let converted_dead_url = crate::common::idn::convert_idn_to_ascii(dead_url.clone())?;
            let addrs = match socket_addrs(&converted_dead_url, || Some(1000)).await {
                Ok(addrs) => addrs,
                Err(e) => {
                    data.global_ctx.issue_event(GlobalCtxEvent::ConnectError(
                        dead_url.to_string(),
                        format!("{:?}", IpVersion::Both),
                        format!("{:?}", e),
                    ));
                    return Err(Error::AnyhowError(anyhow::anyhow!(
                        "get ip from url failed: {:?}",
                        e
                    )));
                }
            };
            tracing::info!(?addrs, ?dead_url, "get ip from url done");
            let mut has_ipv4 = false;
            let mut has_ipv6 = false;
            for addr in addrs {
                if addr.is_ipv4() {
                    if !has_ipv4 {
                        ip_versions.insert(0, IpVersion::V4);
                    }
                    has_ipv4 = true;
                } else if addr.is_ipv6() {
                    if !has_ipv6 {
                        ip_versions.push(IpVersion::V6);
                    }
                    has_ipv6 = true;
                }
            }
        }

        let mut reconn_ret = Err(Error::AnyhowError(anyhow::anyhow!(
            "cannot get ip from url"
        )));
        let failures = data
            .borrowed_failures
            .entry(dead_url.clone())
            .and_modify(|count| *count += 1)
            .or_insert(1);
        let should_try_borrowed = *failures >= 3;
        drop(failures);

        for ip_version in ip_versions {
            let use_long_timeout = dead_url.scheme() == "http"
                || dead_url.scheme() == "https"
                || dead_url.scheme() == "ws"
                || dead_url.scheme() == "wss"
                || dead_url.scheme() == "txt"
                || dead_url.scheme() == "srv";
            let ret = timeout(
                // allow http/websocket connector to wait longer
                std::time::Duration::from_secs(if use_long_timeout { 20 } else { 2 }),
                Self::conn_reconnect_with_ip_version(
                    data.clone(),
                    dead_url.to_string(),
                    ip_version,
                ),
            )
            .await;
            tracing::info!("reconnect: {} done, ret: {:?}", dead_url, ret);

            match ret {
                Ok(Ok(_)) => {
                    // 外层和内层都成功：解包并跳出
                    reconn_ret = ret.unwrap();
                    break;
                }
                Ok(Err(e)) => {
                    // 外层成功，内层失败
                    reconn_ret = Err(e);
                }
                Err(e) => {
                    // 外层失败
                    reconn_ret = Err(e.into());
                }
            }

            // 发送事件（只有在未 break 时才执行）
            data.global_ctx.issue_event(GlobalCtxEvent::ConnectError(
                dead_url.to_string(),
                format!("{:?}", ip_version),
                format!("{:?}", reconn_ret),
            ));
        }

        match Self::try_signed_peer_hint_connect(data.clone(), &dead_url).await {
            Ok(ret) => return Ok(ret),
            Err(err) => {
                tracing::debug!(source = "signed-peer-hint", %dead_url, ?err, "signed peer hint reconnect failed");
            }
        }

        match Self::try_local_peer_cache_connect(data.clone(), &dead_url).await {
            Ok(ret) => return Ok(ret),
            Err(err) => {
                tracing::debug!(source = "local-peer-cache", %dead_url, ?err, "local peer cache reconnect failed");
            }
        }

        if should_try_borrowed {
            match Self::try_borrowed_relay_connect(data.clone(), &dead_url).await {
                Ok(ret) => return Ok(ret),
                Err(err) => {
                    reconn_ret = Err(err);
                }
            }
        }

        reconn_ret
    }
}

#[derive(Clone)]
pub struct ConnectorManagerRpcService(pub Weak<ManualConnectorManager>);

#[async_trait::async_trait]
impl ConnectorManageRpc for ConnectorManagerRpcService {
    type Controller = BaseController;

    async fn list_connector(
        &self,
        _: BaseController,
        _request: ListConnectorRequest,
    ) -> Result<ListConnectorResponse, rpc_types::error::Error> {
        let mut ret = ListConnectorResponse::default();
        let connectors = weak_upgrade(&self.0)?.list_connectors().await;
        ret.connectors = connectors;
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        peers::tests::create_mock_peer_manager,
        set_global_var,
        trust::{
            NetworkLocalId, NetworkStatePayload, PeerHint, TrustDomainRoot, UnsignedNetworkState,
        },
        tunnel::{Tunnel, TunnelError},
    };

    use super::*;

    fn signed_state_with_hints(hints: Vec<PeerHint>) -> crate::trust::SignedNetworkState {
        let root = TrustDomainRoot::generate();
        UnsignedNetworkState {
            trust_domain_id: root.id(),
            network_local_id: NetworkLocalId::try_from_str("office-net").unwrap(),
            version: 1,
            payload: NetworkStatePayload {
                member_cert_index: Vec::new(),
                revoked_certs: Vec::new(),
                disabled_certs: Vec::new(),
                acl: Vec::new(),
                routes: Vec::new(),
                peer_hints: hints,
            },
        }
        .sign(&root)
    }

    fn hint(url: &str, expires_at: Option<u64>) -> PeerHint {
        PeerHint {
            url: url.to_owned(),
            label: None,
            capabilities: Vec::new(),
            updated_at: 1,
            expires_at,
        }
    }

    #[test]
    fn test_valid_local_peer_cache_urls_filters_scope_ttl_and_failures() {
        let now = LOCAL_PEER_CACHE_TTL_SECS + 1_000;
        let cache = LocalPeerCacheFile {
            schema_version: LOCAL_PEER_CACHE_SCHEMA_VERSION,
            entries: vec![
                LocalPeerCacheEntry {
                    url: "tcp://203.0.113.20:11010".to_owned(),
                    peer_id: 2,
                    trust_domain_id: "td-a".to_owned(),
                    network_local_id: "office-net".to_owned(),
                    last_success: now - 10,
                    failures: 0,
                },
                LocalPeerCacheEntry {
                    url: "tcp://203.0.113.10:11010".to_owned(),
                    peer_id: 1,
                    trust_domain_id: "td-a".to_owned(),
                    network_local_id: "office-net".to_owned(),
                    last_success: now - 20,
                    failures: 0,
                },
                LocalPeerCacheEntry {
                    url: "tcp://203.0.113.30:11010".to_owned(),
                    peer_id: 3,
                    trust_domain_id: "td-b".to_owned(),
                    network_local_id: "office-net".to_owned(),
                    last_success: now - 10,
                    failures: 0,
                },
                LocalPeerCacheEntry {
                    url: "tcp://203.0.113.40:11010".to_owned(),
                    peer_id: 4,
                    trust_domain_id: "td-a".to_owned(),
                    network_local_id: "lab-net".to_owned(),
                    last_success: now - 10,
                    failures: 0,
                },
                LocalPeerCacheEntry {
                    url: "tcp://203.0.113.50:11010".to_owned(),
                    peer_id: 5,
                    trust_domain_id: "td-a".to_owned(),
                    network_local_id: "office-net".to_owned(),
                    last_success: now - LOCAL_PEER_CACHE_TTL_SECS - 1,
                    failures: 0,
                },
                LocalPeerCacheEntry {
                    url: "tcp://203.0.113.60:11010".to_owned(),
                    peer_id: 6,
                    trust_domain_id: "td-a".to_owned(),
                    network_local_id: "office-net".to_owned(),
                    last_success: now - 10,
                    failures: LOCAL_PEER_CACHE_MAX_FAILURES,
                },
                LocalPeerCacheEntry {
                    url: "not-a-url".to_owned(),
                    peer_id: 7,
                    trust_domain_id: "td-a".to_owned(),
                    network_local_id: "office-net".to_owned(),
                    last_success: now - 10,
                    failures: 0,
                },
            ],
        };

        let urls = valid_local_peer_cache_urls(&cache, "td-a", "office-net", now);

        assert_eq!(
            urls.into_iter()
                .map(|url| url.to_string())
                .collect::<Vec<_>>(),
            vec!["tcp://203.0.113.10:11010", "tcp://203.0.113.20:11010"]
        );
    }

    #[test]
    fn test_local_peer_cache_file_round_trip_readable_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("td-a/office-net.json");
        let cache = LocalPeerCacheFile {
            schema_version: LOCAL_PEER_CACHE_SCHEMA_VERSION,
            entries: vec![LocalPeerCacheEntry {
                url: "tcp://203.0.113.10:11010".to_owned(),
                peer_id: 7,
                trust_domain_id: "td-a".to_owned(),
                network_local_id: "office-net".to_owned(),
                last_success: 10,
                failures: 0,
            }],
        };

        write_local_peer_cache(&path, &cache);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("schema_version"));

        assert_eq!(read_local_peer_cache(&path), cache);
    }

    #[test]
    fn test_peer_hint_urls_from_state_filters_invalid_expired_and_dedups() {
        let state = signed_state_with_hints(vec![
            hint("tcp://203.0.113.20:11010", Some(200)),
            hint("not-a-url", None),
            hint("tcp://203.0.113.10:11010", Some(200)),
            hint("tcp://203.0.113.10:11010", Some(200)),
            hint("tcp://203.0.113.30:11010", Some(99)),
        ]);

        let urls = peer_hint_urls_from_state(&state, 100);

        assert_eq!(
            urls.into_iter()
                .map(|url| url.to_string())
                .collect::<Vec<_>>(),
            vec!["tcp://203.0.113.10:11010", "tcp://203.0.113.20:11010"]
        );
    }

    #[tokio::test]
    async fn test_reconnect_with_connecting_addr() {
        set_global_var!(MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS, 1);

        let peer_mgr = create_mock_peer_manager().await;
        let mgr = ManualConnectorManager::new(peer_mgr.get_global_ctx(), peer_mgr);

        struct MockConnector {}
        #[async_trait::async_trait]
        impl TunnelConnector for MockConnector {
            fn remote_url(&self) -> url::Url {
                url::Url::parse("tcp://aa.com").unwrap()
            }
            async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                Err(TunnelError::InvalidPacket("fake error".into()))
            }
        }

        mgr.add_connector(MockConnector {});

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
