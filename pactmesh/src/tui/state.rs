//! TUI 共享状态 + RPC fetcher。
//!
//! 用 ArcSwap 做 lock-free snapshot：fetcher 整体替换，render 同步 load 零阻塞。

use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use tokio::sync::Mutex;

use crate::common::config_dir::pnw_trust_domains_dir;
use crate::proto::{
    api::{
        config::{
            ListPendingJoinRequestsRequest, RejectJoinRequestRequest, TrustJoinManageRpc,
            TrustJoinManageRpcClientFactory,
        },
        instance::{
            Connector, ConnectorManageRpc, ConnectorManageRpcClientFactory, InstanceIdentifier,
            ListConnectorRequest, ListPeerRequest, ListRouteRequest, NodeInfo, PeerManageRpc,
            PeerManageRpcClientFactory, PeerRoutePair, ShowNodeInfoRequest, list_peer_route_pair,
        },
    },
    common::StunInfo,
    rpc_impl::standalone::StandAloneClient,
    rpc_types::controller::BaseController,
};
use crate::tunnel::tcp::TcpTunnelConnector;

pub type RpcClient = StandAloneClient<TcpTunnelConnector>;
pub type SharedRpc = Arc<Mutex<RpcClient>>;
pub type AppState = Arc<ArcSwap<Snapshot>>;

#[derive(Debug, Clone)]
pub struct JoinRow {
    pub trust_domain_id: Vec<u8>,
    pub trust_domain_id_b64: String,
    pub network_local_id: String,
    pub applicant_pk: Vec<u8>,
    pub applicant_short: String,
    pub device_label: String,
    pub hint: String,
}

#[derive(Debug, Default, Clone)]
pub struct Snapshot {
    pub node_info: Option<NodeInfo>,
    pub stun: StunInfo,
    pub peers: Vec<PeerRoutePair>,
    pub pending_joins: Vec<JoinRow>,
    pub connectors: Vec<Connector>,
    pub last_error: Option<String>,
    pub last_refresh_at: Option<SystemTime>,
}

pub fn new_state() -> AppState {
    Arc::new(ArcSwap::from_pointee(Snapshot::default()))
}

async fn peer_client(
    rpc: &SharedRpc,
) -> Result<Box<dyn PeerManageRpc<Controller = BaseController> + Send + Sync>> {
    let mut g = rpc.lock().await;
    g.scoped_client::<PeerManageRpcClientFactory<BaseController>>(String::new())
        .await
        .context("creating peer manage rpc client")
}

async fn connector_client(
    rpc: &SharedRpc,
) -> Result<Box<dyn ConnectorManageRpc<Controller = BaseController> + Send + Sync>> {
    let mut g = rpc.lock().await;
    g.scoped_client::<ConnectorManageRpcClientFactory<BaseController>>(String::new())
        .await
        .context("creating connector manage rpc client")
}

async fn trust_join_client(
    rpc: &SharedRpc,
) -> Result<Box<dyn TrustJoinManageRpc<Controller = BaseController> + Send + Sync>> {
    let mut g = rpc.lock().await;
    g.scoped_client::<TrustJoinManageRpcClientFactory<BaseController>>(String::new())
        .await
        .context("creating trust join manage rpc client")
}

/// 一次拉齐 Node + Peers + Routes + Joins + Connectors，整体替换 snapshot。
/// 单个子项失败不阻断其他项；最后一个错存进 last_error 兜底。
pub async fn refresh_all(
    rpc: &SharedRpc,
    instance: &InstanceIdentifier,
    state: &AppState,
) -> Result<()> {
    let mut last_err: Option<String> = None;

    let (node, stun, peers) = fetch_node_peers(rpc, instance)
        .await
        .map(|(n, s, p)| (n, s, p))
        .unwrap_or_else(|e| {
            last_err = Some(format!("peer/node: {e:#}"));
            (None, StunInfo::default(), Vec::new())
        });

    let connectors = match fetch_connectors(rpc, instance).await {
        Ok(v) => v,
        Err(e) => {
            last_err = Some(format!("connectors: {e:#}"));
            Vec::new()
        }
    };

    let pending_joins = match fetch_pending_joins(rpc, instance).await {
        Ok(v) => v,
        Err(e) => {
            last_err = Some(format!("joins: {e:#}"));
            Vec::new()
        }
    };

    let new = Snapshot {
        node_info: node,
        stun,
        peers,
        pending_joins,
        connectors,
        last_error: last_err,
        last_refresh_at: Some(SystemTime::now()),
    };
    state.store(Arc::new(new));
    Ok(())
}

async fn fetch_node_peers(
    rpc: &SharedRpc,
    instance: &InstanceIdentifier,
) -> Result<(Option<NodeInfo>, StunInfo, Vec<PeerRoutePair>)> {
    let client = peer_client(rpc).await?;
    let peers = client
        .list_peer(
            BaseController::default(),
            ListPeerRequest {
                instance: Some(instance.clone()),
            },
        )
        .await?
        .peer_infos;
    let routes = client
        .list_route(
            BaseController::default(),
            ListRouteRequest {
                instance: Some(instance.clone()),
            },
        )
        .await?
        .routes;
    let node = client
        .show_node_info(
            BaseController::default(),
            ShowNodeInfoRequest {
                instance: Some(instance.clone()),
            },
        )
        .await?
        .node_info;
    let stun = node
        .as_ref()
        .and_then(|n| n.stun_info.clone())
        .unwrap_or_default();
    Ok((node, stun, list_peer_route_pair(peers, routes)))
}

async fn fetch_connectors(
    rpc: &SharedRpc,
    instance: &InstanceIdentifier,
) -> Result<Vec<Connector>> {
    let client = connector_client(rpc).await?;
    Ok(client
        .list_connector(
            BaseController::default(),
            ListConnectorRequest {
                instance: Some(instance.clone()),
            },
        )
        .await?
        .connectors)
}

/// 枚举磁盘上 `<config>/trust-domains/<td>/networks/<network>` 全部已建网络。
/// 没有 trust-domains 目录时返回空，不当作错误（首次跑或 lab 之前的状态）。
fn enumerate_trust_networks() -> Result<Vec<(String, String)>> {
    let base = match pnw_trust_domains_dir() {
        Ok(b) => b,
        Err(_) => return Ok(Vec::new()),
    };
    let entries = match std::fs::read_dir(&base) {
        Ok(it) => it,
        Err(_) => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for td_entry in entries.flatten() {
        let td_path = td_entry.path();
        if !td_path.is_dir() {
            continue;
        }
        let td_id = match td_entry.file_name().into_string() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let networks_dir: PathBuf = td_path.join("networks");
        let net_iter = match std::fs::read_dir(&networks_dir) {
            Ok(it) => it,
            Err(_) => continue,
        };
        for net_entry in net_iter.flatten() {
            let net_path = net_entry.path();
            if !net_path.is_dir() {
                continue;
            }
            if let Ok(name) = net_entry.file_name().into_string() {
                out.push((td_id.clone(), name));
            }
        }
    }
    Ok(out)
}

fn parse_td_id(td_b64: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(td_b64)
        .with_context(|| format!("trust_domain_id not base64-url: {td_b64}"))
}

async fn fetch_pending_joins(
    rpc: &SharedRpc,
    instance: &InstanceIdentifier,
) -> Result<Vec<JoinRow>> {
    let pairs = enumerate_trust_networks()?;
    if pairs.is_empty() {
        return Ok(Vec::new());
    }
    let client = trust_join_client(rpc).await?;
    let mut rows = Vec::new();
    for (td_b64, network_local_id) in pairs {
        let td_bytes = match parse_td_id(&td_b64) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let resp = match client
            .list_pending_join_requests(
                BaseController::default(),
                ListPendingJoinRequestsRequest {
                    instance: Some(instance.clone()),
                    trust_domain_id: td_bytes.clone(),
                    network_local_id: network_local_id.clone(),
                },
            )
            .await
        {
            Ok(r) => r,
            // network 可能尚未在 daemon 上 attach，跳过即可
            Err(_) => continue,
        };
        for req in resp.requests {
            let applicant_short = short_hex(&req.applicant_pk, 8);
            rows.push(JoinRow {
                trust_domain_id: td_bytes.clone(),
                trust_domain_id_b64: td_b64.clone(),
                network_local_id: network_local_id.clone(),
                applicant_pk: req.applicant_pk,
                applicant_short,
                device_label: req.device_label,
                hint: req.hint,
            });
        }
    }
    Ok(rows)
}

fn short_hex(bytes: &[u8], width: usize) -> String {
    let mut s = String::with_capacity(width);
    for b in bytes.iter().take((width + 1) / 2) {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
    }
    s.truncate(width);
    s
}

/// 调用 daemon 拒绝指定 join request。失败由调用方处理。
pub async fn reject_join_request(rpc: &SharedRpc, row: &JoinRow) -> Result<()> {
    let client = trust_join_client(rpc).await?;
    client
        .reject_join_request(
            BaseController::default(),
            RejectJoinRequestRequest {
                instance: Some(InstanceIdentifier::default()),
                trust_domain_id: row.trust_domain_id.clone(),
                network_local_id: row.network_local_id.clone(),
                applicant_pk: row.applicant_pk.clone(),
            },
        )
        .await
        .context("daemon refused to reject join request")?;
    Ok(())
}

/// 把错误存进 snapshot 但不替换数据帧，让 UI 仍展示上一帧 + 红色 last_error 行。
pub fn record_error(state: &AppState, err: &anyhow::Error) {
    let cur = state.load_full();
    let mut next = (*cur).clone();
    next.last_error = Some(format!("{err:#}"));
    state.store(Arc::new(next));
}

#[cfg(test)]
mod tests {
    use super::short_hex;

    #[test]
    fn short_hex_truncates_to_width() {
        assert_eq!(short_hex(&[0xde, 0xad, 0xbe, 0xef], 4), "dead");
        assert_eq!(short_hex(&[0xde, 0xad, 0xbe, 0xef], 8), "deadbeef");
        assert_eq!(short_hex(&[], 8), "");
        assert_eq!(short_hex(&[0xff], 4), "ff");
    }
}
