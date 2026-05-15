//! TUI 共享状态 + RPC fetcher。
//!
//! 用 ArcSwap 做 lock-free snapshot：fetcher 整体替换，render 同步 load 零阻塞。

use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use tokio::sync::Mutex;

use crate::proto::{
    api::instance::{
        InstanceIdentifier, ListPeerRequest, ListRouteRequest, NodeInfo, PeerManageRpc,
        PeerManageRpcClientFactory, PeerRoutePair, ShowNodeInfoRequest, list_peer_route_pair,
    },
    common::StunInfo,
    rpc_impl::standalone::StandAloneClient,
    rpc_types::controller::BaseController,
};
use crate::tunnel::tcp::TcpTunnelConnector;

pub type RpcClient = StandAloneClient<TcpTunnelConnector>;
pub type SharedRpc = Arc<Mutex<RpcClient>>;
pub type AppState = Arc<ArcSwap<Snapshot>>;

#[derive(Debug, Default, Clone)]
pub struct Snapshot {
    pub node_info: Option<NodeInfo>,
    pub stun: StunInfo,
    pub peers: Vec<PeerRoutePair>,
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

/// 一次拉齐 Node + Peers + Routes，整体替换 snapshot。
/// 失败时返回 Err 让事件循环用 record_error 写入 last_error 字段。
pub async fn refresh_node_and_peers(
    rpc: &SharedRpc,
    instance: &InstanceIdentifier,
    state: &AppState,
) -> Result<()> {
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

    let pairs = list_peer_route_pair(peers, routes);

    let new = Snapshot {
        node_info: node,
        stun,
        peers: pairs,
        last_error: None,
        last_refresh_at: Some(SystemTime::now()),
    };
    state.store(Arc::new(new));
    Ok(())
}

/// 把错误存进 snapshot 但不替换数据帧，让 UI 仍展示上一帧 + 红色 last_error 行。
pub fn record_error(state: &AppState, err: &anyhow::Error) {
    let cur = state.load_full();
    let mut next = (*cur).clone();
    next.last_error = Some(format!("{err:#}"));
    state.store(Arc::new(next));
}
