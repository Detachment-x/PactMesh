//! 本地 Web 控制器（浏览器管理控制台）。
//!
//! M1：只读 dashboard（node/peers/routes/stats）+ token 鉴权 + loopback 限制。
//! 会话解锁 / root 签名治理 / 配置下发在后续里程碑接入。
//!
//! 设计同 `tui`：本模块是 lib 侧实现，bin 仅加一个 `controller` 子命令并转调
//! [`run`]，复用 CLI 已建立的 daemon RPC 客户端。

mod auth;
mod routes;
mod session;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::Mutex;

use crate::proto::api::instance::InstanceIdentifier;
use crate::proto::rpc_impl::standalone::StandAloneClient;
use crate::tunnel::tcp::TcpTunnelConnector;

pub type RpcClient = StandAloneClient<TcpTunnelConnector>;

/// 控制器运行配置（由 bin 的 clap 参数构造）。
pub struct ControllerConfig {
    pub listen: SocketAddr,
    pub token: Option<String>,
    /// root 口令解锁 TTL（秒）。M2 会话解锁使用，M1 仅保留。
    pub unlock_ttl_secs: u64,
}

#[derive(Clone)]
struct AppState {
    client: Arc<Mutex<RpcClient>>,
    instance: InstanceIdentifier,
    token: Arc<String>,
    /// 解锁会话（root 口令 + TTL），治理写操作前需先 `/api/unlock`。
    session: Arc<Mutex<Option<session::Session>>>,
    unlock_ttl: Duration,
}

/// 启动控制器 HTTP 服务并阻塞至退出。
pub async fn run(
    client: Arc<Mutex<RpcClient>>,
    instance: InstanceIdentifier,
    config: ControllerConfig,
) -> Result<()> {
    let token = config.token.unwrap_or_else(auth::generate_token);
    let state = AppState {
        client,
        instance,
        token: Arc::new(token.clone()),
        session: Arc::new(Mutex::new(None)),
        unlock_ttl: Duration::from_secs(config.unlock_ttl_secs),
    };

    let app = routes::router(state);

    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to bind controller on {}", config.listen))?;
    let local = listener.local_addr().unwrap_or(config.listen);

    println!("pactmesh controller serving at http://{local}");
    println!("open in browser: http://{local}/?token={token}");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("controller http server terminated")?;

    Ok(())
}
