//! 本地 Web 控制器（浏览器管理控制台）。
//!
//! M1：只读 dashboard（node/peers/routes/stats）+ token 鉴权 + loopback 限制。
//! 会话解锁 / root 签名治理 / 配置下发在后续里程碑接入。
//!
//! 设计同 `tui`：本模块是 lib 侧实现，bin 仅加一个 `controller` 子命令并转调
//! [`run`]，复用 CLI 已建立的 daemon RPC 客户端。

mod access;
mod auth;
mod routes;
mod session;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
    /// quickstart / serve run 的主网络：控制器启动后经 `run_network_instance`
    /// 挂载到空载 daemon（而非烘焙进 CLI），使主网络成为可管理、可热停的实例。
    pub attach_primary: Option<AttachPrimary>,
    /// 落 `controller-endpoint.json` 并向 stdout 打印带 token 的浏览器入口。
    /// 桌面端靠这两样把用户送进控制台；进程内宿主（Android）自带 token 与端口、
    /// 也没有 stdout，置 false 即可。
    pub announce_endpoint: bool,
}

/// 待挂载的主网络描述（quickstart/serve 由既有信任域自举后交由控制器挂载）。
pub struct AttachPrimary {
    pub trust_domain_id: String,
    pub network_local_id: String,
    pub listeners: Vec<String>,
    pub no_tun: bool,
}

#[derive(Clone)]
struct AppState {
    client: Arc<Mutex<RpcClient>>,
    instance: InstanceIdentifier,
    token: Arc<String>,
    /// 解锁会话（root 口令 + TTL），治理写操作前需先 `/api/unlock`。
    session: Arc<Mutex<Option<session::Session>>>,
    unlock_ttl: Duration,
    /// 本次进程生效的 Web UI 访问来源。改设置只落盘，重启后才换绑定，故此处为启动快照。
    access: access::WebuiAccess,
}

/// 启动控制器 HTTP 服务并阻塞至退出。
pub async fn run(
    client: Arc<Mutex<RpcClient>>,
    instance: InstanceIdentifier,
    config: ControllerConfig,
) -> Result<()> {
    let token = config.token.unwrap_or_else(auth::generate_token);
    let access = access::load();
    let state = AppState {
        client,
        instance,
        token: Arc::new(token.clone()),
        session: Arc::new(Mutex::new(None)),
        unlock_ttl: Duration::from_secs(config.unlock_ttl_secs),
        access,
    };

    // 主网络挂载：quickstart/serve 起空载 daemon 后，在此对运行中 daemon 调
    // `run_network_instance` 挂主网 → 主网络成为可热停/可删的托管实例（修复烘焙式
    // 只读实例无法 leave/purge 的问题）。失败不致命：控制台仍拉起以便诊断/重试。
    if let Some(ap) = config.attach_primary {
        if let Err(e) = routes::attach_trust_network(
            &state,
            &ap.trust_domain_id,
            &ap.network_local_id,
            ap.listeners,
            vec![],
            ap.no_tun,
            None,
        )
        .await
        {
            eprintln!("warning: failed to attach primary network: {e:#}");
        }
    }

    // 重开控制台时把没走完的 join 接着跑（进程内任务不会跨重启存活）。
    routes::resume_pending_joins();

    let app = routes::router(state);

    // 绑定地址由「Web UI 访问来源」决定，只沿用 `--listen` 的端口；来源过滤在 auth::guard。
    let listen = access.bind(config.listen.port());
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind controller on {listen}"))?;
    let local = listener.local_addr().unwrap_or(listen);
    // 绑 0.0.0.0 时浏览器/端点文件不能用 0.0.0.0 作目标，改用回环呈现。
    let url = if local.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), local.port())
    } else {
        local
    };

    // 运行时端点文件（Jupyter 式）：存活期间落 {listen,token} 0600，退出删除，
    // 供 `pactmesh web` / Windows 托盘读取后免 token 直达浏览器。
    let _endpoint = config
        .announce_endpoint
        .then(|| EndpointFileGuard::write(url, &token));

    if config.announce_endpoint {
        println!("pactmesh controller serving at http://{url}");
        println!("open in browser: http://{url}/?token={token}");
    } else {
        tracing::info!("pactmesh controller serving at http://{url}");
    }

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("controller http server terminated")?;

    // serve 优雅退出后返回，`_endpoint` 在此 Drop 删除端点文件。
    Ok(())
}

/// 等待 Ctrl-C（全平台）或 SIGTERM（unix），用于优雅退出以触发端点文件清理。
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

const ENDPOINT_FILE: &str = "controller-endpoint.json";

/// 机器级端点目录：Windows 下用 `%ProgramData%\PactMesh`，让 LocalSystem 服务写的
/// 端点文件能被交互用户的 `pactmesh web`/托盘读到（跨账户）。非 Windows 返回 None，
/// 沿用每用户 config 目录、行为不变。
#[cfg(windows)]
fn machine_endpoint_path() -> Option<std::path::PathBuf> {
    let base = std::env::var_os("ProgramData")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\ProgramData"));
    Some(base.join("PactMesh").join(ENDPOINT_FILE))
}

#[cfg(not(windows))]
fn machine_endpoint_path() -> Option<std::path::PathBuf> {
    None
}

fn user_endpoint_path() -> Option<std::path::PathBuf> {
    crate::common::config_dir::pnw_config_dir()
        .ok()
        .map(|d| d.join(ENDPOINT_FILE))
}

/// 端点文件候选路径：机器级优先（服务↔用户跨账户可见），回退每用户目录。
fn endpoint_path_candidates() -> Vec<std::path::PathBuf> {
    [machine_endpoint_path(), user_endpoint_path()]
        .into_iter()
        .flatten()
        .collect()
}

/// 控制器存活期间持有的端点文件，Drop 时删除（优雅退出清理）。
struct EndpointFileGuard(Option<std::path::PathBuf>);

impl EndpointFileGuard {
    fn write(listen: SocketAddr, token: &str) -> Self {
        Self(write_endpoint_file(listen, token))
    }
}

impl Drop for EndpointFileGuard {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn write_endpoint_file(listen: SocketAddr, token: &str) -> Option<std::path::PathBuf> {
    let body = serde_json::json!({ "listen": listen.to_string(), "token": token }).to_string();
    // 机器级优先（Windows 服务写处用户可读）；写不动（权限）回退每用户目录。
    for path in endpoint_path_candidates() {
        if let Some(parent) = path.parent() {
            if std::fs::create_dir_all(parent).is_err() {
                continue;
            }
        }
        if std::fs::write(&path, &body).is_err() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        return Some(path);
    }
    None
}

/// 读取运行时端点文件，返回浏览器可直达的 URL（含 token）。
/// 供 `pactmesh web` 与 Windows 托盘复用：机器级优先、回退每用户。
pub fn read_endpoint_url() -> Result<String> {
    let candidates = endpoint_path_candidates();
    if candidates.is_empty() {
        anyhow::bail!("could not locate config dir for controller endpoint file");
    }
    for path in &candidates {
        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(_) => continue,
        };
        let value: serde_json::Value =
            serde_json::from_str(&raw).context("controller endpoint file is corrupt")?;
        let listen = value
            .get("listen")
            .and_then(|x| x.as_str())
            .context("controller endpoint file missing 'listen'")?;
        let token = value
            .get("token")
            .and_then(|x| x.as_str())
            .context("controller endpoint file missing 'token'")?;
        return Ok(format!("http://{listen}/?token={token}"));
    }
    let shown = candidates
        .last()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    anyhow::bail!(
        "controller endpoint file not found (looked under {shown}); start it first with `pactmesh serve` or `pactmesh quickstart`"
    )
}
