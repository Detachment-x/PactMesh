//! The daemon, in-process.
//!
//! `pactmesh serve` forks a `pactmesh-core` child to own the RPC portal and the
//! instance manager, then sleeps 1.5s hoping the portal has bound. Android cannot
//! fork an ELF at all, so the same bootstrap is exposed here as a library call —
//! and the desktop gets to drop the child process, its log file and the sleep.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use cidr::IpCidr;

use crate::common::config::load_config_from_file;
use crate::instance_manager::{DaemonGuard, NetworkInstanceManager};
use crate::rpc_service::api::ApiRpcServer;
use crate::tunnel::tcp::TcpTunnelListener;

pub struct EmbeddedDaemonOptions {
    /// `ip:port` the console's RPC client dials.
    pub rpc_portal: String,
    pub rpc_portal_whitelist: Option<Vec<IpCidr>>,
    /// Holds the persisted `*.toml` instances; each is restored on start, which
    /// is how a network survives a reboot — or Android killing the process.
    pub instances_dir: PathBuf,
}

/// Keeps the daemon alive: dropping it tears down the RPC portal and stops every
/// instance the manager owns.
pub struct EmbeddedDaemon {
    pub manager: Arc<NetworkInstanceManager>,
    _rpc_server: ApiRpcServer<TcpTunnelListener>,
    _daemon_guard: DaemonGuard,
}

impl EmbeddedDaemon {
    /// Resolves when every instance has stopped.
    pub async fn wait(&self) {
        self.manager.wait().await;
    }
}

pub async fn start_embedded_daemon(options: EmbeddedDaemonOptions) -> Result<EmbeddedDaemon> {
    std::fs::create_dir_all(&options.instances_dir)
        .with_context(|| format!("failed to create {}", options.instances_dir.display()))?;

    let manager = Arc::new(
        NetworkInstanceManager::new().with_config_path(Some(options.instances_dir.clone())),
    );

    let rpc_server = ApiRpcServer::new(
        Some(options.rpc_portal.clone()),
        options.rpc_portal_whitelist,
        manager.clone(),
    )
    .with_context(|| format!("failed to bind rpc portal {}", options.rpc_portal))?
    .serve()
    .await?;

    let daemon_guard = manager.register_daemon();

    for entry in std::fs::read_dir(&options.instances_dir)
        .with_context(|| format!("failed to read {}", options.instances_dir.display()))?
    {
        let path = entry?.path();
        if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let (cfg, control) =
            load_config_from_file(&path, Some(&options.instances_dir), false).await?;
        tracing::info!("restoring instance from {}", path.display());
        manager.run_network_instance(cfg, true, control)?;
    }

    Ok(EmbeddedDaemon {
        manager,
        _rpc_server: rpc_server,
        _daemon_guard: daemon_guard,
    })
}
