//! 控制器解锁会话：浏览器输入一次 root 口令，进程内存缓存 TTL 秒。
//!
//! 口令以 [`Zeroizing`] 持有，会话被替换/清除/到期时自动清零；绝不落盘、绝不日志。
//! 每次治理写操作用缓存口令经 [`crate::control::SigningSession::open`] 重新解锁 sk_root，
//! 控制器自身不长期持有解密后的私钥。

use std::time::Instant;

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use super::AppState;
use crate::control::SigningSession;

/// 当前解锁状态：绑定到某个 (信任域, 网络)，缓存其 root 口令至 `expires_at`。
pub struct Session {
    pub trust_domain_id: String,
    pub network_local_id: String,
    pub passphrase: Zeroizing<String>,
    pub expires_at: Instant,
}

/// 解锁：用提供口令尝试打开签名会话（校验 sk_root 可解密且 id 与 td 匹配），成功则缓存。
/// 返回剩余 TTL 秒。
pub async fn unlock(
    state: &AppState,
    trust_domain_id: String,
    network_local_id: String,
    passphrase: String,
) -> Result<u64> {
    // 立即包裹进 Zeroizing，确保任何提前返回路径上的明文都会清零。
    let passphrase = Zeroizing::new(passphrase);
    // 校验：能打开即口令正确（open 内部 load sk_root + 校验 root.id == td）。
    SigningSession::open(&trust_domain_id, &network_local_id, &passphrase)
        .context("unlock failed: wrong passphrase or unknown trust domain/network")?;

    let ttl = state.unlock_ttl;
    let expires_at = Instant::now() + ttl;
    *state.session.lock().await = Some(Session {
        trust_domain_id,
        network_local_id,
        passphrase,
        expires_at,
    });
    Ok(ttl.as_secs())
}

/// 立即锁定（清除并清零缓存口令）。
pub async fn lock(state: &AppState) {
    *state.session.lock().await = None;
}

/// 取当前有效会话快照 `(td, nid, passphrase)`；若无 / 已过期，顺手清除并返回 `None`。
pub async fn snapshot(state: &AppState) -> Option<(String, String, Zeroizing<String>)> {
    let mut guard = state.session.lock().await;
    if let Some(s) = guard.as_ref() {
        if Instant::now() < s.expires_at {
            return Some((
                s.trust_domain_id.clone(),
                s.network_local_id.clone(),
                s.passphrase.clone(),
            ));
        }
    }
    *guard = None;
    None
}

/// 会话状态 JSON（供 `/api/session` 与解锁/锁定响应）。
pub async fn status(state: &AppState) -> serde_json::Value {
    let mut guard = state.session.lock().await;
    if let Some(s) = guard.as_ref() {
        let now = Instant::now();
        if now < s.expires_at {
            return serde_json::json!({
                "unlocked": true,
                "ttl_secs": (s.expires_at - now).as_secs(),
                "trust_domain_id": s.trust_domain_id,
                "network_local_id": s.network_local_id,
            });
        }
    }
    *guard = None;
    serde_json::json!({ "unlocked": false, "ttl_secs": 0 })
}
