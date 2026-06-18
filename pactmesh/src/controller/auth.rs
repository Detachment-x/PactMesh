//! 控制器鉴权：loopback-only + 本地随机 token（jupyter 式）。
//! token 经 `?token=`（首屏）→ Set-Cookie 持久化 → 后续请求经 Cookie/Bearer 校验。

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};

use super::AppState;

/// 生成 24 字节随机 hex token。
pub fn generate_token() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut buf);
    let mut s = String::with_capacity(buf.len() * 2);
    for b in buf {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn token_from_request(req: &Request) -> Option<String> {
    // 1) Authorization: Bearer <t>
    if let Some(v) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(s) = v.to_str() {
            if let Some(t) = s.strip_prefix("Bearer ") {
                return Some(t.trim().to_string());
            }
        }
    }
    // 2) ?token=<t>
    if let Some(q) = req.uri().query() {
        for pair in q.split('&') {
            if let Some(t) = pair.strip_prefix("token=") {
                return Some(t.to_string());
            }
        }
    }
    // 3) Cookie: pm_token=<t>
    if let Some(v) = req.headers().get(header::COOKIE) {
        if let Ok(s) = v.to_str() {
            for c in s.split(';') {
                if let Some(t) = c.trim().strip_prefix("pm_token=") {
                    return Some(t.to_string());
                }
            }
        }
    }
    None
}

/// 中间件：非环回来源直接拒；token 不符返回 401。
pub async fn guard(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if !peer.ip().is_loopback() {
        return Err(StatusCode::FORBIDDEN);
    }
    match token_from_request(&req) {
        Some(t) if t == *state.token => Ok(next.run(req).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}
