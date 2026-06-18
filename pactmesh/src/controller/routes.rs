//! 控制器路由：内嵌静态资源 + 只读 JSON 端点（daemon RPC 透传）。

use axum::{
    body::Body,
    extract::{Query, State},
    http::{header, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::{auth, session, AppState};
use crate::control::{self, SigningSession};
use crate::proto::acl::Acl;
use crate::proto::api::config::{
    AclPatch, ConfigPatchAction, ConfigRpc, ConfigRpcClientFactory, ExitNodePatch,
    GetConfigRequest, GetConfigResponse, InstanceConfigPatch, ListPendingJoinRequestsRequest,
    PatchConfigRequest, PortForwardPatch, ProxyNetworkPatch, RejectJoinRequestRequest,
    RelayServingPatch, RoutePatch, StringPatch, TrustJoinManageRpc,
    TrustJoinManageRpcClientFactory, UpgradePeerToRootRequest, UrlPatch,
};
use crate::proto::common::{Ipv4Inet, PortForwardConfigPb, SocketType};
use crate::trust::hostname::check_hostname_unique;
use crate::trust::HostnameLabel;
use crate::tui::state::JoinRow;
use crate::proto::api::instance::{
    AclManageRpc, AclManageRpcClientFactory, ConnectorManageRpc, ConnectorManageRpcClientFactory,
    CredentialManageRpc, CredentialManageRpcClientFactory, GenerateCredentialRequest,
    GenerateCredentialResponse, GetAclStatsRequest, GetAclStatsResponse, GetStatsRequest,
    GetStatsResponse, GetVpnPortalInfoRequest, GetVpnPortalInfoResponse, GetWhitelistRequest,
    GetWhitelistResponse, ListConnectorRequest, ListConnectorResponse, ListCredentialsRequest,
    ListCredentialsResponse, ListMappedListenerRequest, ListMappedListenerResponse,
    ListPeerRequest, ListPeerResponse, ListPortForwardRequest, ListPortForwardResponse,
    ListRouteRequest, ListRouteResponse, ListTcpProxyEntryRequest, ListTcpProxyEntryResponse,
    MappedListenerManageRpc, MappedListenerManageRpcClientFactory, PeerManageRpc,
    PeerManageRpcClientFactory, PortForwardManageRpc, PortForwardManageRpcClientFactory,
    RevokeCredentialRequest, ShowNodeInfoRequest, ShowNodeInfoResponse, StatsRpc,
    StatsRpcClientFactory, TcpProxyRpc, TcpProxyRpcClientFactory, VpnPortalRpc,
    VpnPortalRpcClientFactory,
};
use std::str::FromStr;
use crate::proto::rpc_types::controller::BaseController;
use crate::trust::{
    DeviceFingerprint, DisabledCert, MemberCertFingerprint, PeerHint, RevocationReason, RevokedCert,
    TagName, UnsignedMemberCert,
};

const INDEX_HTML: &str = include_str!("assets/index.html");
const APP_CSS: &str = include_str!("assets/app.css");
const APP_JS: &str = include_str!("assets/app.js");

pub(super) fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/static/app.css", get(asset_css))
        .route("/static/app.js", get(asset_js))
        .route("/api/session", get(api_session))
        .route("/api/unlock", post(api_unlock))
        .route("/api/lock", post(api_lock))
        .route("/api/domains", get(api_domains))
        .route("/api/members", get(api_members))
        .route("/api/revoke", post(api_revoke))
        .route("/api/disable", post(api_disable))
        .route("/api/enable", post(api_enable))
        .route("/api/rename", post(api_rename))
        .route("/api/hostname", post(api_hostname))
        .route("/api/capability", post(api_capability))
        .route("/api/pending", get(api_pending))
        .route("/api/approve", post(api_approve))
        .route("/api/reject", post(api_reject))
        .route("/api/node", get(api_node))
        .route("/api/peers", get(api_peers))
        .route("/api/routes", get(api_routes))
        .route("/api/stats", get(api_stats))
        .route("/api/connectors", get(api_connectors))
        .route("/api/mapped-listeners", get(api_mapped_listeners))
        .route("/api/port-forwards", get(api_port_forwards))
        .route("/api/tcp-proxy", get(api_tcp_proxy))
        .route("/api/vpn-portal", get(api_vpn_portal))
        .route("/api/acl-stats", get(api_acl_stats))
        .route("/api/whitelist", get(api_whitelist))
        .route("/api/config", get(api_get_config))
        .route("/api/credentials", get(api_credentials))
        .route("/api/credentials/generate", post(api_cred_generate))
        .route("/api/credentials/revoke", post(api_cred_revoke))
        .route("/api/config/connector", post(api_cfg_connector))
        .route("/api/config/mapped-listener", post(api_cfg_mapped_listener))
        .route("/api/config/port-forward", post(api_cfg_port_forward))
        .route("/api/config/route", post(api_cfg_route))
        .route("/api/config/proxy-network", post(api_cfg_proxy_network))
        .route("/api/config/exit-node", post(api_cfg_exit_node))
        .route("/api/config/relay-serving", post(api_cfg_relay_serving))
        .route("/api/config/hostname", post(api_cfg_hostname))
        .route("/api/config/ipv4", post(api_cfg_ipv4))
        .route("/api/config/whitelist", post(api_cfg_whitelist))
        .route("/api/config/acl", post(api_cfg_acl))
        .route("/api/trust/create-domain", post(api_trust_create_domain))
        .route("/api/trust/create-network", post(api_trust_create_network))
        .route("/api/trust/upgrade-peer-to-root", post(api_trust_upgrade_root))
        .route("/api/trust/arm-root-upgrade", post(api_trust_arm_root_upgrade))
        .route("/api/trust/tags", get(api_trust_tags))
        .route("/api/trust/tag", post(api_trust_tag))
        .route("/api/trust/peer-hints", get(api_trust_peer_hints))
        .route("/api/trust/peer-hint", post(api_trust_peer_hint))
        .route("/api/trust/invite", post(api_trust_invite))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::guard))
        .with_state(state)
}

// ---------- 响应辅助 ----------

fn build(status: StatusCode, ctype: &str, set_cookie: Option<String>, body: Body) -> Response {
    let mut b = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, ctype);
    if let Some(c) = set_cookie {
        b = b.header(header::SET_COOKIE, c);
    }
    b.body(body).unwrap()
}

/// 指定状态码的 JSON 响应。
fn json_response(status: StatusCode, value: serde_json::Value) -> Response {
    build(status, "application/json", None, Body::from(value.to_string()))
}

/// `{ "error": msg }` + 指定状态码。
fn json_error(status: StatusCode, msg: impl std::fmt::Display) -> Response {
    json_response(status, serde_json::json!({ "error": msg.to_string() }))
}

/// 把 daemon RPC / 本地错误包装为 502 JSON。
struct ApiError(anyhow::Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        build(
            StatusCode::BAD_GATEWAY,
            "application/json",
            None,
            Body::from(serde_json::json!({ "error": self.0.to_string() }).to_string()),
        )
    }
}

impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(e: E) -> Self {
        ApiError(e.into())
    }
}

// ---------- 页面 / 静态资源 ----------

async fn index(State(s): State<AppState>) -> Response {
    let cookie = format!("pm_token={}; Path=/; SameSite=Strict", s.token);
    build(
        StatusCode::OK,
        "text/html; charset=utf-8",
        Some(cookie),
        Body::from(INDEX_HTML),
    )
}

async fn asset_css() -> Response {
    build(StatusCode::OK, "text/css; charset=utf-8", None, Body::from(APP_CSS))
}

async fn asset_js() -> Response {
    build(
        StatusCode::OK,
        "application/javascript; charset=utf-8",
        None,
        Body::from(APP_JS),
    )
}

// ---------- 会话解锁 / 治理写 ----------

async fn api_session(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(session::status(&s).await)
}

#[derive(Deserialize)]
struct UnlockReq {
    trust_domain_id: String,
    network_local_id: String,
    passphrase: String,
}

async fn api_unlock(State(s): State<AppState>, Json(req): Json<UnlockReq>) -> Response {
    match session::unlock(&s, req.trust_domain_id, req.network_local_id, req.passphrase).await {
        Ok(_) => Json(session::status(&s).await).into_response(),
        Err(e) => json_error(StatusCode::UNAUTHORIZED, e),
    }
}

async fn api_lock(State(s): State<AppState>) -> Json<serde_json::Value> {
    session::lock(&s).await;
    Json(session::status(&s).await)
}

async fn api_domains() -> Result<Json<Vec<control::DomainInfo>>, ApiError> {
    Ok(Json(control::list_domains()?))
}

#[derive(Deserialize)]
struct MembersQuery {
    trust_domain_id: String,
    network_local_id: String,
}

/// 富成员列表（DeviceView）。只读：不需解锁，按 query 指定 (td, nid)。
async fn api_members(Query(q): Query<MembersQuery>) -> Response {
    match control::read_network_state(&q.trust_domain_id, &q.network_local_id) {
        Ok((network_dir, _pem, state)) => {
            Json(control::list_member_views(&network_dir, &state, &q.network_local_id))
                .into_response()
        }
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}

#[derive(Deserialize)]
struct RevokeReq {
    fingerprint: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

async fn api_revoke(State(s): State<AppState>, Json(req): Json<RevokeReq>) -> Response {
    let (td, nid, passphrase) = match require_session(&s).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fingerprint = match control::parse_member_cert_fingerprint(&req.fingerprint) {
        Ok(fp) => fp,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    let reason = parse_reason(req.reason.as_deref());
    let note = req.note;

    let revoked_at = now_unix_secs();
    let result = (|| {
        let sess = SigningSession::open(&td, &nid, &passphrase)?;
        let live = sess
            .original_state
            .details
            .payload
            .member_cert_index
            .iter()
            .any(|e| e.fingerprint == fingerprint);
        if !live {
            anyhow::bail!("fingerprint not found in member_cert_index");
        }
        let prev = sess.version();
        let version = sess.commit(|next, _root| {
            next.payload.revoked_certs.push(RevokedCert {
                cert_fingerprint: fingerprint,
                revoked_at,
                reason_code: reason,
                reason_note: note,
            });
            Ok(())
        })?;
        Ok::<(u64, u64), anyhow::Error>((prev, version))
    })();

    version_response(&req.fingerprint, result)
}

#[derive(Deserialize)]
struct DisableReq {
    fingerprint: String,
    /// 期望禁用截止（unix 秒），仅记录于 DisabledCert，不自动重启。
    #[serde(default)]
    until: Option<u64>,
    #[serde(default)]
    note: Option<String>,
}

async fn api_disable(State(s): State<AppState>, Json(req): Json<DisableReq>) -> Response {
    let (td, nid, pass) = match require_session(&s).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fp = match control::parse_member_cert_fingerprint(&req.fingerprint) {
        Ok(fp) => fp,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    let disabled_at = now_unix_secs();
    let until = req.until;
    let note = req.note;
    let result = (|| {
        let sess = SigningSession::open(&td, &nid, &pass)?;
        let payload = &sess.original_state.details.payload;
        if payload.revoked_certs.iter().any(|r| r.cert_fingerprint == fp) {
            anyhow::bail!("fingerprint is permanently revoked; use revoke instead");
        }
        if !payload.member_cert_index.iter().any(|e| e.fingerprint == fp) {
            anyhow::bail!("fingerprint not found in member_cert_index");
        }
        let prev = sess.version();
        let version = sess.commit(|next, _root| {
            next.payload
                .disabled_certs
                .retain(|d| d.cert_fingerprint != fp);
            next.payload.disabled_certs.push(DisabledCert {
                cert_fingerprint: fp,
                disabled_at,
                expected_until: until,
                reason_note: note,
            });
            Ok(())
        })?;
        Ok::<(u64, u64), anyhow::Error>((prev, version))
    })();
    version_response(&req.fingerprint, result)
}

#[derive(Deserialize)]
struct FingerprintReq {
    fingerprint: String,
}

async fn api_enable(State(s): State<AppState>, Json(req): Json<FingerprintReq>) -> Response {
    let (td, nid, pass) = match require_session(&s).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fp = match control::parse_member_cert_fingerprint(&req.fingerprint) {
        Ok(fp) => fp,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    let result = (|| {
        let sess = SigningSession::open(&td, &nid, &pass)?;
        let payload = &sess.original_state.details.payload;
        if payload.revoked_certs.iter().any(|r| r.cert_fingerprint == fp) {
            anyhow::bail!("fingerprint is permanently revoked and cannot be enabled");
        }
        if !payload.disabled_certs.iter().any(|d| d.cert_fingerprint == fp) {
            anyhow::bail!("fingerprint is not disabled");
        }
        let prev = sess.version();
        let version = sess.commit(|next, _root| {
            next.payload
                .disabled_certs
                .retain(|d| d.cert_fingerprint != fp);
            Ok(())
        })?;
        Ok::<(u64, u64), anyhow::Error>((prev, version))
    })();
    version_response(&req.fingerprint, result)
}

#[derive(Deserialize)]
struct RenameReq {
    fingerprint: String,
    label: String,
    #[serde(default)]
    note: Option<String>,
}

async fn api_rename(State(s): State<AppState>, Json(req): Json<RenameReq>) -> Response {
    let (td, nid, pass) = match require_session(&s).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if req.label.trim().is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "device label cannot be empty");
    }
    let fp = match control::parse_member_cert_fingerprint(&req.fingerprint) {
        Ok(fp) => fp,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    let revoked_at = now_unix_secs();
    let result = (|| {
        let sess = SigningSession::open(&td, &nid, &pass)?;
        let old_cert = active_member_cert(&sess, fp)?;
        if old_cert.details.device_label == req.label {
            let v = sess.version();
            return Ok((v, v));
        }
        let mut new_details = old_cert.details.clone();
        new_details.device_label = req.label.clone();
        new_details.network_state_version_ref = sess.version().saturating_add(1);
        reissue(sess, fp, req.note, revoked_at, new_details)
    })();
    version_response(&req.fingerprint, result)
}

#[derive(Deserialize)]
struct HostnameReq {
    fingerprint: String,
    /// `None`/缺省 = 清除主机名；`Some` = 设置（校验唯一）。
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

async fn api_hostname(State(s): State<AppState>, Json(req): Json<HostnameReq>) -> Response {
    let (td, nid, pass) = match require_session(&s).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fp = match control::parse_member_cert_fingerprint(&req.fingerprint) {
        Ok(fp) => fp,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    let revoked_at = now_unix_secs();
    let result = (|| {
        let sess = SigningSession::open(&td, &nid, &pass)?;
        let old_cert = active_member_cert(&sess, fp)?;
        let new_hostname = req
            .hostname
            .as_deref()
            .filter(|h| !h.trim().is_empty())
            .map(HostnameLabel::try_from_str)
            .transpose()
            .map_err(|e| anyhow::anyhow!("invalid hostname: {e}"))?;
        if old_cert.details.hostname == new_hostname {
            let v = sess.version();
            return Ok((v, v));
        }
        if let Some(hostname) = new_hostname.as_ref() {
            let certs = control::read_member_cert_bodies(&sess.network_dir);
            check_hostname_unique(
                hostname,
                &control::live_hostname_entries(&sess.original_state, &certs, fp),
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        let mut new_details = old_cert.details.clone();
        new_details.hostname = new_hostname;
        new_details.network_state_version_ref = sess.version().saturating_add(1);
        reissue(sess, fp, req.note, revoked_at, new_details)
    })();
    version_response(&req.fingerprint, result)
}

#[derive(Deserialize)]
struct CapabilityReq {
    fingerprint: String,
    #[serde(default)]
    relay_data: Option<bool>,
    #[serde(default)]
    relay_control: Option<bool>,
    #[serde(default)]
    proxy_subnet: Option<Vec<String>>,
    #[serde(default)]
    clear_proxy_subnet: bool,
    #[serde(default)]
    note: Option<String>,
}

async fn api_capability(State(s): State<AppState>, Json(req): Json<CapabilityReq>) -> Response {
    let (td, nid, pass) = match require_session(&s).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fp = match control::parse_member_cert_fingerprint(&req.fingerprint) {
        Ok(fp) => fp,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    let revoked_at = now_unix_secs();
    let result = (|| {
        let subnets = req.proxy_subnet.unwrap_or_default();
        if req.clear_proxy_subnet && !subnets.is_empty() {
            anyhow::bail!("clear_proxy_subnet cannot be combined with proxy_subnet");
        }
        if req.relay_data.is_none()
            && req.relay_control.is_none()
            && !req.clear_proxy_subnet
            && subnets.is_empty()
        {
            anyhow::bail!("no capability change requested");
        }
        let sess = SigningSession::open(&td, &nid, &pass)?;
        let old_cert = active_member_cert(&sess, fp)?;
        let mut capabilities = old_cert.details.capabilities.clone();
        if let Some(relay_data) = req.relay_data {
            capabilities.can_relay_data = relay_data;
        }
        if let Some(relay_control) = req.relay_control {
            capabilities.can_relay_control = relay_control;
        }
        if req.clear_proxy_subnet {
            capabilities.can_proxy_subnet.clear();
        } else if !subnets.is_empty() {
            let mut parsed = subnets
                .iter()
                .map(|s| {
                    s.parse::<pnet::ipnetwork::IpNetwork>()
                        .map_err(|e| anyhow::anyhow!("invalid proxy subnet '{s}': {e}"))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            parsed.sort_by_key(|net| net.to_string());
            parsed.dedup();
            capabilities.can_proxy_subnet = parsed;
        }
        if capabilities == old_cert.details.capabilities {
            let v = sess.version();
            return Ok((v, v));
        }
        let mut new_details = old_cert.details.clone();
        new_details.capabilities = capabilities;
        new_details.network_state_version_ref = sess.version().saturating_add(1);
        reissue(sess, fp, req.note, revoked_at, new_details)
    })();
    version_response(&req.fingerprint, result)
}

// ---------- Pending join：列出 / approve / reject ----------

#[derive(Deserialize)]
struct PendingQuery {
    trust_domain_id: String,
    network_local_id: String,
}

/// 列出某网络的待批入网申请（daemon RPC，只读，不需解锁）。
async fn api_pending(State(s): State<AppState>, Query(q): Query<PendingQuery>) -> Response {
    let result = async {
        let td_bytes = parse_b64(&q.trust_domain_id)?;
        let client = {
            let mut g = s.client.lock().await;
            g.scoped_client::<TrustJoinManageRpcClientFactory<BaseController>>(String::new())
                .await?
        };
        let resp = client
            .list_pending_join_requests(
                BaseController::default(),
                ListPendingJoinRequestsRequest {
                    instance: Some(s.instance.clone()),
                    trust_domain_id: td_bytes,
                    network_local_id: q.network_local_id.clone(),
                },
            )
            .await?;
        let items = resp
            .requests
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "applicant_pk": b64(&r.applicant_pk),
                    "device_label": r.device_label,
                    "hint": r.hint,
                    "network_local_id": r.network_local_id,
                })
            })
            .collect::<Vec<_>>();
        Ok::<_, anyhow::Error>(items)
    }
    .await;
    match result {
        Ok(items) => json_response(StatusCode::OK, serde_json::Value::Array(items)),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}

#[derive(Deserialize)]
struct ApproveReq {
    applicant_pk: String,
    device_label: String,
}

/// 批准入网：签发成员证书 + 通知 daemon + 落盘新状态（需解锁，绑定会话的 td/nid）。
async fn api_approve(State(s): State<AppState>, Json(req): Json<ApproveReq>) -> Response {
    let (td, nid, passphrase) = match require_session(&s).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let result = async {
        let row = JoinRow {
            trust_domain_id: parse_b64(&td)?,
            trust_domain_id_b64: td.clone(),
            network_local_id: nid.clone(),
            applicant_pk: parse_b64(&req.applicant_pk)?,
            applicant_short: String::new(),
            device_label: req.device_label.clone(),
            hint: String::new(),
        };
        crate::tui::actions::approve_join(&s.client, &s.instance, &row, passphrase.as_str()).await
    }
    .await;
    match result {
        Ok(out) => json_response(
            StatusCode::OK,
            serde_json::json!({
                "device_label": out.device_label,
                "fingerprint_short": out.short_fp,
                "version": out.network_state_version,
            }),
        ),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}

#[derive(Deserialize)]
struct RejectReq {
    trust_domain_id: String,
    network_local_id: String,
    applicant_pk: String,
}

/// 拒绝入网：daemon RPC（不签名、不需解锁）。
async fn api_reject(State(s): State<AppState>, Json(req): Json<RejectReq>) -> Response {
    let result = async {
        let td_bytes = parse_b64(&req.trust_domain_id)?;
        let applicant_pk = parse_b64(&req.applicant_pk)?;
        let client = {
            let mut g = s.client.lock().await;
            g.scoped_client::<TrustJoinManageRpcClientFactory<BaseController>>(String::new())
                .await?
        };
        client
            .reject_join_request(
                BaseController::default(),
                RejectJoinRequestRequest {
                    instance: Some(s.instance.clone()),
                    trust_domain_id: td_bytes,
                    network_local_id: req.network_local_id.clone(),
                    applicant_pk,
                },
            )
            .await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    match result {
        Ok(()) => json_response(StatusCode::OK, serde_json::json!({ "status": "rejected" })),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}

// ---------- 辅助 ----------

/// b64(URL_SAFE_NO_PAD) 编码字节。
fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// 解码 b64（URL_SAFE_NO_PAD 优先，回退 STANDARD）为字节。
fn parse_b64(value: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(value))
        .map_err(|_| anyhow::anyhow!("invalid base64 '{value}'"))
}

/// 取已解锁会话快照，未解锁返回 403 响应。
async fn require_session(
    s: &AppState,
) -> Result<(String, String, Zeroizing<String>), Response> {
    session::snapshot(s)
        .await
        .ok_or_else(|| json_error(StatusCode::FORBIDDEN, "locked: POST /api/unlock first"))
}

/// 校验指纹在 index 中且未吊销，返回其活跃成员证书（用于重签发改签）。
fn active_member_cert(
    sess: &SigningSession,
    fp: MemberCertFingerprint,
) -> anyhow::Result<crate::trust::MemberCert> {
    if !sess
        .original_state
        .details
        .payload
        .member_cert_index
        .iter()
        .any(|e| e.fingerprint == fp)
    {
        anyhow::bail!("fingerprint not found in member_cert_index");
    }
    if control::member_status(&fp, &sess.original_state) == "revoked" {
        anyhow::bail!("fingerprint is revoked");
    }
    control::read_member_cert_bodies(&sess.network_dir)
        .get(&fp)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("member cert body not found; cannot reissue"))
}

/// 重签发改签的通用尾部：版本+1 → 签新证书 → 旧证书记为 superseded → 替换 index → 落盘。
fn reissue(
    sess: SigningSession,
    old_fp: MemberCertFingerprint,
    note: Option<String>,
    revoked_at: u64,
    new_details: UnsignedMemberCert,
) -> anyhow::Result<(u64, u64)> {
    let network_dir = sess.network_dir.clone();
    let prev = sess.version();
    let version = sess.commit(move |next, root| {
        let new_cert = new_details.sign(root);
        next.payload.revoked_certs.push(RevokedCert {
            cert_fingerprint: old_fp,
            revoked_at,
            reason_code: RevocationReason::Superseded,
            reason_note: note,
        });
        control::replace_member_index_entry(&mut next.payload.member_cert_index, old_fp, &new_cert);
        control::write_reissued_member_cert(&network_dir, &new_cert)?;
        Ok(())
    })?;
    Ok((prev, version))
}

/// `{fingerprint, previous_version, version}` 成功响应 / 502 错误响应。
fn version_response(fingerprint: &str, result: anyhow::Result<(u64, u64)>) -> Response {
    match result {
        Ok((prev, version)) => json_response(
            StatusCode::OK,
            serde_json::json!({
                "fingerprint": fingerprint,
                "previous_version": prev,
                "version": version,
            }),
        ),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn parse_reason(value: Option<&str>) -> RevocationReason {
    match value.unwrap_or("unspecified") {
        "key-compromise" | "key_compromise" => RevocationReason::KeyCompromise,
        "device-lost" | "device_lost" => RevocationReason::DeviceLost,
        "removed" => RevocationReason::Removed,
        "superseded" => RevocationReason::Superseded,
        _ => RevocationReason::Unspecified,
    }
}

// ---------- 只读 RPC 端点 ----------

async fn api_node(State(s): State<AppState>) -> Result<Json<ShowNodeInfoResponse>, ApiError> {
    let client = {
        let mut g = s.client.lock().await;
        g.scoped_client::<PeerManageRpcClientFactory<BaseController>>(String::new())
            .await?
    };
    let resp = client
        .show_node_info(
            BaseController::default(),
            ShowNodeInfoRequest {
                instance: Some(s.instance.clone()),
            },
        )
        .await?;
    Ok(Json(resp))
}

async fn api_peers(State(s): State<AppState>) -> Result<Json<ListPeerResponse>, ApiError> {
    let client = {
        let mut g = s.client.lock().await;
        g.scoped_client::<PeerManageRpcClientFactory<BaseController>>(String::new())
            .await?
    };
    let resp = client
        .list_peer(
            BaseController::default(),
            ListPeerRequest {
                instance: Some(s.instance.clone()),
            },
        )
        .await?;
    Ok(Json(resp))
}

async fn api_routes(State(s): State<AppState>) -> Result<Json<ListRouteResponse>, ApiError> {
    let client = {
        let mut g = s.client.lock().await;
        g.scoped_client::<PeerManageRpcClientFactory<BaseController>>(String::new())
            .await?
    };
    let resp = client
        .list_route(
            BaseController::default(),
            ListRouteRequest {
                instance: Some(s.instance.clone()),
            },
        )
        .await?;
    Ok(Json(resp))
}

async fn api_stats(State(s): State<AppState>) -> Result<Json<GetStatsResponse>, ApiError> {
    let client = {
        let mut g = s.client.lock().await;
        g.scoped_client::<StatsRpcClientFactory<BaseController>>(String::new())
            .await?
    };
    let resp = client
        .get_stats(
            BaseController::default(),
            GetStatsRequest {
                instance: Some(s.instance.clone()),
            },
        )
        .await?;
    Ok(Json(resp))
}

// ---------- M3：只读视图（daemon RPC 透传，仅含 instance 的请求） ----------

/// 生成一个只取 `instance` 的只读端点：建 scoped client → 调方法 → `Json(resp)`。
macro_rules! rpc_view {
    ($name:ident, $factory:ident, $method:ident, $req:ident, $resp:ty) => {
        async fn $name(State(s): State<AppState>) -> Result<Json<$resp>, ApiError> {
            let client = {
                let mut g = s.client.lock().await;
                g.scoped_client::<$factory<BaseController>>(String::new()).await?
            };
            let resp = client
                .$method(
                    BaseController::default(),
                    $req {
                        instance: Some(s.instance.clone()),
                    },
                )
                .await?;
            Ok(Json(resp))
        }
    };
}

rpc_view!(api_connectors, ConnectorManageRpcClientFactory, list_connector, ListConnectorRequest, ListConnectorResponse);
rpc_view!(api_mapped_listeners, MappedListenerManageRpcClientFactory, list_mapped_listener, ListMappedListenerRequest, ListMappedListenerResponse);
rpc_view!(api_port_forwards, PortForwardManageRpcClientFactory, list_port_forward, ListPortForwardRequest, ListPortForwardResponse);
rpc_view!(api_tcp_proxy, TcpProxyRpcClientFactory, list_tcp_proxy_entry, ListTcpProxyEntryRequest, ListTcpProxyEntryResponse);
rpc_view!(api_vpn_portal, VpnPortalRpcClientFactory, get_vpn_portal_info, GetVpnPortalInfoRequest, GetVpnPortalInfoResponse);
rpc_view!(api_acl_stats, AclManageRpcClientFactory, get_acl_stats, GetAclStatsRequest, GetAclStatsResponse);
rpc_view!(api_whitelist, AclManageRpcClientFactory, get_whitelist, GetWhitelistRequest, GetWhitelistResponse);
rpc_view!(api_get_config, ConfigRpcClientFactory, get_config, GetConfigRequest, GetConfigResponse);
rpc_view!(api_credentials, CredentialManageRpcClientFactory, list_credentials, ListCredentialsRequest, ListCredentialsResponse);

// ---------- M3：凭据签发 / 吊销（daemon RPC，无 root 口令） ----------

#[derive(Deserialize)]
struct GenerateCredentialReq {
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    allow_relay: bool,
    #[serde(default)]
    allowed_proxy_cidrs: Vec<String>,
    ttl_seconds: i64,
    #[serde(default)]
    credential_id: Option<String>,
    #[serde(default)]
    reusable: Option<bool>,
}

async fn api_cred_generate(
    State(s): State<AppState>,
    Json(req): Json<GenerateCredentialReq>,
) -> Result<Json<GenerateCredentialResponse>, ApiError> {
    if req.ttl_seconds <= 0 {
        return Err(anyhow::anyhow!("ttl_seconds must be > 0").into());
    }
    let client = {
        let mut g = s.client.lock().await;
        g.scoped_client::<CredentialManageRpcClientFactory<BaseController>>(String::new())
            .await?
    };
    let resp = client
        .generate_credential(
            BaseController::default(),
            GenerateCredentialRequest {
                groups: req.groups,
                allow_relay: req.allow_relay,
                allowed_proxy_cidrs: req.allowed_proxy_cidrs,
                ttl_seconds: req.ttl_seconds,
                credential_id: req.credential_id,
                instance: Some(s.instance.clone()),
                reusable: req.reusable,
            },
        )
        .await?;
    Ok(Json(resp))
}

#[derive(Deserialize)]
struct RevokeCredentialReq {
    credential_id: String,
}

async fn api_cred_revoke(State(s): State<AppState>, Json(req): Json<RevokeCredentialReq>) -> Response {
    let result = async {
        let client = {
            let mut g = s.client.lock().await;
            g.scoped_client::<CredentialManageRpcClientFactory<BaseController>>(String::new())
                .await?
        };
        let resp = client
            .revoke_credential(
                BaseController::default(),
                RevokeCredentialRequest {
                    credential_id: req.credential_id.clone(),
                    instance: Some(s.instance.clone()),
                },
            )
            .await?;
        Ok::<bool, anyhow::Error>(resp.success)
    }
    .await;
    match result {
        Ok(success) => json_response(StatusCode::OK, serde_json::json!({ "success": success })),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}

// ---------- M3：配置下发 PatchConfig（daemon RPC，无 root 口令） ----------

/// 把一个 InstanceConfigPatch 经 ConfigRpc.PatchConfig 下发给本地 daemon 热重载。
async fn apply_patch(s: &AppState, patch: InstanceConfigPatch) -> anyhow::Result<()> {
    let client = {
        let mut g = s.client.lock().await;
        g.scoped_client::<ConfigRpcClientFactory<BaseController>>(String::new())
            .await?
    };
    client
        .patch_config(
            BaseController::default(),
            PatchConfigRequest {
                patch: Some(patch),
                instance: Some(s.instance.clone()),
                network_state_cbor: None,
            },
        )
        .await?;
    Ok(())
}

/// "ok" / 502 包装：配置 patch 端点统一返回。
fn patch_response(result: anyhow::Result<()>) -> Response {
    match result {
        Ok(()) => json_response(StatusCode::OK, serde_json::json!({ "status": "ok" })),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}

fn parse_action(a: &str) -> anyhow::Result<ConfigPatchAction> {
    match a {
        "add" => Ok(ConfigPatchAction::Add),
        "remove" => Ok(ConfigPatchAction::Remove),
        "clear" => Ok(ConfigPatchAction::Clear),
        other => anyhow::bail!("invalid action '{other}' (add|remove|clear)"),
    }
}

#[derive(Deserialize)]
struct UrlPatchReq {
    action: String,
    url: String,
}

async fn api_cfg_connector(State(s): State<AppState>, Json(req): Json<UrlPatchReq>) -> Response {
    patch_response(
        async {
            let action = parse_action(&req.action)?;
            let url = url::Url::parse(&req.url)
                .map_err(|e| anyhow::anyhow!("invalid url ({}): {e}", req.url))?;
            apply_patch(
                &s,
                InstanceConfigPatch {
                    connectors: vec![UrlPatch {
                        action: action.into(),
                        url: Some(url.into()),
                    }],
                    ..Default::default()
                },
            )
            .await
        }
        .await,
    )
}

async fn api_cfg_mapped_listener(State(s): State<AppState>, Json(req): Json<UrlPatchReq>) -> Response {
    patch_response(
        async {
            let action = parse_action(&req.action)?;
            let url = url::Url::parse(&req.url)
                .map_err(|e| anyhow::anyhow!("invalid url ({}): {e}", req.url))?;
            apply_patch(
                &s,
                InstanceConfigPatch {
                    mapped_listeners: vec![UrlPatch {
                        action: action.into(),
                        url: Some(url.into()),
                    }],
                    ..Default::default()
                },
            )
            .await
        }
        .await,
    )
}

#[derive(Deserialize)]
struct PortForwardReq {
    action: String,
    protocol: String,
    bind_addr: String,
    #[serde(default)]
    dst_addr: Option<String>,
}

async fn api_cfg_port_forward(State(s): State<AppState>, Json(req): Json<PortForwardReq>) -> Response {
    patch_response(
        async {
            let action = parse_action(&req.action)?;
            let bind_addr: std::net::SocketAddr = req
                .bind_addr
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid bind address {}: {e}", req.bind_addr))?;
            let dst_addr = req
                .dst_addr
                .as_deref()
                .map(|s| {
                    s.parse::<std::net::SocketAddr>()
                        .map_err(|e| anyhow::anyhow!("invalid dst address {s}: {e}"))
                })
                .transpose()?;
            let socket_type = match req.protocol.as_str() {
                "tcp" => SocketType::Tcp,
                "udp" => SocketType::Udp,
                other => anyhow::bail!("protocol must be tcp or udp, got '{other}'"),
            };
            apply_patch(
                &s,
                InstanceConfigPatch {
                    port_forwards: vec![PortForwardPatch {
                        action: action.into(),
                        cfg: Some(PortForwardConfigPb {
                            bind_addr: Some(bind_addr.into()),
                            dst_addr: dst_addr.map(Into::into),
                            socket_type: socket_type.into(),
                        }),
                    }],
                    ..Default::default()
                },
            )
            .await
        }
        .await,
    )
}

#[derive(Deserialize)]
struct CidrReq {
    action: String,
    cidr: String,
}

async fn api_cfg_route(State(s): State<AppState>, Json(req): Json<CidrReq>) -> Response {
    patch_response(
        async {
            let action = parse_action(&req.action)?;
            let cidr = Ipv4Inet::from_str(&req.cidr)
                .map_err(|e| anyhow::anyhow!("invalid cidr {}: {e}", req.cidr))?;
            apply_patch(
                &s,
                InstanceConfigPatch {
                    routes: vec![RoutePatch {
                        action: action.into(),
                        cidr: Some(cidr),
                    }],
                    ..Default::default()
                },
            )
            .await
        }
        .await,
    )
}

#[derive(Deserialize)]
struct ProxyNetworkReq {
    action: String,
    cidr: String,
    #[serde(default)]
    mapped_cidr: Option<String>,
}

async fn api_cfg_proxy_network(State(s): State<AppState>, Json(req): Json<ProxyNetworkReq>) -> Response {
    patch_response(
        async {
            let action = parse_action(&req.action)?;
            let cidr = Ipv4Inet::from_str(&req.cidr)
                .map_err(|e| anyhow::anyhow!("invalid cidr {}: {e}", req.cidr))?;
            let mapped_cidr = req
                .mapped_cidr
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .map(|s| {
                    Ipv4Inet::from_str(s).map_err(|e| anyhow::anyhow!("invalid mapped_cidr {s}: {e}"))
                })
                .transpose()?;
            apply_patch(
                &s,
                InstanceConfigPatch {
                    proxy_networks: vec![ProxyNetworkPatch {
                        action: action.into(),
                        cidr: Some(cidr),
                        mapped_cidr,
                    }],
                    ..Default::default()
                },
            )
            .await
        }
        .await,
    )
}

#[derive(Deserialize)]
struct ExitNodeReq {
    action: String,
    node: String,
}

async fn api_cfg_exit_node(State(s): State<AppState>, Json(req): Json<ExitNodeReq>) -> Response {
    patch_response(
        async {
            let action = parse_action(&req.action)?;
            let node: std::net::IpAddr = req
                .node
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid ip address {}: {e}", req.node))?;
            apply_patch(
                &s,
                InstanceConfigPatch {
                    exit_nodes: vec![ExitNodePatch {
                        action: action.into(),
                        node: Some(node.into()),
                    }],
                    ..Default::default()
                },
            )
            .await
        }
        .await,
    )
}

#[derive(Deserialize)]
struct RelayServingReq {
    action: String,
    foreign_root_pk_hex: String,
    #[serde(default)]
    can_relay_data: bool,
    #[serde(default)]
    can_assist_holepunch: bool,
    #[serde(default)]
    ttl_secs: u64,
}

async fn api_cfg_relay_serving(State(s): State<AppState>, Json(req): Json<RelayServingReq>) -> Response {
    patch_response(
        async {
            let action = parse_action(&req.action)?;
            let expires_at = now_unix_secs().saturating_add(req.ttl_secs);
            apply_patch(
                &s,
                InstanceConfigPatch {
                    relay_serving: vec![RelayServingPatch {
                        action: action.into(),
                        foreign_root_pk_hex: req.foreign_root_pk_hex.clone(),
                        can_relay_data: req.can_relay_data,
                        can_assist_holepunch: req.can_assist_holepunch,
                        expires_at,
                    }],
                    ..Default::default()
                },
            )
            .await
        }
        .await,
    )
}

#[derive(Deserialize)]
struct HostnameCfgReq {
    hostname: String,
}

async fn api_cfg_hostname(State(s): State<AppState>, Json(req): Json<HostnameCfgReq>) -> Response {
    patch_response(
        apply_patch(
            &s,
            InstanceConfigPatch {
                hostname: Some(req.hostname),
                ..Default::default()
            },
        )
        .await,
    )
}

#[derive(Deserialize)]
struct Ipv4CfgReq {
    ipv4: String,
}

async fn api_cfg_ipv4(State(s): State<AppState>, Json(req): Json<Ipv4CfgReq>) -> Response {
    patch_response(
        async {
            let ipv4 = Ipv4Inet::from_str(&req.ipv4)
                .map_err(|e| anyhow::anyhow!("invalid ipv4 inet {}: {e}", req.ipv4))?;
            apply_patch(
                &s,
                InstanceConfigPatch {
                    ipv4: Some(ipv4),
                    ..Default::default()
                },
            )
            .await
        }
        .await,
    )
}

#[derive(Deserialize)]
struct WhitelistCfgReq {
    /// "tcp" 或 "udp"。
    kind: String,
    /// 端口/区间列表，逗号分隔；`clear=true` 时忽略。
    #[serde(default)]
    ports: String,
    /// 仅清空白名单。
    #[serde(default)]
    clear: bool,
}

async fn api_cfg_whitelist(State(s): State<AppState>, Json(req): Json<WhitelistCfgReq>) -> Response {
    patch_response(
        async {
            let is_tcp = match req.kind.as_str() {
                "tcp" => true,
                "udp" => false,
                other => anyhow::bail!("kind must be tcp or udp, got '{other}'"),
            };
            // Clear 头 + 逐项 Add，整列替换语义（同 CLI whitelist set）。
            let mut patches = vec![StringPatch {
                action: ConfigPatchAction::Clear.into(),
                value: String::new(),
            }];
            if !req.clear {
                for p in req.ports.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                    patches.push(StringPatch {
                        action: ConfigPatchAction::Add.into(),
                        value: p.to_string(),
                    });
                }
            }
            let acl = if is_tcp {
                AclPatch {
                    tcp_whitelist: patches,
                    ..Default::default()
                }
            } else {
                AclPatch {
                    udp_whitelist: patches,
                    ..Default::default()
                }
            };
            apply_patch(
                &s,
                InstanceConfigPatch {
                    acl: Some(acl),
                    ..Default::default()
                },
            )
            .await
        }
        .await,
    )
}

/// ACL 表单编辑器：前端拉 `/api/config` 取当前 acl，编辑 chains/rules 后整体回传。
async fn api_cfg_acl(State(s): State<AppState>, Json(acl): Json<Acl>) -> Response {
    patch_response(
        apply_patch(
            &s,
            InstanceConfigPatch {
                acl: Some(AclPatch {
                    acl: Some(acl),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await,
    )
}

// ---------- M4：引导/高危治理（建域/建网/升根/tags/peer-hints/invite） ----------

#[derive(Deserialize)]
struct CreateDomainReq {
    label: String,
    /// 新管理口令（确立该信任域的 root 口令；即用即清，绝不缓存/落盘）。
    passphrase: String,
}

/// 建域：生成新 root + 新管理口令。高危——前端二次确认。口令用 `Zeroizing` 即用即清。
async fn api_trust_create_domain(Json(req): Json<CreateDomainReq>) -> Response {
    let passphrase = Zeroizing::new(req.passphrase);
    match control::create_domain(&req.label, passphrase.as_str()) {
        Ok(out) => json_response(StatusCode::OK, serde_json::json!(out)),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}

#[derive(Deserialize)]
struct CreateNetworkReq {
    trust_domain_id: String,
    network_local_id: String,
    /// 解锁既有域 root 的管理口令（即用即清）。
    passphrase: String,
    #[serde(default = "default_acl_action")]
    default_action: String,
}

fn default_acl_action() -> String {
    "accept".to_string()
}

/// 建网：在既有域下解锁 root，签发 v1 空状态。口令即用即清。
async fn api_trust_create_network(Json(req): Json<CreateNetworkReq>) -> Response {
    let passphrase = Zeroizing::new(req.passphrase);
    match control::create_network(
        &req.trust_domain_id,
        &req.network_local_id,
        &req.default_action,
        passphrase.as_str(),
    ) {
        Ok(out) => json_response(StatusCode::OK, serde_json::json!(out)),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}

#[derive(Deserialize)]
struct UpgradeRootReq {
    peer_id: u32,
}

/// 升级 peer 为 root：解锁本域 root → 导出 sk_root 升级载荷 → daemon RPC 推送。高危。
async fn api_trust_upgrade_root(State(s): State<AppState>, Json(req): Json<UpgradeRootReq>) -> Response {
    let (td, nid, pass) = match require_session(&s).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let result = async {
        let td_bytes = parse_b64(&td)?;
        let sess = SigningSession::open(&td, &nid, &pass)?;
        let sk_root_payload = sess.root.export_secret_for_root_upgrade().to_vec();
        let client = {
            let mut g = s.client.lock().await;
            g.scoped_client::<TrustJoinManageRpcClientFactory<BaseController>>(String::new())
                .await?
        };
        let resp = client
            .upgrade_peer_to_root(
                BaseController::default(),
                UpgradePeerToRootRequest {
                    instance: Some(s.instance.clone()),
                    trust_domain_id: td_bytes,
                    network_local_id: nid.clone(),
                    peer_id: req.peer_id,
                    sk_root_payload,
                },
            )
            .await?;
        Ok::<bool, anyhow::Error>(resp.ack)
    }
    .await;
    match result {
        Ok(ack) => json_response(
            StatusCode::OK,
            serde_json::json!({ "ack": ack, "peer_id": req.peer_id }),
        ),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}

#[derive(Deserialize)]
struct ArmRootUpgradeReq {
    /// 本机被升级后将用作 root 管理口令的一次性令牌。
    passphrase: String,
    #[serde(default = "default_arm_ttl")]
    ttl_secs: u32,
}

fn default_arm_ttl() -> u32 {
    300
}

/// 本机预授权 root 升级（daemon 武装限时一次性接受令牌）。无需会话解锁。
async fn api_trust_arm_root_upgrade(
    State(s): State<AppState>,
    Json(req): Json<ArmRootUpgradeReq>,
) -> Response {
    let passphrase = Zeroizing::new(req.passphrase);
    let result =
        crate::tui::actions::arm_root_upgrade(&s.client, &s.instance, passphrase.as_str(), req.ttl_secs)
            .await;
    match result {
        Ok(ttl) => json_response(StatusCode::OK, serde_json::json!({ "armed_ttl_secs": ttl })),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}

#[derive(Deserialize)]
struct NetworkQuery {
    trust_domain_id: String,
    network_local_id: String,
}

/// 列出 ACL tags（只读，不需解锁）。
async fn api_trust_tags(Query(q): Query<NetworkQuery>) -> Response {
    let result = (|| {
        let (_dir, _pem, state) =
            control::read_network_state(&q.trust_domain_id, &q.network_local_id)?;
        let policy = control::acl_policy_from_state(&state)?;
        let rows = policy
            .tags
            .iter()
            .map(|(tag, members)| {
                serde_json::json!({
                    "tag": tag.as_str(),
                    "members": members
                        .iter()
                        .map(|m| MemberCertFingerprint(m.0).to_string())
                        .collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>();
        Ok::<_, anyhow::Error>(rows)
    })();
    match result {
        Ok(rows) => json_response(StatusCode::OK, serde_json::Value::Array(rows)),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}

#[derive(Deserialize)]
struct TagReq {
    fingerprint: String,
    tag: String,
    add: bool,
}

/// 给成员增删 ACL tag（需解锁，签名落盘）。
async fn api_trust_tag(State(s): State<AppState>, Json(req): Json<TagReq>) -> Response {
    let (td, nid, pass) = match require_session(&s).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let result = (|| {
        let tag = TagName::try_from_str(&req.tag)
            .map_err(|e| anyhow::anyhow!("invalid tag '{}': {e}", req.tag))?;
        let fp = control::parse_member_cert_fingerprint(&req.fingerprint)?;
        let sess = SigningSession::open(&td, &nid, &pass)?;
        if !sess
            .original_state
            .details
            .payload
            .member_cert_index
            .iter()
            .any(|e| e.fingerprint == fp)
        {
            anyhow::bail!("fingerprint not found in member_cert_index");
        }
        if control::member_status(&fp, &sess.original_state) == "revoked" {
            anyhow::bail!("fingerprint is revoked");
        }
        let member = control::cert_to_device_fingerprint(fp);
        let mut policy = control::acl_policy_from_state(&sess.original_state)?;
        if !apply_tag(&mut policy, &tag, member, req.add) {
            let v = sess.version();
            return Ok((v, v));
        }
        control::validate_acl_for_signing(&policy, &sess.network_dir, &sess.original_state)?;
        let encoded = control::encode_acl_policy(&policy);
        let prev = sess.version();
        let version = sess.commit(move |next, _root| {
            next.payload.acl = encoded;
            Ok(())
        })?;
        Ok::<(u64, u64), anyhow::Error>((prev, version))
    })();
    version_response(&req.fingerprint, result)
}

/// tag 增删的纯逻辑（与 CLI `handle_trust_tag_update` 同形）。返回是否有变更。
fn apply_tag(policy: &mut crate::trust::AclPolicy, tag: &TagName, member: DeviceFingerprint, add: bool) -> bool {
    if add {
        let members = policy.tags.entry(tag.clone()).or_default();
        if members.contains(&member) {
            false
        } else {
            members.push(member);
            members.sort_unstable();
            true
        }
    } else if let Some(members) = policy.tags.get_mut(tag) {
        let old_len = members.len();
        members.retain(|existing| *existing != member);
        let changed = members.len() != old_len;
        if members.is_empty() {
            policy.tags.remove(tag);
        }
        changed
    } else {
        false
    }
}

/// 列出 peer-hints（只读，不需解锁）。
async fn api_trust_peer_hints(Query(q): Query<NetworkQuery>) -> Response {
    match control::read_network_state(&q.trust_domain_id, &q.network_local_id) {
        Ok((_dir, _pem, state)) => {
            let mut hints = state.details.payload.peer_hints;
            hints.sort_by(|a, b| a.url.cmp(&b.url));
            let rows = hints
                .into_iter()
                .map(|h| {
                    serde_json::json!({
                        "url": h.url,
                        "label": h.label,
                        "capabilities": h.capabilities,
                        "updated_at": h.updated_at,
                        "expires_at": h.expires_at,
                    })
                })
                .collect::<Vec<_>>();
            json_response(StatusCode::OK, serde_json::Value::Array(rows))
        }
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}

#[derive(Deserialize)]
struct PeerHintReq {
    url: String,
    add: bool,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    expires_at: Option<u64>,
}

/// 增删 peer-hint（需解锁，签名落盘）。
async fn api_trust_peer_hint(State(s): State<AppState>, Json(req): Json<PeerHintReq>) -> Response {
    let (td, nid, pass) = match require_session(&s).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let updated_at = now_unix_secs();
    let result = (|| {
        let url = url::Url::parse(&req.url)
            .map_err(|e| anyhow::anyhow!("invalid url '{}': {e}", req.url))?
            .to_string();
        let sess = SigningSession::open(&td, &nid, &pass)?;
        let mut hints = sess.original_state.details.payload.peer_hints.clone();
        let changed = if req.add {
            let hint = PeerHint {
                url: url.clone(),
                label: req.label.clone(),
                capabilities: normalize_capabilities(req.capabilities.clone()),
                updated_at,
                expires_at: req.expires_at,
            };
            match hints.iter_mut().find(|e| e.url == url) {
                Some(existing) if *existing == hint => false,
                Some(existing) => {
                    *existing = hint;
                    true
                }
                None => {
                    hints.push(hint);
                    true
                }
            }
        } else {
            let old_len = hints.len();
            hints.retain(|e| e.url != url);
            hints.len() != old_len
        };
        if !changed {
            let v = sess.version();
            return Ok((v, v));
        }
        hints.sort_by(|a, b| a.url.cmp(&b.url));
        let prev = sess.version();
        let version = sess.commit(move |next, _root| {
            next.payload.peer_hints = hints;
            Ok(())
        })?;
        Ok::<(u64, u64), anyhow::Error>((prev, version))
    })();
    match result {
        Ok((prev, version)) => json_response(
            StatusCode::OK,
            serde_json::json!({ "previous_version": prev, "version": version }),
        ),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}

/// peer-hint capabilities 规范化（trim/小写/去重/排序），同 CLI。
fn normalize_capabilities(mut caps: Vec<String>) -> Vec<String> {
    for c in &mut caps {
        *c = c.trim().to_ascii_lowercase();
    }
    caps.retain(|c| !c.is_empty());
    caps.sort();
    caps.dedup();
    caps
}

#[derive(Deserialize)]
struct InviteReq {
    trust_domain_id: String,
    network_local_id: String,
    seeds: Vec<String>,
    #[serde(default = "default_invite_format")]
    format: String,
}

fn default_invite_format() -> String {
    "url".to_string()
}

/// 导出入网引导 invite（url|file）。只读，不解锁。
async fn api_trust_invite(Json(req): Json<InviteReq>) -> Response {
    let result = (|| {
        let seeds = req
            .seeds
            .iter()
            .map(|s| {
                url::Url::parse(s.trim()).map_err(|e| anyhow::anyhow!("invalid seed '{s}': {e}"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        control::export_invite(
            &req.trust_domain_id,
            &req.network_local_id,
            seeds,
            &req.format,
        )
    })();
    match result {
        Ok(out) => json_response(StatusCode::OK, serde_json::json!({ "invite": out })),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}
