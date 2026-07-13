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

use super::{access, auth, session, AppState};
use crate::control::{self, SigningSession};
use crate::proto::acl::Acl;
use crate::proto::api::config::{
    AclPatch, ConfigPatchAction, ConfigRpc, ConfigRpcClientFactory, ExitNodePatch,
    GetConfigRequest, GetConfigResponse, InstanceConfigPatch, ListPeerTrustIdentitiesRequest,
    ListPendingJoinRequestsRequest,
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
    GetWhitelistResponse, InstanceIdentifier, ListConnectorRequest, ListConnectorResponse,
    ListCredentialsRequest,
    ListCredentialsResponse, ListMappedListenerRequest, ListMappedListenerResponse,
    ListPeerRequest, ListPeerResponse, ListPortForwardRequest, ListPortForwardResponse,
    ListRouteRequest, ListRouteResponse, ListTcpProxyEntryRequest, ListTcpProxyEntryResponse,
    MappedListenerManageRpc, MappedListenerManageRpcClientFactory, NodeInfo, PeerManageRpc,
    PeerManageRpcClientFactory, PortForwardManageRpc, PortForwardManageRpcClientFactory,
    RevokeCredentialRequest, ShowNodeInfoRequest, ShowNodeInfoResponse, StatsRpc,
    StatsRpcClientFactory, TcpProxyRpc, TcpProxyRpcClientFactory, VpnPortalRpc,
    VpnPortalRpcClientFactory,
};
use std::str::FromStr;
use anyhow::Context as _;
use crate::proto::rpc_types::controller::BaseController;
use crate::proto::api::manage::{
    DeleteNetworkInstanceRequest, ListNetworkInstanceRequest,
    ListNetworkInstanceResponse, NetworkConfig, NetworkingMethod, RunNetworkInstanceRequest,
    TrustDomainLocator, WebClientService, WebClientServiceClientFactory,
};
use crate::trust::{
    AssignedIpv4, CapabilityGrant, DeviceFingerprint, DisabledCert, HostnameBinding, IpAssignment,
    LabelBinding, MemberCertFingerprint, NetworkBootstrap, PeerHint, RevocationReason, RevokedCert,
    TagName, effective_capabilities, effective_hostname, effective_label, encode_device_id,
};

const INDEX_HTML: &str = include_str!("assets/dist/index.html");

pub(super) fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
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
        .route("/api/assigned-ipv4", post(api_assigned_ipv4))
        .route("/api/pending", get(api_pending))
        .route("/api/approve", post(api_approve))
        .route("/api/reject", post(api_reject))
        .route("/api/instances", get(api_instances))
        .route("/api/node", get(api_node))
        .route("/api/peers", get(api_peers))
        .route("/api/peer-identities", get(api_peer_identities))
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
        .route("/api/config/dns", post(api_cfg_dns))
        .route("/api/config/whitelist", post(api_cfg_whitelist))
        .route("/api/config/acl", post(api_cfg_acl))
        .route("/api/trust/create-domain", post(api_trust_create_domain))
        .route("/api/trust/create-network", post(api_trust_create_network))
        .route("/api/network/run", post(api_network_run))
        .route("/api/network/mount", post(api_network_mount))
        .route("/api/network/ip-pool", get(api_ip_pool_get).post(api_ip_pool_set))
        .route("/api/network/auto-assign", post(api_auto_assign))
        .route("/api/network/leave", post(api_network_leave))
        .route("/api/network/purge-local", post(api_network_purge_local))
        .route("/api/trust/upgrade-peer-to-root", post(api_trust_upgrade_root))
        .route("/api/trust/arm-root-upgrade", post(api_trust_arm_root_upgrade))
        .route("/api/trust/tags", get(api_trust_tags))
        .route("/api/trust/tag", post(api_trust_tag))
        .route("/api/trust/peer-hints", get(api_trust_peer_hints))
        .route("/api/trust/peer-hint", post(api_trust_peer_hint))
        .route("/api/trust/invite", post(api_trust_invite))
        .route("/api/network/invite-preview", post(api_invite_preview))
        .route("/api/network/join", post(api_network_join))
        .route("/api/network/join-status", get(api_join_status))
        .route(
            "/api/console/access",
            get(api_console_access_get).post(api_console_access_set),
        )
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
    let label = req.label.trim().to_owned();
    if label.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "device label cannot be empty");
    }
    let fp = match control::parse_member_cert_fingerprint(&req.fingerprint) {
        Ok(fp) => fp,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    let bound_at = now_unix_secs();
    let result = (|| {
        let sess = SigningSession::open(&td, &nid, &pass)?;
        let old_cert = active_member_cert(&sess, fp)?;
        // 现有生效名 = state binding 优先，否则证书正文。相同 → 幂等，不动版本。
        if label == effective_label(&old_cert, &sess.original_state) {
            let v = sess.version();
            return Ok((v, v));
        }
        // 写 state 绑定（键=现有指纹，不重签、不踢线）；等于证书正文名时移除绑定保持状态精简。
        let cert_label = old_cert.details.device_label.clone();
        let prev = sess.version();
        let version = sess.commit(move |next, _root| {
            next.payload
                .label_bindings
                .retain(|b| b.cert_fingerprint != fp);
            if label != cert_label {
                next.payload.label_bindings.push(LabelBinding {
                    cert_fingerprint: fp,
                    label,
                    bound_at,
                });
            }
            Ok(())
        })?;
        Ok::<(u64, u64), anyhow::Error>((prev, version))
    })();
    if let Ok((prev, version)) = &result
        && version != prev
        && let Ok((_d, _p, state)) = control::read_network_state(&td, &nid)
    {
        push_network_state_to_daemon(&s, crate::trust::to_canonical_cbor(&state)).await;
    }
    version_response(&req.fingerprint, result)
}

#[derive(Deserialize)]
struct HostnameReq {
    fingerprint: String,
    /// `None`/缺省 = 清除主机名；`Some` = 设置（校验唯一）。
    #[serde(default)]
    hostname: Option<String>,
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
    let bound_at = now_unix_secs();
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
        // 现有生效值 = state binding 优先，否则证书正文。相同 → 幂等，不动版本。
        if new_hostname == effective_hostname(&old_cert, &sess.original_state) {
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
        // 写 state 绑定（键=现有指纹，不重签、不踢线）。回落证书正文时移除绑定保持状态精简。
        let cert_hostname = old_cert.details.hostname.clone();
        let prev = sess.version();
        let version = sess.commit(move |next, _root| {
            next.payload
                .hostname_bindings
                .retain(|b| b.cert_fingerprint != fp);
            if new_hostname != cert_hostname {
                next.payload.hostname_bindings.push(HostnameBinding {
                    cert_fingerprint: fp,
                    hostname: new_hostname,
                    bound_at,
                });
            }
            Ok(())
        })?;
        Ok::<(u64, u64), anyhow::Error>((prev, version))
    })();
    if let Ok((prev, version)) = &result
        && version != prev
        && let Ok((_d, _p, state)) = control::read_network_state(&td, &nid)
    {
        push_network_state_to_daemon(&s, crate::trust::to_canonical_cbor(&state)).await;
    }
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
    let granted_at = now_unix_secs();
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
        // 以现有生效能力（state grant 优先，否则证书正文）为基线做增量编辑。
        let current = effective_capabilities(&old_cert, &sess.original_state);
        let mut capabilities = current.clone();
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
        if capabilities == current {
            let v = sess.version();
            return Ok((v, v));
        }
        // 写 state 授予（键=现有指纹，不重签、不踢线）。等于证书正文时移除授予回落基线。
        let cert_capabilities = old_cert.details.capabilities.clone();
        let prev = sess.version();
        let version = sess.commit(move |next, _root| {
            next.payload
                .capability_grants
                .retain(|g| g.cert_fingerprint != fp);
            if capabilities != cert_capabilities {
                next.payload.capability_grants.push(CapabilityGrant {
                    cert_fingerprint: fp,
                    capabilities,
                    granted_at,
                });
            }
            Ok(())
        })?;
        Ok::<(u64, u64), anyhow::Error>((prev, version))
    })();
    if let Ok((prev, version)) = &result
        && version != prev
        && let Ok((_d, _p, state)) = control::read_network_state(&td, &nid)
    {
        push_network_state_to_daemon(&s, crate::trust::to_canonical_cbor(&state)).await;
    }
    version_response(&req.fingerprint, result)
}

#[derive(Deserialize)]
struct AssignedIpv4Req {
    fingerprint: String,
    /// CIDR 串（如 `10.0.0.7/24`）；缺省/空 = 清除指派，设备回退 DHCP/静态。
    #[serde(default)]
    ipv4: Option<String>,
}

/// 主控指派/清除设备固定虚拟 IPv4。写入 root 签名的 `network_state.ip_assignments`
/// （键=稳定 device_id，**不重签证书**），节点运行时验签后自行应用到 TUN。
async fn api_assigned_ipv4(State(s): State<AppState>, Json(req): Json<AssignedIpv4Req>) -> Response {
    let (td, nid, pass) = match require_session(&s).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fp = match control::parse_member_cert_fingerprint(&req.fingerprint) {
        Ok(fp) => fp,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    let result = (|| {
        let assign = match req.ipv4.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(cidr) => {
                let inet = Ipv4Inet::from_str(cidr)
                    .map_err(|e| anyhow::anyhow!("invalid ipv4 cidr '{cidr}': {e}"))?;
                let addr = inet.address.map(|a| a.addr).unwrap_or(0);
                Some(AssignedIpv4 {
                    addr,
                    prefix: inet.network_length as u8,
                })
            }
            None => None,
        };
        let sess = SigningSession::open(&td, &nid, &pass)?;
        let cert = active_member_cert(&sess, fp)?;
        let device_id = encode_device_id(cert.details.device_pk.as_bytes());
        let current = sess
            .original_state
            .details
            .payload
            .ip_assignments
            .iter()
            .find(|a| a.device_id == device_id)
            .map(|a| a.ipv4);
        if current == assign {
            let v = sess.version();
            return Ok((v, v));
        }
        let prev = sess.version();
        let version = sess.commit(move |next, _root| {
            next.payload
                .ip_assignments
                .retain(|a| a.device_id != device_id);
            if let Some(ipv4) = assign {
                next.payload.ip_assignments.push(IpAssignment {
                    device_id: device_id.clone(),
                    ipv4,
                });
            }
            Ok(())
        })?;
        Ok::<(u64, u64), anyhow::Error>((prev, version))
    })();
    // 指派变更后，把新签名的 network_state 推给本地 daemon（best-effort）：
    // daemon 池更新 → config-sync 服务对端 → 各节点验签后运行时应用指派 IP。
    // daemon 不在线则忽略（已落盘，待 daemon 起来经 config-sync 传播）。
    if let Ok((prev, version)) = &result
        && version != prev
        && let Ok((_d, _p, state)) = control::read_network_state(&td, &nid)
    {
        push_network_state_to_daemon(&s, crate::trust::to_canonical_cbor(&state)).await;
    }
    version_response(&req.fingerprint, result)
}

/// 把一份已签名的 network_state（CBOR）经 ConfigRpc.PatchConfig 推入本地 daemon 运行时池。
/// best-effort：失败仅告警，不影响已落盘的治理结果。
async fn push_network_state_to_daemon(s: &AppState, state_cbor: Vec<u8>) {
    let res = async {
        let client = {
            let mut g = s.client.lock().await;
            g.scoped_client::<ConfigRpcClientFactory<BaseController>>(String::new())
                .await?
        };
        client
            .patch_config(
                BaseController::default(),
                PatchConfigRequest {
                    patch: None,
                    instance: Some(s.instance.clone()),
                    network_state_cbor: Some(state_cbor),
                },
            )
            .await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if let Err(e) = res {
        tracing::warn!(
            "failed to push network_state to local daemon (governance persisted to disk; will propagate via config-sync): {e}"
        );
    }
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

// ---------- Web UI 访问来源（console.json） ----------
// 只决定控制台的可见范围，不实施网络控制（治理操作仍由网络管理员口令保护），故不需解锁，
// console token 即足。绑定地址无法热改：写盘后重启服务生效。

#[derive(Deserialize)]
struct ConsoleAccessReq {
    mode: access::WebuiAccess,
}

/// 读访问来源：`mode` = 盘上已保存的（重启后生效的），`active_mode` = 本进程正生效的。
async fn api_console_access_get(State(s): State<AppState>) -> Response {
    let saved = access::load();
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "mode": saved,
            "active_mode": s.access,
            "needs_restart": saved != s.access,
        }),
    )
}

async fn api_console_access_set(
    State(s): State<AppState>,
    Json(req): Json<ConsoleAccessReq>,
) -> Response {
    match access::save(req.mode) {
        Ok(()) => json_response(
            StatusCode::OK,
            serde_json::json!({ "ok": true, "needs_restart": req.mode != s.access }),
        ),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

// ---------- 网络级 IP 池（controller_meta.json，控制器元数据、非签名态） ----------

#[derive(Deserialize, serde::Serialize, Default)]
struct ControllerMeta {
    #[serde(default)]
    ip_pool_cidr: String,
    #[serde(default)]
    auto_assign: bool,
}

fn controller_meta_path(td: &str, nid: &str) -> anyhow::Result<std::path::PathBuf> {
    Ok(crate::common::config_dir::pnw_trust_domains_dir()?
        .join(td)
        .join("networks")
        .join(nid)
        .join("controller_meta.json"))
}

/// 建网时若未配 IP 池，默认采用此网段：使本机 root 设备能自动获派固定 IP，
/// 实例带 virtual_ipv4 起 → 生成 TUN 网卡（否则 EasyTier 无 IP 不建卡）。用户可在网络页改。
const DEFAULT_IP_POOL_CIDR: &str = "10.126.126.0/24";

fn read_controller_meta(td: &str, nid: &str) -> ControllerMeta {
    controller_meta_path(td, nid)
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// 写 0600 私有文件（同 sk_self.seal 的权限约束）。
fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[derive(Deserialize)]
struct IpPoolQuery {
    trust_domain_id: String,
    network_local_id: String,
}

/// 读网络级 IP 池设置（只读，不需解锁）。
async fn api_ip_pool_get(Query(q): Query<IpPoolQuery>) -> Response {
    let meta = read_controller_meta(&q.trust_domain_id, &q.network_local_id);
    json_response(
        StatusCode::OK,
        serde_json::json!({ "ip_pool_cidr": meta.ip_pool_cidr, "auto_assign": meta.auto_assign }),
    )
}

#[derive(Deserialize)]
struct IpPoolSetReq {
    trust_domain_id: String,
    network_local_id: String,
    ip_pool_cidr: String,
    auto_assign: bool,
}

/// 写网络级 IP 池设置（需主控解锁：证明持有该网络 root 口令；本身非签名态）。
async fn api_ip_pool_set(State(s): State<AppState>, Json(req): Json<IpPoolSetReq>) -> Response {
    let (td, nid, _pass) = match require_session(&s).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if td != req.trust_domain_id || nid != req.network_local_id {
        return json_error(StatusCode::FORBIDDEN, "unlocked session is for a different network");
    }
    let result = (|| {
        let cidr = req.ip_pool_cidr.trim();
        if !cidr.is_empty() {
            Ipv4Inet::from_str(cidr)
                .map_err(|e| anyhow::anyhow!("invalid pool cidr '{cidr}': {e}"))?;
        }
        let path = controller_meta_path(&td, &nid)?;
        if !path.parent().map(|p| p.is_dir()).unwrap_or(false) {
            anyhow::bail!("network not found");
        }
        let meta = ControllerMeta { ip_pool_cidr: cidr.to_string(), auto_assign: req.auto_assign };
        write_private_file(&path, serde_json::to_string(&meta)?.as_bytes())?;
        Ok::<(), anyhow::Error>(())
    })();
    match result {
        Ok(()) => json_response(StatusCode::OK, serde_json::json!({ "ok": true })),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}

/// 从池 CIDR 选一个空闲主机地址（跳过网络地址、.1 网关约定、广播、已指派）。addr = u32::from(Ipv4Addr) 大端。
fn pick_free_ip(pool: &Ipv4Inet, assignments: &[IpAssignment]) -> anyhow::Result<u32> {
    let base = pool.address.as_ref().map(|a| a.addr).unwrap_or(0);
    let prefix = pool.network_length as u32;
    if prefix >= 31 {
        anyhow::bail!("pool prefix too small for host allocation");
    }
    let host_bits = 32 - prefix;
    let mask = u32::MAX.checked_shl(host_bits).unwrap_or(0);
    let network = base & mask;
    let broadcast = network | !mask;
    let used: std::collections::HashSet<u32> = assignments.iter().map(|a| a.ipv4.addr).collect();
    for host in network.saturating_add(2)..broadcast {
        if !used.contains(&host) {
            return Ok(host);
        }
    }
    anyhow::bail!("no free address left in pool")
}

#[derive(Deserialize)]
struct AutoAssignReq {
    fingerprint: String,
}

/// 从 IP 池自动为某设备分配空闲 IP，走 assigned-ipv4 签名路径（需解锁）。已指派则原样返回。
async fn api_auto_assign(State(s): State<AppState>, Json(req): Json<AutoAssignReq>) -> Response {
    let (td, nid, pass) = match require_session(&s).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fp = match control::parse_member_cert_fingerprint(&req.fingerprint) {
        Ok(fp) => fp,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    let result = (|| {
        let meta = read_controller_meta(&td, &nid);
        let cidr = meta.ip_pool_cidr.trim();
        if cidr.is_empty() {
            anyhow::bail!("IP pool not configured; set the pool CIDR first");
        }
        let pool = Ipv4Inet::from_str(cidr)
            .map_err(|e| anyhow::anyhow!("invalid pool cidr '{cidr}': {e}"))?;
        let sess = SigningSession::open(&td, &nid, &pass)?;
        let cert = active_member_cert(&sess, fp)?;
        let device_id = encode_device_id(cert.details.device_pk.as_bytes());
        if let Some(a) = sess
            .original_state
            .details
            .payload
            .ip_assignments
            .iter()
            .find(|a| a.device_id == device_id)
        {
            let v = sess.version();
            let ip = format!("{}/{}", std::net::Ipv4Addr::from(a.ipv4.addr), a.ipv4.prefix);
            return Ok((v, v, ip));
        }
        let free = pick_free_ip(&pool, &sess.original_state.details.payload.ip_assignments)?;
        let assign = AssignedIpv4 { addr: free, prefix: pool.network_length as u8 };
        let ip = format!("{}/{}", std::net::Ipv4Addr::from(free), pool.network_length);
        let prev = sess.version();
        let version = sess.commit(move |next, _root| {
            next.payload.ip_assignments.retain(|a| a.device_id != device_id);
            next.payload
                .ip_assignments
                .push(IpAssignment { device_id: device_id.clone(), ipv4: assign });
            Ok(())
        })?;
        Ok::<(u64, u64, String), anyhow::Error>((prev, version, ip))
    })();
    if let Ok((prev, version, _)) = &result
        && version != prev
        && let Ok((_d, _p, state)) = control::read_network_state(&td, &nid)
    {
        push_network_state_to_daemon(&s, crate::trust::to_canonical_cbor(&state)).await;
    }
    match result {
        Ok((_prev, version, ip)) => json_response(
            StatusCode::OK,
            serde_json::json!({ "fingerprint": req.fingerprint, "assigned_ipv4": ip, "version": version }),
        ),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}

/// 给本机（root 自身设备，device_id 取自 network_dir/device_id）从池派一个空闲固定 IP，
/// 签进 network_state.ip_assignments。已指派则返回 false（不改状态）。供建网流程调用，
/// 使新建网络的实例带 virtual_ipv4 起 → 生成 TUN 网卡。失败由调用方降级处理，不阻断建网。
fn ensure_self_ip_assigned(td: &str, nid: &str, pass: &str, cidr: &str) -> anyhow::Result<bool> {
    let cidr = cidr.trim();
    if cidr.is_empty() {
        anyhow::bail!("no IP pool cidr");
    }
    let pool =
        Ipv4Inet::from_str(cidr).map_err(|e| anyhow::anyhow!("invalid pool cidr '{cidr}': {e}"))?;
    let (network_dir, _pem, _state) = control::read_network_state(td, nid)?;
    let device_id = std::fs::read_to_string(network_dir.join("device_id"))
        .map(|s| s.trim().to_owned())
        .unwrap_or_default();
    if device_id.is_empty() {
        anyhow::bail!("self device_id not found");
    }
    let sess = SigningSession::open(td, nid, pass)?;
    if sess
        .original_state
        .details
        .payload
        .ip_assignments
        .iter()
        .any(|a| a.device_id == device_id)
    {
        return Ok(false);
    }
    let free = pick_free_ip(&pool, &sess.original_state.details.payload.ip_assignments)?;
    let assign = AssignedIpv4 { addr: free, prefix: pool.network_length as u8 };
    let prev = sess.version();
    let version = sess.commit(move |next, _root| {
        next.payload.ip_assignments.retain(|a| a.device_id != device_id);
        next.payload
            .ip_assignments
            .push(IpAssignment { device_id: device_id.clone(), ipv4: assign });
        Ok(())
    })?;
    Ok(version != prev)
}

// ---------- 成员离开网络（停本机实例 + 清封存口令；本机 daemon 操作、不签名） ----------

#[derive(Deserialize)]
struct LeaveReq {
    trust_domain_id: String,
    network_local_id: String,
}

/// 停止并删除匹配 (td,nid) 的运行实例（DeleteNetworkInstance = 停实例 + 删持久化 toml
/// → 不再开机自动重连）。返回停掉的实例数。供 `leave` 与 `purge-local` 复用。
async fn stop_network_instances(
    s: &AppState,
    trust_domain_id: &str,
    network_local_id: &str,
) -> anyhow::Result<usize> {
    let client = {
        let mut g = s.client.lock().await;
        g.scoped_client::<WebClientServiceClientFactory<BaseController>>(String::new())
            .await?
    };
    let cfg_client = {
        let mut g = s.client.lock().await;
        g.scoped_client::<ConfigRpcClientFactory<BaseController>>(String::new())
            .await?
    };
    let listed = client
        .list_network_instance(BaseController::default(), ListNetworkInstanceRequest {})
        .await?;
    // 按覆盖层 network_name=`{td}/{nid}` 匹配（A2 复合名即全局唯一身份）。用 live 配置
    // `get_config`（launcher 反向映射）而非 `get_network_instance_config`：后者对 quickstart/
    // serve CLI 起的实例（只读配置，源自环境/命令行）直接报错 → 旧 locator 匹配漏掉主网实例，
    // 令 leave/purge 停不掉主网络。get_config 对只读实例同样可读，覆盖 CLI + RPC 两类实例。
    let want_name = overlay_network_name(trust_domain_id, network_local_id);
    let mut matched = Vec::new();
    for inst in listed.inst_ids.iter() {
        let Ok(resp) = cfg_client
            .get_config(
                BaseController::default(),
                GetConfigRequest {
                    instance: Some(InstanceIdentifier {
                        selector: Some(
                            crate::proto::api::instance::instance_identifier::Selector::Id(
                                inst.clone(),
                            ),
                        ),
                    }),
                },
            )
            .await
        else {
            continue;
        };
        if resp.config.and_then(|c| c.network_name).as_deref() == Some(want_name.as_str()) {
            matched.push(inst.clone());
        }
    }
    if matched.is_empty() {
        return Ok(0);
    }
    let count = matched.len();
    client
        .delete_network_instance(
            BaseController::default(),
            DeleteNetworkInstanceRequest { inst_ids: matched },
        )
        .await?;
    Ok(count)
}

/// 离开网络：匹配 (td,nid) 对应的运行实例 → DeleteNetworkInstance（停实例 + 删持久化 toml
/// → 不再开机自动重连）。不需 root 签名（纯本机 daemon 操作）。
async fn api_network_leave(State(s): State<AppState>, Json(req): Json<LeaveReq>) -> Response {
    let result = async {
        if stop_network_instances(&s, &req.trust_domain_id, &req.network_local_id).await? == 0 {
            anyhow::bail!("no running instance found for this network");
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    match result {
        Ok(()) => json_response(StatusCode::OK, serde_json::json!({ "status": "left" })),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}

#[derive(Deserialize)]
struct PurgeLocalReq {
    trust_domain_id: String,
    network_local_id: String,
}

/// 纯判定：给定域布局，返回应从本机删除的路径集合。**仅字符串/布尔运算，绝不触碰文件系统**
/// （purge 事故铁律 [[destructive-test-real-paths-incident]] — 单测只断言这些路径串）。
/// 铁律：`is_root_holder`（持 `sk_root.age`）→ **绝不**返回域目录（根钥须经卸载器 purge/显式导出）。
fn purge_local_targets(
    domain_dir: &std::path::Path,
    network_local_id: &str,
    is_root_holder: bool,
    remaining_networks: usize,
) -> Vec<std::path::PathBuf> {
    let mut targets = vec![domain_dir.join("networks").join(network_local_id)];
    if !is_root_holder && remaining_networks == 0 {
        targets.push(domain_dir.to_path_buf());
    }
    targets
}

/// 统计域下除 `exclude_nid` 外的网络目录数（= 删除目标网络后将剩余的网络数）。
fn count_other_networks(domain_dir: &std::path::Path, exclude_nid: &str) -> usize {
    std::fs::read_dir(domain_dir.join("networks"))
        .map(|entries| {
            entries
                .filter_map(std::result::Result::ok)
                .filter(|e| e.path().is_dir())
                .filter(|e| e.file_name().to_string_lossy() != exclude_nid)
                .count()
        })
        .unwrap_or(0)
}

/// 退出并清除：先停实例（复用 leave，best-effort，未挂载则忽略）→ 删本机该网络目录；
/// 若域下已无其它网络且非 root 持有者 → 连域目录一并删。root 持有者的 `sk_root.age` 绝不删。
async fn api_network_purge_local(
    State(s): State<AppState>,
    Json(req): Json<PurgeLocalReq>,
) -> Response {
    let result = async {
        let _ = stop_network_instances(&s, &req.trust_domain_id, &req.network_local_id).await;
        let domain_dir =
            crate::common::config_dir::pnw_trust_domains_dir()?.join(&req.trust_domain_id);
        let is_root_holder = domain_dir.join("sk_root.age").is_file();
        let remaining = count_other_networks(&domain_dir, &req.network_local_id);
        let targets =
            purge_local_targets(&domain_dir, &req.network_local_id, is_root_holder, remaining);
        let mut domain_removed = false;
        for target in &targets {
            if target == &domain_dir {
                domain_removed = true;
            }
            if target.exists() {
                std::fs::remove_dir_all(target)
                    .with_context(|| format!("failed to remove {}", target.display()))?;
            }
        }
        Ok::<_, anyhow::Error>(serde_json::json!({
            "status": "purged",
            "domain_removed": domain_removed,
        }))
    }
    .await;
    match result {
        Ok(v) => json_response(StatusCode::OK, v),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}

// ---------- 只读 RPC 端点 ----------

/// 列出已挂载到 daemon 的网络实例（ListNetworkInstance 透传）。空载 daemon 返回
/// `{inst_ids:[]}`（200，区别于 daemon 不可达的 502）→ 前端据此键出「未加网」空状态。
async fn api_instances(
    State(s): State<AppState>,
) -> Result<Json<ListNetworkInstanceResponse>, ApiError> {
    let client = {
        let mut g = s.client.lock().await;
        g.scoped_client::<WebClientServiceClientFactory<BaseController>>(String::new())
            .await?
    };
    let resp = client
        .list_network_instance(BaseController::default(), ListNetworkInstanceRequest {})
        .await?;
    Ok(Json(resp))
}

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

/// 运行时直连对端的信任身份（peer_id → 成员证书指纹）。供前端把运行时连接按稳定
/// 指纹关联到治理名册成员，避免 hostname 不匹配时把同一设备拆成「成员+临时设备」两行。
async fn api_peer_identities(State(s): State<AppState>) -> Response {
    let result = async {
        let client = {
            let mut g = s.client.lock().await;
            g.scoped_client::<TrustJoinManageRpcClientFactory<BaseController>>(String::new())
                .await?
        };
        let resp = client
            .list_peer_trust_identities(
                BaseController::default(),
                ListPeerTrustIdentitiesRequest {
                    instance: Some(s.instance.clone()),
                },
            )
            .await?;
        let items = resp
            .identities
            .into_iter()
            .map(|i| {
                serde_json::json!({
                    "peer_id": i.peer_id,
                    "fingerprint": i.member_cert_fingerprint,
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
struct DnsCfgReq {
    /// MagicDNS 开关。
    enable: bool,
    /// 顶级区（如 "home.pm."）；空则沿用当前区。
    #[serde(default)]
    zone: String,
}

async fn api_cfg_dns(State(s): State<AppState>, Json(req): Json<DnsCfgReq>) -> Response {
    patch_response(
        apply_patch(
            &s,
            InstanceConfigPatch {
                accept_dns: Some(req.enable),
                tld_dns_zone: if req.zone.is_empty() {
                    None
                } else {
                    Some(req.zone)
                },
                ..Default::default()
            },
        )
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
struct NetworkRunReq {
    /// 既有信任域 id；缺省=新建一个域（用 `domain_label`）。
    #[serde(default)]
    trust_domain_id: Option<String>,
    #[serde(default)]
    domain_label: Option<String>,
    network_local_id: String,
    #[serde(default = "default_acl_action")]
    default_action: String,
    #[serde(default)]
    device_label: Option<String>,
    /// 域 root 管理口令（即用即清）。
    root_passphrase: String,
    #[serde(default)]
    listeners: Vec<String>,
    #[serde(default)]
    no_tun: bool,
}

/// 由 network_local_id 派生 MagicDNS 顶级区（`<nid>.pm.`）。nid 消毒为 DNS 标签：
/// 小写、非 [a-z0-9-] → '-'、去首尾 '-'，空则回退 "net"。全网各节点同 nid → 同区。
fn magic_dns_zone(network_local_id: &str) -> String {
    let sanitized: String = network_local_id
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' })
        .collect();
    let base = sanitized.trim_matches('-');
    let base = if base.is_empty() { "net" } else { base };
    format!("{base}.pm.")
}

/// 覆盖层网络身份：`{td}/{nid}`。td 为 URL-safe base64（不含 '/'）→ 分隔无歧义；
/// 全网各节点由共享 (td,nid) 算出同值 → 同域互通，跨域同 nid 不再撞名。
fn overlay_network_name(trust_domain_id: &str, network_local_id: &str) -> String {
    format!("{trust_domain_id}/{network_local_id}")
}

/// TUN 设备名（Windows wintun 卡名 / Linux 接口名）。留空则底层 tun crate 自动生成
/// `et_<hash>`——EasyTier 前缀，既是品牌泄漏又不可辨识。显式命名 `PactMesh-<5hex>`：
/// 拼全产品名一眼可认（仿 ZeroTier「产品名+短 ID」），5 位 hex 取自 {td}/{nid} 稳定哈希
/// → 每网唯一、重启不变、纯 ASCII；共 14 字符安全落在 Linux IFNAMSIZ(15) 内，两平台同名不分叉。
fn branded_dev_name(trust_domain_id: &str, network_local_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(overlay_network_name(trust_domain_id, network_local_id).as_bytes());
    let hex: String = digest.iter().take(3).map(|b| format!("{b:02x}")).collect();
    format!("PactMesh-{}", &hex[..5])
}

/// 同一 daemon 可挂多个网络实例，监听端口不能撞（tunnel 未启 SO_REUSEPORT）。每实例实占
/// 两口：peer 口 `P` + 入网准入 RPC 口 `P+1`（instance.rs `derive_join_admission_url`）。
/// 用试绑探测——唯一可靠信号：不依赖各实例配置回读（quickstart CLI 起的首实例经
/// `get_network_instance_config` 不含 listener_urls，回读会漏占）。从 11010 起按 2 步长
/// 找首个 `[P,P+1]` 全空块：首网得 11010（旧 seed/邀请仍命中），后续网络顺延；额外网 seed
/// 由 peer_hints/手填承担，不依赖固定口。探测 socket 即绑即释 → daemon 随后可绑同口。
fn default_listener_url() -> anyhow::Result<String> {
    let free = |p: u16| std::net::TcpListener::bind(("0.0.0.0", p)).is_ok();
    (11010..u16::MAX)
        .step_by(2)
        .find(|&p| free(p) && free(p + 1))
        .map(|p| format!("tcp://0.0.0.0:{p}"))
        .ok_or_else(|| anyhow::anyhow!("no free listener port block ≥11010"))
}

/// 对**运行中**空载 daemon 挂载信任域网络实例（不重启）。设备钥为 raw（免口令），
/// 实例 toml 恒持久化 → 开机自动重连。返回 inst_id 串。
/// 建网(`api_network_run`)与经邀请加入(`api_join_status`)共用此尾部。
pub(super) async fn attach_trust_network(
    s: &AppState,
    trust_domain_id: &str,
    network_local_id: &str,
    listeners: Vec<String>,
    peers: Vec<String>,
    no_tun: bool,
) -> anyhow::Result<Option<String>> {
    let domain_dir = crate::common::config_dir::pnw_trust_domains_dir()?.join(trust_domain_id);
    let domain_dir_str = domain_dir.to_string_lossy().into_owned();
    let listeners = if listeners.is_empty() {
        vec![default_listener_url()?]
    } else {
        listeners
    };
    // gen_config 仅在 Manual 下应用 peer_urls（连接器）；建网无 seed 用 Standalone，
    // 经邀请加入须拨向邀请里的 seed → Manual，否则挂载后连不上网络。
    let networking_method = if peers.is_empty() {
        NetworkingMethod::Standalone
    } else {
        NetworkingMethod::Manual
    };
    let nc = NetworkConfig {
        network_name: Some(overlay_network_name(trust_domain_id, network_local_id)),
        dev_name: Some(branded_dev_name(trust_domain_id, network_local_id)),
        networking_method: Some(networking_method as i32),
        listener_urls: listeners,
        peer_urls: peers,
        no_tun: Some(no_tun),
        enable_magic_dns: Some(true),
        tld_dns_zone: Some(magic_dns_zone(network_local_id)),
        trust_domain: Some(TrustDomainLocator {
            trust_domain_dir: domain_dir_str,
            network_local_id: network_local_id.to_string(),
            sk_self_password_env: "PNW_DEVICE_PASSPHRASE".to_string(),
        }),
        ..Default::default()
    };
    let client = {
        let mut g = s.client.lock().await;
        g.scoped_client::<WebClientServiceClientFactory<BaseController>>(String::new())
            .await?
    };
    let resp = client
        .run_network_instance(
            BaseController::default(),
            RunNetworkInstanceRequest {
                inst_id: None,
                config: Some(nc),
                overwrite: true,
                source: 0,
            },
        )
        .await?;
    let inst_id_str = resp.inst_id.map(|u| uuid::Uuid::from(u).to_string());
    Ok(inst_id_str)
}

/// 一站式建网+加网：建域(可选)→建网→自举本机（设备钥 raw，免口令）→对**运行中**
/// 空载 daemon 调 `RunNetworkInstance`（不重启）。root 口令即用即清，绝不进 toml/明文。
async fn api_network_run(State(s): State<AppState>, Json(req): Json<NetworkRunReq>) -> Response {
    let root_pass = Zeroizing::new(req.root_passphrase.clone());
    let result = async {
        // 1) 既有域 or 新建域。域概念对用户隐藏：新建域的 label 自动=主网络名（仅供 legacy 展示回退）。
        let (trust_domain_id, created_domain) = match req.trust_domain_id.clone() {
            Some(td) => (td, false),
            None => {
                let label = req
                    .domain_label
                    .clone()
                    .unwrap_or_else(|| req.network_local_id.clone());
                let td = control::create_domain(&label, root_pass.as_str())?.trust_domain_id;
                (td, true)
            }
        };
        // 2) 建网（root 签 v1 空状态）
        control::create_network(
            &trust_domain_id,
            &req.network_local_id,
            &req.default_action,
            root_pass.as_str(),
        )?;
        // 一步建域+建网：此网络即该域的主网络（承载网络），标记 base_network。
        if created_domain {
            control::set_domain_base_network(&trust_domain_id, &req.network_local_id)?;
        }
        // 3) 自举本机：自执行 binary（设备身份助手为 binary 私有）；无设备口令 → 写 sk_self.raw
        let device_label = req
            .device_label
            .clone()
            .unwrap_or_else(|| gethostname::gethostname().to_string_lossy().to_string());
        let exe = std::env::current_exe().context("failed to locate the pactmesh executable")?;
        let status = std::process::Command::new(&exe)
            .args([
                "trust",
                "bootstrap-self",
                &trust_domain_id,
                &req.network_local_id,
                "--device-label",
                &device_label,
            ])
            .env("PNW_ROOT_PASSPHRASE", root_pass.as_str())
            .status()
            .context("failed to run bootstrap-self")?;
        if !status.success() {
            anyhow::bail!("bootstrap-self exited with {status}");
        }
        // 3.5) 建网即给本机（root 设备）从默认池派固定 IP，使实例带 virtual_ipv4 起 → 生成
        //      TUN 网卡。默认池空则写入 DEFAULT_IP_POOL_CIDR（用户后续可在网络页改）。
        //      先落盘 network_state（attach 前）→ 实例启动即读到 effective_ipv4；失败仅告警、
        //      不阻断建网（退化为无 IP/无网卡，同旧行为）。
        let self_ip_assigned = {
            let mut meta = read_controller_meta(&trust_domain_id, &req.network_local_id);
            if meta.ip_pool_cidr.trim().is_empty() {
                meta.ip_pool_cidr = DEFAULT_IP_POOL_CIDR.to_string();
                if let Ok(path) = controller_meta_path(&trust_domain_id, &req.network_local_id)
                    && let Ok(json) = serde_json::to_string(&meta)
                {
                    let _ = write_private_file(&path, json.as_bytes());
                }
            }
            match ensure_self_ip_assigned(
                &trust_domain_id,
                &req.network_local_id,
                root_pass.as_str(),
                &meta.ip_pool_cidr,
            ) {
                Ok(changed) => changed,
                Err(e) => {
                    tracing::warn!("self IP auto-assign skipped (network created without NIC): {e}");
                    false
                }
            }
        };
        // 4) 对运行中空载 daemon 加网（不重启）；实例恒持久化 → 开机自动重连。
        let inst_id_str = attach_trust_network(
            &s,
            &trust_domain_id,
            &req.network_local_id,
            req.listeners.clone(),
            Vec::new(),
            req.no_tun,
        )
        .await?;
        // 4.5) 推最新 network_state → 运行实例热应用 effective_ipv4（覆盖启动未即建卡的情况）。
        if self_ip_assigned
            && let Ok((_d, _p, state)) =
                control::read_network_state(&trust_domain_id, &req.network_local_id)
        {
            push_network_state_to_daemon(&s, crate::trust::to_canonical_cbor(&state)).await;
        }
        Ok::<_, anyhow::Error>(serde_json::json!({
            "trust_domain_id": trust_domain_id,
            "network_local_id": req.network_local_id,
            "inst_id": inst_id_str,
        }))
    }
    .await;
    match result {
        Ok(v) => json_response(StatusCode::OK, v),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}

#[derive(Deserialize)]
struct NetworkMountReq {
    trust_domain_id: String,
    network_local_id: String,
    #[serde(default)]
    listeners: Vec<String>,
    #[serde(default)]
    no_tun: bool,
}

/// 复用并上线：把盘上已有但未挂载的网络重新挂到运行中空载 daemon。跳过建域/建网/
/// 自举——设备钥 raw、证书与 network_state 已在盘，无需 root 口令。返回 inst_id。
async fn api_network_mount(State(s): State<AppState>, Json(req): Json<NetworkMountReq>) -> Response {
    let result = attach_trust_network(
        &s,
        &req.trust_domain_id,
        &req.network_local_id,
        req.listeners,
        Vec::new(),
        req.no_tun,
    )
    .await;
    match result {
        Ok(inst_id) => json_response(
            StatusCode::OK,
            serde_json::json!({
                "trust_domain_id": req.trust_domain_id,
                "network_local_id": req.network_local_id,
                "inst_id": inst_id,
            }),
        ),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}

// ---------- 经邀请加入既有网络（异步：提交→轮询→批准后自动挂载）----------

const JOIN_WAIT_SECS: u64 = 3600;
const JOIN_POLL_SECS: u64 = 30;

/// 把 td/nid 拼成文件系统安全的 pending-join meta 键（非 [A-Za-z0-9._-] 一律换 `_`）。
fn pending_join_key(trust_domain_id: &str, network_local_id: &str) -> String {
    let raw = format!("{trust_domain_id}__{network_local_id}");
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Deserialize)]
struct JoinReq {
    invite_url: String,
    #[serde(default)]
    device_label: Option<String>,
    #[serde(default)]
    no_tun: bool,
    #[serde(default)]
    listeners: Vec<String>,
}

/// B-2 发起加入（非阻塞）：解析邀请 → 封存口令 → 起脱离会话子进程 `accept-invite`
/// （自己等批准）→ 落一份 pending-join meta 供 B-3 判定/挂载 → 立即返回 pending。
async fn api_network_join(State(_s): State<AppState>, Json(req): Json<JoinReq>) -> Response {
    // 1) 解析校验邀请链接（失败 400，与 invite-preview 一致）
    let url = match url::Url::parse(req.invite_url.trim()) {
        Ok(u) => u,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, format!("invalid invite url: {e}")),
    };
    let bootstrap = match NetworkBootstrap::from_url(&url) {
        Ok(b) => b,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    let td = bootstrap.trust_domain_id.to_string();
    let nid = bootstrap.network_local_id.to_string();

    let result = (|| {
        // 2) 计算 network_dir（供 meta；设备钥 raw，无口令封存）。accept-invite 会自建该目录。
        let domain_dir = crate::common::config_dir::pnw_trust_domains_dir()?.join(&td);
        let network_dir = domain_dir.join("networks").join(&nid);

        // 3) 脱离会话起后台子进程 accept-invite（online 默认；无设备口令 → raw，日志落盘）
        let device_label = req
            .device_label
            .clone()
            .unwrap_or_else(|| gethostname::gethostname().to_string_lossy().to_string());
        let exe = std::env::current_exe().context("failed to locate the pactmesh executable")?;
        let log_path = crate::common::config_dir::pnw_config_dir()?
            .join(format!("pactmesh-join-{}.log", pending_join_key(&td, &nid)));
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .with_context(|| format!("failed to open {}", log_path.display()))?;
        let log_err = log.try_clone()?;
        std::process::Command::new(&exe)
            .args([
                "trust",
                "accept-invite",
                req.invite_url.trim(),
                "--device-label",
                &device_label,
                "--wait-secs",
                &JOIN_WAIT_SECS.to_string(),
                "--poll-secs",
                &JOIN_POLL_SECS.to_string(),
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(log))
            .stderr(std::process::Stdio::from(log_err))
            .spawn()
            .context("failed to start accept-invite")?;

        // 4) 落控制器 meta 供 B-3（join-status）判定 + 批准后挂载 + F-4 重开恢复
        let meta_dir = crate::common::config_dir::pnw_config_dir()?.join("pending-joins");
        std::fs::create_dir_all(&meta_dir)
            .with_context(|| format!("failed to create {}", meta_dir.display()))?;
        let meta = serde_json::json!({
            "trust_domain_id": td,
            "network_local_id": nid,
            "domain_label": bootstrap.trust_domain_label,
            "network_name": bootstrap.network_name,
            "network_dir": network_dir.to_string_lossy(),
            "no_tun": req.no_tun,
            "listeners": req.listeners,
            "seeds": bootstrap.bootstrap_seeds.iter().map(|u| u.as_str().to_string()).collect::<Vec<_>>(),
            "started_at": now_unix(),
            "wait_secs": JOIN_WAIT_SECS,
        });
        let meta_path = meta_dir.join(format!("{}.json", pending_join_key(&td, &nid)));
        std::fs::write(&meta_path, serde_json::to_vec_pretty(&meta)?)
            .with_context(|| format!("failed to write {}", meta_path.display()))?;

        Ok::<_, anyhow::Error>(serde_json::json!({
            "trust_domain_id": td,
            "network_local_id": nid,
            "status": "pending",
        }))
    })();
    match result {
        Ok(v) => json_response(StatusCode::OK, v),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}

/// B-3 查状态 + 批准后自动挂载。扫描 pending-joins/*.json，逐个判定：
/// member_cert.pem 出现 → 挂载(不重启)、删 meta、报 online{inst_id}；
/// pending_join_request.cbor.pem 在且未超时 → pending；超时无 cert → timeout(清理)。
/// 无参数（扫全部）→ 供 F-3 轮询 + F-4 Console 重开恢复等待界面。
async fn api_join_status(State(s): State<AppState>) -> Response {
    let meta_dir = match crate::common::config_dir::pnw_config_dir() {
        Ok(d) => d.join("pending-joins"),
        Err(e) => return json_error(StatusCode::BAD_GATEWAY, e),
    };
    let mut joins = Vec::new();
    let entries = match std::fs::read_dir(&meta_dir) {
        Ok(rd) => rd,
        Err(_) => return json_response(StatusCode::OK, serde_json::json!({ "joins": joins })),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let meta: serde_json::Value = match std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
        {
            Some(m) => m,
            None => continue,
        };
        let td = meta["trust_domain_id"].as_str().unwrap_or_default().to_string();
        let nid = meta["network_local_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let network_dir = std::path::PathBuf::from(meta["network_dir"].as_str().unwrap_or_default());
        let no_tun = meta["no_tun"].as_bool().unwrap_or(false);
        let listeners: Vec<String> = meta["listeners"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let seeds: Vec<String> = meta["seeds"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let started_at = meta["started_at"].as_u64().unwrap_or(0);
        let wait_secs = meta["wait_secs"].as_u64().unwrap_or(JOIN_WAIT_SECS);

        let base = serde_json::json!({
            "trust_domain_id": td,
            "network_local_id": nid,
            "domain_label": meta["domain_label"].clone(),
            "network_name": meta["network_name"].clone(),
        });
        let cert_ok = network_dir.join("member_cert.pem").exists();
        let submitted = network_dir.join("pending_join_request.cbor.pem").exists();

        let mut item = base.clone();
        if cert_ok {
            // 批准：挂载到运行中空载 daemon（不重启）→ 成功删 meta。
            match attach_trust_network(&s, &td, &nid, listeners, seeds, no_tun).await {
                Ok(inst_id) => {
                    let _ = std::fs::remove_file(&path);
                    item["status"] = serde_json::json!("online");
                    item["inst_id"] = serde_json::json!(inst_id);
                }
                Err(e) => {
                    item["status"] = serde_json::json!("error");
                    item["error"] = serde_json::json!(e.to_string());
                }
            }
        } else if started_at > 0 && now_unix().saturating_sub(started_at) > wait_secs {
            // 超时无 cert：清理 meta（子进程已放弃）。
            let _ = std::fs::remove_file(&path);
            item["status"] = serde_json::json!("timeout");
        } else if submitted {
            item["status"] = serde_json::json!("pending");
        } else {
            item["status"] = serde_json::json!("submitting");
        }
        joins.push(item);
    }
    json_response(StatusCode::OK, serde_json::json!({ "joins": joins }))
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
    #[serde(default)]
    seeds: Vec<String>,
    #[serde(default)]
    include_peer_hints: bool,
    #[serde(default)]
    include_local_listeners: bool,
    #[serde(default = "default_invite_format")]
    format: String,
}

fn default_invite_format() -> String {
    "url".to_string()
}

/// 从本机 `NodeInfo` 推导可达入网落脚点（按优先级：public v4/v6 → 接口 v4/v6）。
/// 仅取 listeners 的 (scheme∈{tcp,udp}, port)，与可达 host 交叉；剔除 ring/回环/通配。
fn derive_local_seeds(node_info: &NodeInfo) -> Vec<url::Url> {
    use std::net::IpAddr;

    let ip_list = node_info.ip_list.clone().unwrap_or_default();
    let mut hosts: Vec<String> = Vec::new();
    let mut push_v4 = |s: String| {
        if let Ok(IpAddr::V4(ip)) = s.parse::<IpAddr>() {
            if !ip.is_loopback() && !ip.is_unspecified() {
                hosts.push(ip.to_string());
            }
        }
    };
    if let Some(ip) = ip_list.public_ipv4.as_ref() {
        push_v4(ip.to_string());
    }
    let mut v6_hosts: Vec<String> = Vec::new();
    let mut push_v6 = |s: String| {
        if let Ok(IpAddr::V6(ip)) = s.parse::<IpAddr>() {
            if !ip.is_loopback() && !ip.is_unspecified() {
                v6_hosts.push(format!("[{ip}]"));
            }
        }
    };
    if let Some(ip) = ip_list.public_ipv6.as_ref() {
        push_v6(ip.to_string());
    }
    for ip in &ip_list.interface_ipv4s {
        push_v4(ip.to_string());
    }
    for ip in &ip_list.interface_ipv6s {
        push_v6(ip.to_string());
    }
    // 优先级：public v4 → public v6 → 接口 v4 → 接口 v6。push_v4 收 public 与接口 v4，
    // 这里把 v6 接在 v4 之后即得最终序（public v6 已先于接口 v6 入 v6_hosts）。
    hosts.extend(v6_hosts);

    let mut ports: Vec<(String, u16)> = Vec::new();
    for raw in &node_info.listeners {
        let Ok(url) = url::Url::parse(raw) else { continue };
        let scheme = url.scheme();
        if scheme != "tcp" && scheme != "udp" {
            continue;
        }
        if let Some(port) = url.port() {
            let pair = (scheme.to_owned(), port);
            if !ports.contains(&pair) {
                ports.push(pair);
            }
        }
    }

    let mut seeds = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for host in &hosts {
        for (scheme, port) in &ports {
            if let Ok(url) = url::Url::parse(&format!("{scheme}://{host}:{port}")) {
                if seen.insert(url.as_str().to_owned()) {
                    seeds.push(url);
                }
            }
        }
    }
    seeds
}

/// 导出入网引导 invite（url|file）。只读，不解锁。
/// 落脚点 = 手填 ∪（可选）未过期 peer-hints ∪（可选）本机监听地址，按优先级去重。
async fn api_trust_invite(State(s): State<AppState>, Json(req): Json<InviteReq>) -> Response {
    let manual = req
        .seeds
        .iter()
        .map(|seed| {
            url::Url::parse(seed.trim()).map_err(|e| anyhow::anyhow!("invalid seed '{seed}': {e}"))
        })
        .collect::<anyhow::Result<Vec<_>>>();
    let manual = match manual {
        Ok(seeds) => seeds,
        Err(e) => return json_error(StatusCode::BAD_GATEWAY, e),
    };

    let local = if req.include_local_listeners {
        match fetch_node_info(&s).await {
            Ok(node_info) => derive_local_seeds(&node_info),
            Err(e) => return json_error(StatusCode::BAD_GATEWAY, e),
        }
    } else {
        Vec::new()
    };

    match control::export_invite(
        &req.trust_domain_id,
        &req.network_local_id,
        manual,
        local,
        req.include_peer_hints,
        &req.format,
    ) {
        Ok(out) => json_response(
            StatusCode::OK,
            serde_json::json!({
                "invite": out.content,
                "seed_count": out.seed_count,
                "omitted": out.omitted,
            }),
        ),
        Err(e) => json_error(StatusCode::BAD_GATEWAY, e),
    }
}

#[derive(Deserialize)]
struct InvitePreviewReq {
    invite_url: String,
}

/// 解析邀请链接，回显信任域/网络元数据供加入前确认。只读，不落盘、不解锁、不碰 daemon。
async fn api_invite_preview(Json(req): Json<InvitePreviewReq>) -> Response {
    let url = match url::Url::parse(req.invite_url.trim()) {
        Ok(url) => url,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, format!("invalid invite url: {e}")),
    };
    let bootstrap = match NetworkBootstrap::from_url(&url) {
        Ok(b) => b,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "trust_domain_id": bootstrap.trust_domain_id.to_string(),
            "network_local_id": bootstrap.network_local_id.to_string(),
            "domain_label": bootstrap.trust_domain_label,
            "network_name": bootstrap.network_name,
            "seed_count": bootstrap.bootstrap_seeds.len(),
        }),
    )
}

/// 拉取控制器绑定实例的 `NodeInfo`（用于推导本机监听地址）。
async fn fetch_node_info(s: &AppState) -> anyhow::Result<NodeInfo> {
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
    resp.node_info
        .ok_or_else(|| anyhow::anyhow!("daemon returned no node_info"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // purge 事故铁律：purge 路径判定单测**只做字符串断言**，绝不喂真实 rm。
    fn strs(paths: &[std::path::PathBuf]) -> Vec<String> {
        paths.iter().map(|p| p.display().to_string()).collect()
    }

    #[test]
    fn purge_targets_network_only_when_other_networks_remain() {
        let dir = Path::new("/base/DOMAIN");
        // 非 root 持有者但域下还有其它网络 → 仅删该网络目录，保留域目录。
        let targets = purge_local_targets(dir, "office", false, 2);
        assert_eq!(
            strs(&targets),
            vec![Path::new("/base/DOMAIN/networks/office")
                .display()
                .to_string()]
        );
    }

    #[test]
    fn purge_targets_domain_when_last_network_and_not_root() {
        let dir = Path::new("/base/DOMAIN");
        // 非 root 持有者且这是最后一个网络 → 连域目录一并删。
        let targets = purge_local_targets(dir, "office", false, 0);
        assert_eq!(
            strs(&targets),
            vec![
                Path::new("/base/DOMAIN/networks/office")
                    .display()
                    .to_string(),
                dir.display().to_string(),
            ]
        );
    }

    #[test]
    fn purge_never_targets_domain_dir_for_root_holder() {
        let dir = Path::new("/base/DOMAIN");
        // 铁律：root 持有者（持 sk_root.age）即使删最后一个网络也绝不删域目录（根钥须保留）。
        let targets = purge_local_targets(dir, "office", true, 0);
        assert!(!targets.iter().any(|t| t == dir), "root domain dir must be preserved");
        assert_eq!(targets.len(), 1);
    }
}
