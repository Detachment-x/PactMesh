//! Product-facing device view helpers.
//!
//! This module keeps governance role, network capability, human tag grouping,
//! and ACL flow policy separated. It intentionally does not read local files or
//! perform CLI rendering.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;

use super::{
    AclPolicy, Capabilities, DeviceFingerprint, MemberCert, MemberCertFingerprint,
    SignedNetworkState, from_cbor,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceRole {
    Root,
    Member,
    External,
}

impl DeviceRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Member => "member",
            Self::External => "external",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceStatus {
    Active,
    Disabled,
    Revoked,
    Expired,
}

impl DeviceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceCapabilityView {
    pub relay_data: bool,
    pub relay_control: bool,
    pub proxy_subnets: Vec<String>,
}

impl DeviceCapabilityView {
    pub fn from_capabilities(capabilities: &Capabilities) -> Self {
        Self {
            relay_data: capabilities.can_relay_data,
            relay_control: capabilities.can_relay_control,
            proxy_subnets: capabilities
                .can_proxy_subnet
                .iter()
                .map(ToString::to_string)
                .collect(),
        }
    }

    pub fn render_compact(&self) -> String {
        let mut parts = Vec::new();
        if self.relay_data {
            parts.push("relay-data".to_owned());
        }
        if self.relay_control {
            parts.push("relay-control".to_owned());
        }
        if !self.proxy_subnets.is_empty() {
            parts.push(format!("proxy-subnet:{}", self.proxy_subnets.join(",")));
        }
        parts.join(",")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceView {
    pub fingerprint: String,
    pub device_id: String,
    pub device_label: String,
    pub role: DeviceRole,
    pub network_local_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub status: DeviceStatus,
    pub capabilities: DeviceCapabilityView,
    pub hostname: String,
    /// 主控经 network_state 指派的固定虚拟 IPv4（CIDR 串）；None = 未指派（设备 DHCP/静态自分配）。
    pub assigned_ipv4: Option<String>,
    pub tags: Vec<String>,
}

pub fn encode_device_id(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn role_for_member(
    cert: Option<&MemberCert>,
    local_device_id: Option<&str>,
    has_root_key: bool,
) -> DeviceRole {
    let Some(cert) = cert else {
        return DeviceRole::Member;
    };
    if has_root_key
        && local_device_id
            .map(|device_id| device_id == encode_device_id(cert.details.device_pk.as_bytes()))
            .unwrap_or(false)
    {
        DeviceRole::Root
    } else {
        DeviceRole::Member
    }
}

pub fn status_for_member(
    fingerprint: &MemberCertFingerprint,
    state: &SignedNetworkState,
    expires_at: u64,
    now: u64,
) -> DeviceStatus {
    if state
        .details
        .payload
        .revoked_certs
        .iter()
        .any(|revoked| revoked.cert_fingerprint == *fingerprint)
    {
        DeviceStatus::Revoked
    } else if state
        .details
        .payload
        .disabled_certs
        .iter()
        .any(|disabled| disabled.cert_fingerprint == *fingerprint)
    {
        DeviceStatus::Disabled
    } else if expires_at <= now {
        DeviceStatus::Expired
    } else {
        DeviceStatus::Active
    }
}

pub fn view_for_member(
    entry: &super::MemberCertIndexEntry,
    cert: Option<&MemberCert>,
    state: &SignedNetworkState,
    network_local_id: &str,
    local_device_id: Option<&str>,
    has_root_key: bool,
    now: u64,
) -> DeviceView {
    let tags = tags_for_member(&entry.fingerprint, state);
    let device_id = cert
        .map(|cert| encode_device_id(cert.details.device_pk.as_bytes()))
        .unwrap_or_else(|| "unknown".to_owned());
    let assigned_ipv4 = assigned_ipv4_for_device(&device_id, state);
    DeviceView {
        fingerprint: entry.fingerprint.to_string(),
        device_id: device_id.clone(),
        device_label: entry.device_label.clone(),
        role: role_for_member(cert, local_device_id, has_root_key),
        network_local_id: network_local_id.to_owned(),
        issued_at: entry.issued_at,
        expires_at: entry.expires_at,
        status: status_for_member(&entry.fingerprint, state, entry.expires_at, now),
        capabilities: cert
            .map(|cert| DeviceCapabilityView::from_capabilities(&cert.details.capabilities))
            .unwrap_or_else(|| DeviceCapabilityView {
                relay_data: false,
                relay_control: false,
                proxy_subnets: Vec::new(),
            }),
        hostname: cert
            .and_then(|cert| cert.details.hostname.as_ref())
            .map(|hostname| hostname.as_str().to_owned())
            .unwrap_or_default(),
        assigned_ipv4,
        tags,
    }
}

/// 从 network_state.ip_assignments 按稳定 device_id 取主控指派 IP（CIDR 串）。
fn assigned_ipv4_for_device(device_id: &str, state: &SignedNetworkState) -> Option<String> {
    state
        .details
        .payload
        .ip_assignments
        .iter()
        .find(|a| a.device_id == device_id)
        .map(|a| format!("{}/{}", a.ipv4.ipv4_addr(), a.ipv4.prefix))
}

fn tags_for_member(fingerprint: &MemberCertFingerprint, state: &SignedNetworkState) -> Vec<String> {
    let Ok(policy) = from_cbor::<AclPolicy>(&state.details.payload.acl) else {
        return Vec::new();
    };
    let member = DeviceFingerprint(fingerprint.0);
    policy
        .tags
        .iter()
        .filter(|(_, members)| members.contains(&member))
        .map(|(tag, _)| tag.as_str().to_owned())
        .collect()
}
