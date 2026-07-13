//! Web UI 访问来源：决定管理控制台绑定在哪个地址、放行哪些来源 IP。
//!
//! 该设置只决定控制台的**可见范围**，并不实施任何网络控制——治理操作本身仍由
//! 网络管理员口令保护。故读写它只需 console token，不要求网络管理员解锁。
//! 绑定地址无法热改，改动**重启服务后生效**。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use anyhow::Context;
use serde::{Deserialize, Serialize};

const CONSOLE_FILE: &str = "console.json";

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebuiAccess {
    /// 仅本机：真 loopback，端口对外不可见。
    #[default]
    Localhost,
    /// 仅局域网：绑 `0.0.0.0` 再按来源过滤。多网卡主机（有线/无线/overlay 并存）上
    /// 绑单个 LAN IP 会挡住其余网段的设备，故用来源过滤而非选一个网卡地址。
    Lan,
    /// 任何人：绑 `0.0.0.0`，不过滤来源。
    Public,
}

impl WebuiAccess {
    /// 有效绑定地址，端口沿用 `--listen` 的端口。
    pub fn bind(self, port: u16) -> SocketAddr {
        let ip = match self {
            Self::Localhost => IpAddr::V4(Ipv4Addr::LOCALHOST),
            Self::Lan | Self::Public => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        SocketAddr::new(ip, port)
    }

    /// 该来源 IP 是否放行。
    pub fn allows(self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        match self {
            Self::Localhost => ip.is_loopback(),
            Self::Lan => ip.is_loopback() || is_private(ip),
            Self::Public => true,
        }
    }
}

/// 私网来源：IPv4 RFC1918 + 链路本地；IPv6 ULA `fc00::/7` + 链路本地 `fe80::/10`
/// （后两者 std 判定尚未稳定，手写位测）。
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            let head = v6.segments()[0];
            head & 0xfe00 == 0xfc00 || head & 0xffc0 == 0xfe80
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
struct ConsoleConfig {
    #[serde(default)]
    webui_access: WebuiAccess,
}

fn console_path() -> anyhow::Result<PathBuf> {
    Ok(crate::common::config_dir::pnw_config_dir()?.join(CONSOLE_FILE))
}

/// 读取已保存的访问模式；文件缺失/损坏一律回落 `Localhost`（向后兼容旧安装）。
pub fn load() -> WebuiAccess {
    console_path()
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str::<ConsoleConfig>(&s).ok())
        .unwrap_or_default()
        .webui_access
}

pub fn save(mode: WebuiAccess) -> anyhow::Result<()> {
    let path = console_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let body = serde_json::to_string(&ConsoleConfig { webui_access: mode })?;
    std::fs::write(&path, body).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn localhost_only_allows_loopback() {
        let m = WebuiAccess::Localhost;
        assert!(m.allows(ip("127.0.0.1")));
        assert!(m.allows(ip("::1")));
        assert!(!m.allows(ip("192.168.1.10")));
        assert!(!m.allows(ip("203.0.113.7")));
        assert_eq!(m.bind(15810), "127.0.0.1:15810".parse().unwrap());
    }

    #[test]
    fn lan_allows_private_rejects_public() {
        let m = WebuiAccess::Lan;
        for s in ["127.0.0.1", "10.126.126.3", "172.16.0.9", "192.168.101.220", "169.254.1.1"] {
            assert!(m.allows(ip(s)), "{s} should be allowed");
        }
        for s in ["203.0.113.7", "8.8.8.8", "172.32.0.1"] {
            assert!(!m.allows(ip(s)), "{s} should be rejected");
        }
        assert_eq!(m.bind(15810), "0.0.0.0:15810".parse().unwrap());
    }

    #[test]
    fn public_allows_everything() {
        assert!(WebuiAccess::Public.allows(ip("203.0.113.7")));
        assert_eq!(WebuiAccess::Public.bind(15810), "0.0.0.0:15810".parse().unwrap());
    }

    /// 双栈 socket 上的 v4-mapped 来源（`::ffff:127.0.0.1`）必须按其 v4 语义判定。
    #[test]
    fn v4_mapped_is_canonicalized() {
        assert!(WebuiAccess::Localhost.allows(ip("::ffff:127.0.0.1")));
        assert!(WebuiAccess::Lan.allows(ip("::ffff:192.168.1.2")));
        assert!(!WebuiAccess::Lan.allows(ip("::ffff:203.0.113.7")));
    }
}
