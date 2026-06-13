use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use pnet::ipnetwork::IpNetwork;

use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx, idn, network::{is_usable_interface_ipv4, IPCollector}},
    connector::dns_connector::DnsTunnelConnector,
    proto::common::PeerFeatureFlag,
    tunnel::{
        self, FromUrl, IpScheme, IpVersion, TunnelConnector, TunnelError, TunnelScheme,
        ring::RingTunnelConnector, tcp::TcpTunnelConnector, udp::UdpTunnelConnector,
    },
    utils::BoxExt,
};
use http_connector::HttpTunnelConnector;

pub mod direct;
pub mod manual;
pub mod tcp_hole_punch;
pub mod udp_hole_punch;

pub mod dns_connector;
pub mod http_connector;

pub(crate) fn should_try_p2p_with_peer(
    feature_flag: Option<&PeerFeatureFlag>,
    allow_public_server: bool,
    local_disable_p2p: bool,
    local_need_p2p: bool,
) -> bool {
    feature_flag
        .map(|flag| {
            (allow_public_server || !flag.is_public_server)
                && (!local_disable_p2p || flag.need_p2p)
                && (!flag.disable_p2p || local_need_p2p)
        })
        .unwrap_or(!local_disable_p2p)
}

pub(crate) fn should_background_p2p_with_peer(
    feature_flag: Option<&PeerFeatureFlag>,
    allow_public_server: bool,
    lazy_p2p: bool,
    local_disable_p2p: bool,
    local_need_p2p: bool,
) -> bool {
    should_try_p2p_with_peer(
        feature_flag,
        allow_public_server,
        local_disable_p2p,
        local_need_p2p,
    ) && (!lazy_p2p || feature_flag.map(|flag| flag.need_p2p).unwrap_or(false))
}

async fn set_bind_addr_for_peer_connector(
    connector: &mut (impl TunnelConnector + ?Sized),
    dst_addr: SocketAddr,
    global_ctx: &ArcGlobalCtx,
) {
    if cfg!(any(
        target_os = "android",
        any(
            target_os = "ios",
            all(target_os = "macos", feature = "macos-ne")
        ),
        target_env = "ohos"
    )) {
        return;
    }

    let bind_addrs = collect_route_matched_bind_addrs(global_ctx, dst_addr).await;
    if bind_addrs.is_empty() {
        tracing::debug!(
            ?dst_addr,
            "no route-matched bind-device source addresses for direct connector"
        );
    }
    connector.set_bind_addrs(bind_addrs);
    let _ = connector;
}

async fn collect_route_matched_bind_addrs(
    global_ctx: &ArcGlobalCtx,
    dst_addr: SocketAddr,
) -> Vec<SocketAddr> {
    match dst_addr {
        SocketAddr::V4(dst) => {
            let is_private = private_ipv4_family(*dst.ip()).is_some();
            IPCollector::collect_interfaces(global_ctx.net_ns.clone(), true)
                .await
                .into_iter()
                .flat_map(|iface| iface.ips.into_iter())
                .filter_map(|ip| match ip {
                    IpNetwork::V4(network) => {
                        let src = network.ip();
                        let keep = if is_private {
                            network.contains(*dst.ip())
                        } else {
                            is_usable_interface_ipv4(src)
                        };
                        keep.then_some(src)
                    }
                    _ => None,
                })
                .map(|src| SocketAddrV4::new(src, 0).into())
                .collect::<Vec<_>>()
        }
        SocketAddr::V6(dst) => {
            let ips = global_ctx.get_ip_collector().collect_ip_addrs().await;
            ips.interface_ipv6s
                .iter()
                .chain(ips.public_ipv6.iter())
                .map(|src| Ipv6Addr::from(*src))
                .filter(|src| should_bind_ipv6_source_for_dst(*src, *dst.ip()))
                .map(|src| SocketAddrV6::new(src, 0, 0, 0).into())
                .collect::<Vec<_>>()
        }
    }
}

fn private_ipv4_family(ip: Ipv4Addr) -> Option<u8> {
    let octets = ip.octets();
    if octets[0] == 10 {
        Some(10)
    } else if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        Some(172)
    } else if octets[0] == 192 && octets[1] == 168 {
        Some(192)
    } else {
        None
    }
}

fn should_bind_ipv4_source_for_dst(src: Ipv4Addr, dst: Ipv4Addr) -> bool {
    private_ipv4_family(dst).is_some_and(|family| private_ipv4_family(src) == Some(family))
}

fn should_bind_ipv6_source_for_dst(src: Ipv6Addr, dst: Ipv6Addr) -> bool {
    dst.is_unique_local() && src.is_unique_local()
}

fn should_bind_device_for_dst(dst_addr: SocketAddr, bind_public: bool) -> bool {
    match dst_addr.ip() {
        // Private LAN/overlay always bind; public targets bind only when
        // bind_device_public is set, to pin the socket onto a physical NIC and
        // bypass TUN proxies that hijack the default route.
        IpAddr::V4(ip) => bind_public || private_ipv4_family(ip).is_some(),
        IpAddr::V6(ip) => bind_public || ip.is_unique_local(),
    }
}

pub async fn create_connector_by_url(
    url: &str,
    global_ctx: &ArcGlobalCtx,
    ip_version: IpVersion,
) -> Result<Box<dyn TunnelConnector + 'static>, Error> {
    let url = url::Url::parse(url).map_err(|_| Error::InvalidUrl(url.to_owned()))?;
    let url = idn::convert_idn_to_ascii(url)?;
    let scheme = (&url)
        .try_into()
        .map_err(|_| TunnelError::InvalidProtocol(url.scheme().to_owned()))?;
    let mut connector: Box<dyn TunnelConnector + 'static> = match scheme {
        TunnelScheme::Ip(scheme) => {
            let dst_addr = SocketAddr::from_url(url.clone(), ip_version).await?;
            let mut connector: Box<dyn TunnelConnector> = match scheme {
                IpScheme::Tcp => TcpTunnelConnector::new(url).boxed(),
                IpScheme::Udp => UdpTunnelConnector::new(url).boxed(),
                #[cfg(feature = "quic")]
                IpScheme::Quic => {
                    tunnel::quic::QuicTunnelConnector::new(url, global_ctx.clone()).boxed()
                }
                #[cfg(feature = "wireguard")]
                IpScheme::Wg => {
                    use crate::tunnel::wireguard::{WgConfig, WgTunnelConnector};
                    let nid = global_ctx.get_network_identity();
                    let wg_psk = base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        global_ctx.get_256_key(),
                    );
                    let wg_config = WgConfig::new_from_network_identity(&nid.network_name, &wg_psk);
                    WgTunnelConnector::new(url, wg_config).boxed()
                }
                #[cfg(feature = "websocket")]
                IpScheme::Ws | IpScheme::Wss => {
                    tunnel::websocket::WsTunnelConnector::new(url).boxed()
                }
                #[cfg(feature = "faketcp")]
                IpScheme::FakeTcp => tunnel::fake_tcp::FakeTcpTunnelConnector::new(url).boxed(),
            };
            let flags = global_ctx.config.get_flags();
            let bind_device = flags.bind_device;
            let should_bind_device =
                bind_device && should_bind_device_for_dst(dst_addr, flags.bind_device_public);
            if should_bind_device {
                set_bind_addr_for_peer_connector(&mut connector, dst_addr, global_ctx).await;
            } else if bind_device {
                tracing::debug!(
                    ?dst_addr,
                    "skip bind-device for default-routed direct connector destination"
                );
            }
            connector
        }
        #[cfg(unix)]
        TunnelScheme::Unix => tunnel::unix::UnixSocketTunnelConnector::new(url).boxed(),
        TunnelScheme::Http | TunnelScheme::Https => {
            HttpTunnelConnector::new(url, global_ctx.clone()).boxed()
        }
        TunnelScheme::Ring => RingTunnelConnector::new(url).boxed(),
        TunnelScheme::Txt | TunnelScheme::Srv => {
            if url.host_str().is_none() {
                return Err(Error::InvalidUrl(format!(
                    "host should not be empty in txt or srv url: {}",
                    url
                )));
            }
            DnsTunnelConnector::new(url, global_ctx.clone()).boxed()
        }
    };
    connector.set_ip_version(ip_version);

    Ok(connector)
}

#[cfg(test)]
mod tests {
    use crate::proto::common::PeerFeatureFlag;

    use super::{
        private_ipv4_family, should_background_p2p_with_peer, should_bind_device_for_dst,
        should_try_p2p_with_peer,
    };

    #[test]
    fn lazy_background_p2p_requires_need_p2p() {
        let no_need_p2p = PeerFeatureFlag {
            need_p2p: false,
            ..Default::default()
        };
        let need_p2p = PeerFeatureFlag {
            need_p2p: true,
            ..Default::default()
        };

        assert!(should_background_p2p_with_peer(
            Some(&no_need_p2p),
            false,
            false,
            false,
            false
        ));
        assert!(!should_background_p2p_with_peer(
            Some(&no_need_p2p),
            false,
            true,
            false,
            false
        ));
        assert!(should_background_p2p_with_peer(
            Some(&need_p2p),
            false,
            true,
            false,
            false
        ));
    }

    #[test]
    fn bind_device_is_only_used_for_private_direct_targets() {
        assert!(should_bind_device_for_dst(
            "192.168.6.128:11030".parse().unwrap(),
            false
        ));
        assert!(should_bind_device_for_dst(
            "10.0.0.100:11030".parse().unwrap(),
            false
        ));
        assert!(should_bind_device_for_dst(
            "172.16.4.8:11030".parse().unwrap(),
            false
        ));
        assert!(should_bind_device_for_dst(
            "[fd7b:cf81:ff54::785]:11030".parse().unwrap(),
            false
        ));

        assert!(!should_bind_device_for_dst(
            "203.0.113.9:11020".parse().unwrap(),
            false
        ));
        assert!(!should_bind_device_for_dst(
            "203.0.113.16:11010".parse().unwrap(),
            false
        ));
        assert!(!should_bind_device_for_dst(
            "127.0.0.1:11020".parse().unwrap(),
            false
        ));
        assert!(!should_bind_device_for_dst(
            "[2001:4860:4860::8888]:443".parse().unwrap(),
            false
        ));

        // With bind_device_public, public targets bind to a physical NIC too.
        assert!(should_bind_device_for_dst(
            "203.0.113.9:11020".parse().unwrap(),
            true
        ));
        assert!(should_bind_device_for_dst(
            "203.0.113.16:11010".parse().unwrap(),
            true
        ));
    }

    #[test]
    fn private_ipv4_family_recognizes_rfc1918_ranges() {
        assert_eq!(
            private_ipv4_family("10.0.0.100".parse().unwrap()),
            Some(10)
        );
        assert_eq!(
            private_ipv4_family("172.16.4.8".parse().unwrap()),
            Some(172)
        );
        assert_eq!(
            private_ipv4_family("172.31.4.8".parse().unwrap()),
            Some(172)
        );
        assert_eq!(
            private_ipv4_family("192.168.6.128".parse().unwrap()),
            Some(192)
        );

        assert_eq!(private_ipv4_family("172.32.4.8".parse().unwrap()), None);
        assert_eq!(private_ipv4_family("203.0.113.9".parse().unwrap()), None);
    }

    #[test]
    fn p2p_policy_respects_public_server_setting() {
        let public_server = PeerFeatureFlag {
            is_public_server: true,
            ..Default::default()
        };

        assert!(!should_try_p2p_with_peer(
            Some(&public_server),
            false,
            false,
            false
        ));
        assert!(should_try_p2p_with_peer(
            Some(&public_server),
            true,
            false,
            false
        ));
        assert!(!should_background_p2p_with_peer(
            Some(&public_server),
            false,
            false,
            false,
            false
        ));
        assert!(should_background_p2p_with_peer(
            Some(&public_server),
            true,
            false,
            false,
            false
        ));
    }

    #[test]
    fn disable_p2p_only_allows_need_p2p_exceptions() {
        let normal_peer = PeerFeatureFlag::default();
        let need_peer = PeerFeatureFlag {
            need_p2p: true,
            ..Default::default()
        };
        let disable_peer = PeerFeatureFlag {
            disable_p2p: true,
            ..Default::default()
        };
        let disable_need_peer = PeerFeatureFlag {
            disable_p2p: true,
            need_p2p: true,
            ..Default::default()
        };

        assert!(should_try_p2p_with_peer(
            Some(&normal_peer),
            false,
            false,
            false
        ));
        assert!(should_try_p2p_with_peer(None, false, false, false));
        assert!(!should_try_p2p_with_peer(None, false, true, false));
        assert!(!should_try_p2p_with_peer(
            Some(&normal_peer),
            false,
            true,
            false
        ));
        assert!(should_try_p2p_with_peer(
            Some(&need_peer),
            false,
            true,
            false
        ));
        assert!(!should_try_p2p_with_peer(
            Some(&disable_peer),
            false,
            false,
            false
        ));
        assert!(should_try_p2p_with_peer(
            Some(&disable_peer),
            false,
            false,
            true
        ));
        assert!(should_try_p2p_with_peer(
            Some(&disable_need_peer),
            false,
            true,
            true
        ));
        assert!(!should_try_p2p_with_peer(
            Some(&disable_need_peer),
            false,
            true,
            false
        ));
    }
}
