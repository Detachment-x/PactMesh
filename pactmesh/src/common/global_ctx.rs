use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use arc_swap::{ArcSwap, ArcSwapOption};
use dashmap::DashMap;

use super::{
    PeerId,
    config::{ConfigLoader, Flags},
    netns::NetNS,
    network::IPCollector,
    stun::{StunInfoCollector, StunInfoCollectorTrait},
};
use crate::{
    common::{
        config::ProxyNetworkConfig, shrink_dashmap, stats_manager::StatsManager,
        token_bucket::TokenBucketManager,
    },
    peers::{acl_filter::AclFilter, credential_manager::CredentialManager},
    proto::{
        acl::GroupIdentity,
        api::{config::InstanceConfigPatch, instance::PeerConnInfo},
        common::{PeerFeatureFlag, PortForwardConfigPb},
        peer_rpc::PeerGroupInfo,
    },
    rpc_service::protected_port,
    tunnel::matches_protocol,
};
use crossbeam::atomic::AtomicCell;
use sha2::{Digest, Sha256};
use socket2::Protocol;

pub type NetworkIdentity = crate::common::config::NetworkIdentity;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum GlobalCtxEvent {
    TunDeviceReady(String),
    TunDeviceError(String),

    PeerAdded(PeerId),
    PeerRemoved(PeerId),
    PeerConnAdded(PeerConnInfo),
    PeerConnRemoved(PeerConnInfo),

    ListenerAdded(url::Url),
    ListenerAddFailed(url::Url, String), // (url, error message)
    ListenerAcceptFailed(url::Url, String), // (url, error message)
    ConnectionAccepted(String, String),  // (local url, remote url)
    ConnectionError(String, String, String), // (local url, remote url, error message)
    ListenerPortMappingEstablished {
        local_listener: url::Url,
        mapped_listener: url::Url,
        backend: String,
    },

    Connecting(url::Url),
    ConnectError(String, String, String), // (dst, ip version, error message)

    VpnPortalStarted(String),                    // (portal)
    VpnPortalClientConnected(String, String),    // (portal, client ip)
    VpnPortalClientDisconnected(String, String), // (portal, client ip)

    DhcpIpv4Changed(Option<cidr::Ipv4Inet>, Option<cidr::Ipv4Inet>), // (old, new)
    DhcpIpv4Conflicted(Option<cidr::Ipv4Inet>),

    PortForwardAdded(PortForwardConfigPb),

    ConfigPatched(InstanceConfigPatch),

    ProxyCidrsUpdated(Vec<cidr::Ipv4Cidr>, Vec<cidr::Ipv4Cidr>), // (added, removed)

    CredentialChanged,
}

pub type EventBus = tokio::sync::broadcast::Sender<GlobalCtxEvent>;
pub type EventBusSubscriber = tokio::sync::broadcast::Receiver<GlobalCtxEvent>;

/// Source of a trusted public key from OSPF route propagation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedKeySource {
    /// Peer node's noise static pubkey
    OspfNode,
    /// Admin-declared trusted credential pubkey
    OspfCredential,
}

/// Metadata for a trusted public key
#[derive(Debug, Clone)]
pub struct TrustedKeyMetadata {
    pub source: TrustedKeySource,
    /// Expiry time in Unix seconds. None means never expires.
    pub expiry_unix: Option<i64>,
}

impl TrustedKeyMetadata {
    pub fn is_expired(&self) -> bool {
        if let Some(expiry) = self.expiry_unix {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            return now >= expiry;
        }
        false
    }
}

// key is (pubkey, network-name)
pub type TrustedKeyMap = HashMap<Vec<u8>, TrustedKeyMetadata>;

struct TrustedKeyMapManager {
    network_trusted_keys: DashMap<String, ArcSwap<TrustedKeyMap>>,
}

impl TrustedKeyMapManager {
    pub fn new() -> Self {
        Self {
            network_trusted_keys: DashMap::new(),
        }
    }

    pub fn update_trusted_keys(&self, network_name: &str, trusted_keys: TrustedKeyMap) {
        match self.network_trusted_keys.entry(network_name.to_string()) {
            dashmap::Entry::Vacant(entry) => {
                entry.insert(ArcSwap::new(Arc::new(trusted_keys)));
            }
            dashmap::Entry::Occupied(entry) => {
                entry.get().store(Arc::new(trusted_keys));
            }
        }
    }

    pub fn remove_trusted_keys(&self, network_name: &str) {
        self.network_trusted_keys.remove(network_name);
        shrink_dashmap(&self.network_trusted_keys, None);
    }

    pub fn verify_trusted_key(&self, pubkey: &[u8], network_name: &str) -> bool {
        self.verify_trusted_key_with_source(pubkey, network_name, None)
    }

    pub fn verify_trusted_key_with_source(
        &self,
        pubkey: &[u8],
        network_name: &str,
        source: Option<TrustedKeySource>,
    ) -> bool {
        let Some(trusted_keys) = self
            .network_trusted_keys
            .get(network_name)
            .map(|v| v.load_full())
        else {
            return false;
        };

        let Some(metadata) = trusted_keys.get(&pubkey.to_vec()) else {
            return false;
        };

        if let Some(source) = source {
            metadata.source == source && !metadata.is_expired()
        } else {
            !metadata.is_expired()
        }
    }

    pub fn list_trusted_keys(&self, network_name: &str) -> Vec<(Vec<u8>, TrustedKeyMetadata)> {
        let Some(trusted_keys) = self
            .network_trusted_keys
            .get(network_name)
            .map(|v| v.load_full())
        else {
            return Vec::new();
        };

        let mut items = trusted_keys
            .iter()
            .filter(|(_, metadata)| !metadata.is_expired())
            .map(|(pubkey, metadata)| (pubkey.clone(), metadata.clone()))
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.0.cmp(&right.0));
        items
    }
}

pub struct GlobalCtx {
    pub inst_name: String,
    pub id: uuid::Uuid,
    pub config: Box<dyn ConfigLoader>,
    pub net_ns: NetNS,
    pub network: NetworkIdentity,
    pub trust_context:
        tokio::sync::RwLock<Option<Arc<crate::common::trust_context::TrustDomainContext>>>,
    trust_data_keys: ArcSwap<TrustDataKeys>,

    event_bus: EventBus,

    cached_ipv4: AtomicCell<Option<cidr::Ipv4Inet>>,
    cached_ipv6: AtomicCell<Option<cidr::Ipv6Inet>>,
    cached_proxy_cidrs: AtomicCell<Option<Vec<ProxyNetworkConfig>>>,
    /// 本地 member cert `can_proxy_subnet` 的规范化字符串快照，随 trust context 设置。
    /// `None` = 无信任上下文（不裁剪路由宣告，向后兼容）；`Some` = 仅宣告其覆盖的 CIDR。
    cached_cert_proxy_allow: ArcSwapOption<Vec<String>>,
    /// 本地 member cert `can_be_exit_node` 快照，随 trust context 设置。
    /// `None` = 无信任上下文（不门控，加载期保护）；`Some(g)` = 仅当 g 时可服务出口。
    cached_cert_exit_node: AtomicCell<Option<bool>>,

    ip_collector: Mutex<Option<Arc<IPCollector>>>,

    hostname: Mutex<String>,

    stun_info_collection: Mutex<Arc<dyn StunInfoCollectorTrait>>,

    running_listeners: Mutex<Vec<url::Url>>,

    flags: ArcSwap<Flags>,

    feature_flags: AtomicCell<PeerFeatureFlag>,

    token_bucket_manager: TokenBucketManager,

    stats_manager: Arc<StatsManager>,

    acl_filter: Arc<AclFilter>,

    credential_manager: Arc<CredentialManager>,

    /// OSPF propagated trusted keys (peer pubkeys and admin credentials)
    /// Stored in ArcSwap for lock-free reads and atomic batch updates
    trusted_keys: Arc<TrustedKeyMapManager>,
}

impl std::fmt::Debug for GlobalCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GlobalCtx")
            .field("inst_name", &self.inst_name)
            .field("id", &self.id)
            .field("net_ns", &self.net_ns.name())
            .field("event_bus", &"EventBus")
            .field("ipv4", &self.cached_ipv4)
            .finish()
    }
}

pub type ArcGlobalCtx = std::sync::Arc<GlobalCtx>;

impl GlobalCtx {
    fn derive_feature_flags(flags: &Flags, current: Option<PeerFeatureFlag>) -> PeerFeatureFlag {
        let mut feature_flags = current.unwrap_or_default();
        feature_flags.kcp_input = !flags.disable_kcp_input;
        feature_flags.no_relay_kcp = flags.disable_relay_kcp;
        feature_flags.support_conn_list_sync = true;
        feature_flags.quic_input = !flags.disable_quic_input;
        feature_flags.no_relay_quic = flags.disable_relay_quic;
        feature_flags.need_p2p = flags.need_p2p;
        feature_flags.disable_p2p = flags.disable_p2p;
        feature_flags
    }

    pub fn new(config_fs: impl ConfigLoader + 'static) -> Self {
        let id = config_fs.get_id();
        let network = config_fs.get_network_identity();
        let net_ns = NetNS::new(config_fs.get_netns());
        let hostname = config_fs.get_hostname();

        let (event_bus, _) = tokio::sync::broadcast::channel(16);

        let stun_info_collector = StunInfoCollector::new_with_default_servers();

        // Prepend configured peer/root endpoints to the UDP NAT-detection list so
        // they land in the always-queried head (the detection routine samples only
        // the first 3 servers plus 1 random tail entry). A pactmesh root answers
        // STUN on its UDP listener from a literal public IP that is immune to
        // fake-ip DNS hijack, giving a reliable second vantage point when the
        // third-party STUN domains resolve into a default-route TUN proxy's
        // fake-ip range and get dropped as non-public.
        let mut udp_stun_servers: Vec<String> = Vec::new();
        for peer in config_fs.get_peers() {
            if let (Some(host), Some(port)) = (peer.uri.host_str(), peer.uri.port()) {
                let hp = format!("{host}:{port}");
                if !udp_stun_servers.contains(&hp) {
                    udp_stun_servers.push(hp);
                }
            }
        }
        for server in config_fs
            .get_stun_servers()
            .unwrap_or_else(StunInfoCollector::get_default_servers)
        {
            if !udp_stun_servers.contains(&server) {
                udp_stun_servers.push(server);
            }
        }
        stun_info_collector.set_stun_servers(udp_stun_servers);

        if let Some(stun_servers) = config_fs.get_stun_servers_v6() {
            stun_info_collector.set_stun_servers_v6(stun_servers);
        } else {
            stun_info_collector.set_stun_servers_v6(StunInfoCollector::get_default_servers_v6());
        }

        let flags = config_fs.get_flags();

        // Pin NAT-detection sockets to the same physical NIC as hole punching when
        // bind-device-public is enabled; otherwise a default-route TUN proxy
        // (clash/flclash) hijacks the STUN traffic and NAT type resolves to Unknown,
        // flipping the punch strategy to relay. Off by default — no behavior change.
        let stun_info_collector = if flags.bind_device
            && flags.bind_device_public
            && !flags.bind_device_name.is_empty()
        {
            stun_info_collector.with_bind_dev(
                crate::tunnel::common::BindDev::Custom(flags.bind_device_name.clone()),
                Some(net_ns.clone()),
            )
        } else {
            stun_info_collector
        };

        let stun_info_collector = Arc::new(stun_info_collector);

        let feature_flags = Self::derive_feature_flags(&flags, None);

        let credential_storage_path = config_fs.get_credential_file();
        let credential_manager = Arc::new(CredentialManager::new(credential_storage_path));

        GlobalCtx {
            inst_name: config_fs.get_inst_name(),
            id,
            config: Box::new(config_fs),
            net_ns: net_ns.clone(),
            network,
            trust_context: tokio::sync::RwLock::new(None),
            trust_data_keys: ArcSwap::new(Arc::new(TrustDataKeys::zero())),

            event_bus,
            cached_ipv4: AtomicCell::new(None),
            cached_ipv6: AtomicCell::new(None),
            cached_proxy_cidrs: AtomicCell::new(None),
            cached_cert_proxy_allow: ArcSwapOption::const_empty(),
            cached_cert_exit_node: AtomicCell::new(None),

            ip_collector: Mutex::new(Some(Arc::new(IPCollector::new(
                net_ns,
                stun_info_collector.clone(),
            )))),

            hostname: Mutex::new(hostname),

            stun_info_collection: Mutex::new(stun_info_collector),

            running_listeners: Mutex::new(Vec::new()),

            flags: ArcSwap::new(Arc::new(flags)),

            feature_flags: AtomicCell::new(feature_flags),

            token_bucket_manager: TokenBucketManager::new(),

            stats_manager: Arc::new(StatsManager::new()),

            acl_filter: Arc::new(AclFilter::new()),

            credential_manager,

            trusted_keys: Arc::new(TrustedKeyMapManager::new()),
        }
    }

    pub fn subscribe(&self) -> EventBusSubscriber {
        self.event_bus.subscribe()
    }

    pub fn issue_event(&self, event: GlobalCtxEvent) {
        if let Err(e) = self.event_bus.send(event.clone()) {
            tracing::warn!(
                "Failed to send event: {:?}, error: {:?}, receiver count: {}",
                event,
                e,
                self.event_bus.receiver_count()
            );
        }
    }

    pub fn check_network_in_whitelist(&self, network_name: &str) -> Result<(), anyhow::Error> {
        if self
            .get_flags()
            .relay_network_whitelist
            .split(" ")
            .map(wildmatch::WildMatch::new)
            .any(|wl| wl.matches(network_name))
        {
            Ok(())
        } else {
            Err(anyhow::anyhow!("network {} not in whitelist", network_name))
        }
    }

    pub fn get_ipv4(&self) -> Option<cidr::Ipv4Inet> {
        if let Some(ret) = self.cached_ipv4.load() {
            return Some(ret);
        }
        let addr = self.config.get_ipv4();
        self.cached_ipv4.store(addr);
        addr
    }

    pub fn set_ipv4(&self, addr: Option<cidr::Ipv4Inet>) {
        self.config.set_ipv4(addr);
        self.cached_ipv4.store(None);
    }

    pub fn get_ipv6(&self) -> Option<cidr::Ipv6Inet> {
        if let Some(ret) = self.cached_ipv6.load() {
            return Some(ret);
        }
        let addr = self.config.get_ipv6();
        self.cached_ipv6.store(addr);
        addr
    }

    pub fn set_ipv6(&self, addr: Option<cidr::Ipv6Inet>) {
        self.config.set_ipv6(addr);
        self.cached_ipv6.store(None);
    }

    pub fn get_id(&self) -> uuid::Uuid {
        self.config.get_id()
    }

    pub fn is_ip_in_same_network(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.get_ipv4().map(|x| x.contains(v4)).unwrap_or(false),
            IpAddr::V6(v6) => self.get_ipv6().map(|x| x.contains(v6)).unwrap_or(false),
        }
    }

    pub fn is_ip_local_virtual_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.get_ipv4().map(|x| x.address() == *v4).unwrap_or(false),
            IpAddr::V6(v6) => self.get_ipv6().map(|x| x.address() == *v6).unwrap_or(false),
        }
    }

    pub fn get_network_identity(&self) -> NetworkIdentity {
        self.config.get_network_identity()
    }

    pub fn get_network_name(&self) -> String {
        self.get_network_identity().network_name
    }

    pub fn get_ip_collector(&self) -> Arc<IPCollector> {
        self.ip_collector.lock().unwrap().as_ref().unwrap().clone()
    }

    pub fn get_hostname(&self) -> String {
        return self.hostname.lock().unwrap().clone();
    }

    pub fn set_hostname(&self, hostname: String) {
        *self.hostname.lock().unwrap() = hostname;
    }

    pub fn get_stun_info_collector(&self) -> Arc<dyn StunInfoCollectorTrait> {
        self.stun_info_collection.lock().unwrap().clone()
    }

    pub fn replace_stun_info_collector(&self, collector: Box<dyn StunInfoCollectorTrait>) {
        let arc_collector: Arc<dyn StunInfoCollectorTrait> = Arc::new(collector);
        *self.stun_info_collection.lock().unwrap() = arc_collector.clone();

        // rebuild the ip collector
        *self.ip_collector.lock().unwrap() = Some(Arc::new(IPCollector::new(
            self.net_ns.clone(),
            arc_collector,
        )));
    }

    pub fn get_running_listeners(&self) -> Vec<url::Url> {
        self.running_listeners.lock().unwrap().clone()
    }

    pub fn add_running_listener(&self, url: url::Url) {
        let mut l = self.running_listeners.lock().unwrap();
        if !l.contains(&url) {
            l.push(url);
        }
    }

    pub fn get_vpn_portal_cidr(&self) -> Option<cidr::Ipv4Cidr> {
        self.config.get_vpn_portal_config().map(|x| x.client_cidr)
    }

    pub fn get_flags(&self) -> Flags {
        self.flags.load().as_ref().clone()
    }

    pub fn set_flags(&self, flags: Flags) {
        self.config.set_flags(flags.clone());
        self.feature_flags.store(Self::derive_feature_flags(
            &flags,
            Some(self.feature_flags.load()),
        ));
        self.flags.store(Arc::new(flags));
    }

    pub fn flags_arc(&self) -> Arc<Flags> {
        self.flags.load_full()
    }
    pub fn get_128_key(&self) -> [u8; 16] {
        self.trust_data_keys.load().key_128
    }

    pub fn get_256_key(&self) -> [u8; 32] {
        self.trust_data_keys.load().key_256
    }
    pub fn enable_exit_node(&self) -> bool {
        let intent = self.flags.load().enable_exit_node || cfg!(target_env = "ohos");
        // 有信任上下文时由 cert 门控出口服务；无上下文（加载期）退化为仅看本地意图。
        match self.cached_cert_exit_node.load() {
            Some(granted) => intent && granted,
            None => intent,
        }
    }

    pub fn proxy_forward_by_system(&self) -> bool {
        self.flags.load().proxy_forward_by_system
    }

    pub fn no_tun(&self) -> bool {
        self.flags.load().no_tun
    }

    pub fn get_feature_flags(&self) -> PeerFeatureFlag {
        self.feature_flags.load()
    }

    pub fn set_feature_flags(&self, flags: PeerFeatureFlag) {
        self.feature_flags.store(flags);
    }

    pub fn token_bucket_manager(&self) -> &TokenBucketManager {
        &self.token_bucket_manager
    }

    pub fn stats_manager(&self) -> &Arc<StatsManager> {
        &self.stats_manager
    }

    pub fn get_acl_filter(&self) -> &Arc<AclFilter> {
        &self.acl_filter
    }

    pub fn get_credential_manager(&self) -> &Arc<CredentialManager> {
        &self.credential_manager
    }

    /// Check if a public key is trusted using two-level lookup:
    /// 1. OSPF propagated trusted_keys (lock-free)
    /// 2. Local credential_manager
    pub fn is_pubkey_trusted(&self, pubkey: &[u8], network_name: &str) -> bool {
        // First level: check OSPF propagated keys (lock-free)
        if self.trusted_keys.verify_trusted_key(pubkey, network_name) {
            return true;
        }

        // Second level: check local credential_manager if in the same network
        if network_name == self.get_network_name() {
            return self.credential_manager.is_pubkey_trusted(pubkey);
        }

        false
    }

    pub fn is_pubkey_trusted_with_source(
        &self,
        pubkey: &[u8],
        network_name: &str,
        source: TrustedKeySource,
    ) -> bool {
        self.trusted_keys
            .verify_trusted_key_with_source(pubkey, network_name, Some(source))
    }

    /// Atomically replace all OSPF trusted keys with a new set
    /// Called by OSPF route layer after each route update
    pub fn update_trusted_keys(&self, keys: TrustedKeyMap, network_name: &str) {
        self.trusted_keys.update_trusted_keys(network_name, keys);
    }

    pub fn remove_trusted_keys(&self, network_name: &str) {
        self.trusted_keys.remove_trusted_keys(network_name);
    }

    pub fn list_trusted_keys(&self, network_name: &str) -> Vec<(Vec<u8>, TrustedKeyMetadata)> {
        self.trusted_keys.list_trusted_keys(network_name)
    }

    pub fn get_acl_groups(&self, peer_id: PeerId) -> Vec<PeerGroupInfo> {
        use std::collections::HashSet;
        self.config
            .get_acl()
            .and_then(|acl| acl.acl_v1)
            .and_then(|acl_v1| acl_v1.group)
            .map_or_else(Vec::new, |group| {
                let memberships: HashSet<_> = group.members.iter().collect();
                group
                    .declares
                    .iter()
                    .filter(|g| memberships.contains(&g.group_name))
                    .map(|g| {
                        PeerGroupInfo::generate_with_proof(
                            g.group_name.clone(),
                            g.group_secret.clone(),
                            peer_id,
                        )
                    })
                    .collect()
            })
    }

    pub fn get_acl_group_declarations(&self) -> Vec<GroupIdentity> {
        self.config
            .get_acl()
            .and_then(|acl| acl.acl_v1)
            .and_then(|acl_v1| acl_v1.group)
            .map_or_else(Vec::new, |group| group.declares.to_vec())
    }

    pub fn p2p_only(&self) -> bool {
        self.flags.load().p2p_only
    }

    pub fn latency_first(&self) -> bool {
        // NOTICE: p2p only is conflict with latency first
        let flags = self.flags.load();
        flags.latency_first && !flags.p2p_only
    }

    fn is_port_in_running_listeners(&self, port: u16, is_udp: bool) -> bool {
        self.running_listeners
            .lock()
            .unwrap()
            .iter()
            .any(|x| x.port() == Some(port) && matches_protocol!(x, Protocol::UDP) == is_udp)
    }

    #[tracing::instrument(ret, skip(self))]
    pub fn should_deny_proxy(&self, dst_addr: &SocketAddr, is_udp: bool) -> bool {
        let _g = self.net_ns.guard();
        let ip = dst_addr.ip();
        // first check if ip is virtual ip
        // then try bind this ip, if succ means it is local ip
        let dst_is_local_virtual_ip = self.is_ip_local_virtual_ip(&ip);
        // this is an expensive operation, should be called sparingly
        // 1. tcp/kcp/quic call this only after proxy conn is established
        // 2. udp cache the result in nat entry
        let dst_is_local_phy_ip = std::net::UdpSocket::bind(format!("{}:0", ip)).is_ok();

        tracing::trace!(
            "check should_deny_proxy: dst_addr={}, dst_is_local_virtual_ip={}, dst_is_local_phy_ip={}, is_udp={}",
            dst_addr,
            dst_is_local_virtual_ip,
            dst_is_local_phy_ip,
            is_udp
        );

        if dst_is_local_virtual_ip || dst_is_local_phy_ip {
            // if is local ip, make sure the port is not one of the listening ports
            self.is_port_in_running_listeners(dst_addr.port(), is_udp)
                || (!is_udp && protected_port::is_protected_tcp_port(dst_addr.port()))
        } else {
            false
        }
    }

    pub async fn get_trust_context(
        &self,
    ) -> Option<Arc<crate::common::trust_context::TrustDomainContext>> {
        self.trust_context.read().await.clone()
    }

    pub fn trust_context_blocking(
        &self,
    ) -> Option<Arc<crate::common::trust_context::TrustDomainContext>> {
        self.trust_context.blocking_read().clone()
    }

    pub async fn set_trust_context(
        &self,
        ctx: Arc<crate::common::trust_context::TrustDomainContext>,
    ) {
        let allow: Vec<String> = ctx
            .member_cert
            .details
            .capabilities
            .can_proxy_subnet
            .iter()
            .map(|net| net.to_string())
            .collect();
        self.cached_cert_proxy_allow.store(Some(Arc::new(allow)));
        self.cached_cert_exit_node
            .store(Some(ctx.member_cert.details.capabilities.can_be_exit_node));
        *self.trust_context.write().await = Some(ctx);
    }

    /// 本地 member cert 授权的 proxy CIDR 快照（字符串）；`None` 表示无信任上下文。
    pub fn cert_proxy_allow(&self) -> Option<Arc<Vec<String>>> {
        self.cached_cert_proxy_allow.load_full()
    }

    pub fn set_trust_data_keys_from_network_state(&self, state: &crate::trust::SignedNetworkState) {
        self.trust_data_keys
            .store(Arc::new(TrustDataKeys::derive_from_network_state(state)));
    }
}

#[derive(Debug, Clone)]
struct TrustDataKeys {
    key_128: [u8; 16],
    key_256: [u8; 32],
}

impl TrustDataKeys {
    fn zero() -> Self {
        Self {
            key_128: [0u8; 16],
            key_256: [0u8; 32],
        }
    }

    fn derive_from_network_state(state: &crate::trust::SignedNetworkState) -> Self {
        let base = derive_trust_key(state, b"pactmesh data-plane key v1");
        let key_128_full = derive_trust_key(state, b"pactmesh data-plane key v1 aes-128");
        let mut key_128 = [0u8; 16];
        key_128.copy_from_slice(&key_128_full[..16]);
        Self {
            key_128,
            key_256: base,
        }
    }
}

fn derive_trust_key(state: &crate::trust::SignedNetworkState, label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(state.details.trust_domain_id.as_bytes());
    hasher.update(state.details.network_local_id.as_str().as_bytes());
    hasher.update(state.details.version.to_be_bytes());
    hasher.update(&state.signature.0);
    hasher.finalize().into()
}

#[cfg(test)]
pub mod tests {
    use crate::{
        common::{config::TomlConfigLoader, new_peer_id, stun::MockStunInfoCollector},
        proto::common::NatType,
    };

    use super::*;

    #[tokio::test]
    async fn test_global_ctx() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);

        let mut subscriber = global_ctx.subscribe();
        let peer_id = new_peer_id();
        global_ctx.issue_event(GlobalCtxEvent::PeerAdded(peer_id));
        global_ctx.issue_event(GlobalCtxEvent::PeerRemoved(peer_id));
        global_ctx.issue_event(GlobalCtxEvent::PeerConnAdded(PeerConnInfo::default()));
        global_ctx.issue_event(GlobalCtxEvent::PeerConnRemoved(PeerConnInfo::default()));

        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerAdded(peer_id)
        );
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerRemoved(peer_id)
        );
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerConnAdded(PeerConnInfo::default())
        );
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerConnRemoved(PeerConnInfo::default())
        );
    }

    #[tokio::test]
    async fn trusted_key_source_lookup_is_precise() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);
        let network_name = "net1";
        let pubkey = vec![1; 32];

        global_ctx.update_trusted_keys(
            HashMap::from([(
                pubkey.clone(),
                TrustedKeyMetadata {
                    source: TrustedKeySource::OspfCredential,
                    expiry_unix: None,
                },
            )]),
            network_name,
        );

        assert!(global_ctx.is_pubkey_trusted(&pubkey, network_name));
        assert!(!global_ctx.is_pubkey_trusted_with_source(
            &pubkey,
            network_name,
            TrustedKeySource::OspfNode,
        ));
        assert!(global_ctx.is_pubkey_trusted_with_source(
            &pubkey,
            network_name,
            TrustedKeySource::OspfCredential,
        ));
    }

    #[tokio::test]
    async fn set_flags_keeps_derived_feature_flags_in_sync() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);

        let mut feature_flags = global_ctx.get_feature_flags();
        feature_flags.avoid_relay_data = true;
        feature_flags.is_public_server = true;
        global_ctx.set_feature_flags(feature_flags);

        let mut flags = global_ctx.get_flags().clone();
        flags.disable_kcp_input = true;
        flags.disable_relay_kcp = true;
        flags.disable_quic_input = true;
        flags.disable_relay_quic = true;
        flags.need_p2p = true;
        flags.disable_p2p = true;
        global_ctx.set_flags(flags);

        let feature_flags = global_ctx.get_feature_flags();
        assert!(!feature_flags.kcp_input);
        assert!(feature_flags.no_relay_kcp);
        assert!(!feature_flags.quic_input);
        assert!(feature_flags.no_relay_quic);
        assert!(feature_flags.need_p2p);
        assert!(feature_flags.disable_p2p);
        assert!(feature_flags.support_conn_list_sync);
        assert!(feature_flags.avoid_relay_data);
        assert!(feature_flags.is_public_server);
    }

    #[test]
    fn trust_data_keys_are_shared_for_same_network_state_and_rotate_with_version() {
        use crate::trust::{
            NetworkLocalId, NetworkStatePayload, TrustDomainRoot, UnsignedNetworkState,
        };

        fn state(root: &TrustDomainRoot, version: u64) -> crate::trust::SignedNetworkState {
            UnsignedNetworkState {
                trust_domain_id: root.id(),
                network_local_id: NetworkLocalId::try_from_str("office-net").unwrap(),
                version,
                payload: NetworkStatePayload {
                    member_cert_index: Vec::new(),
                    revoked_certs: Vec::new(),
                    disabled_certs: Vec::new(),
                    acl: Vec::new(),
                    routes: Vec::new(),
                    peer_hints: Vec::new(),
                    ip_assignments: Vec::new(),
                },
            }
            .sign(root)
        }

        let root = TrustDomainRoot::generate();
        let state_v1 = state(&root, 1);
        let state_v1_again = state_v1.clone();
        let state_v2 = state(&root, 2);

        let k1 = TrustDataKeys::derive_from_network_state(&state_v1);
        let k1_again = TrustDataKeys::derive_from_network_state(&state_v1_again);
        let k2 = TrustDataKeys::derive_from_network_state(&state_v2);

        assert_ne!(k1.key_128, [0u8; 16]);
        assert_ne!(k1.key_256, [0u8; 32]);
        assert_eq!(k1.key_128, k1_again.key_128);
        assert_eq!(k1.key_256, k1_again.key_256);
        assert_ne!(k1.key_256, k2.key_256);
    }

    #[tokio::test]
    async fn should_deny_proxy_for_process_wide_rpc_port() {
        protected_port::clear_protected_tcp_ports_for_test();
        protected_port::register_protected_tcp_port(15888);

        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);
        let rpc_addr = SocketAddr::from(([127, 0, 0, 1], 15888));
        let other_tcp_addr = SocketAddr::from(([127, 0, 0, 1], 15889));

        assert!(global_ctx.should_deny_proxy(&rpc_addr, false));
        assert!(!global_ctx.should_deny_proxy(&rpc_addr, true));
        assert!(!global_ctx.should_deny_proxy(&other_tcp_addr, false));

        protected_port::clear_protected_tcp_ports_for_test();
    }

    pub fn get_mock_global_ctx_with_network(
        network_identy: Option<NetworkIdentity>,
    ) -> ArcGlobalCtx {
        let config_fs = TomlConfigLoader::default();
        config_fs.set_inst_name(format!("test_{}", config_fs.get_id()));
        config_fs.set_network_identity(network_identy.unwrap_or_default());

        let ctx = Arc::new(GlobalCtx::new(config_fs));
        ctx.replace_stun_info_collector(Box::new(MockStunInfoCollector {
            udp_nat_type: NatType::Unknown,
        }));
        ctx
    }

    pub fn get_mock_global_ctx() -> ArcGlobalCtx {
        get_mock_global_ctx_with_network(None)
    }
}
