use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, prelude::BASE64_STANDARD};
use cidr::Ipv4Cidr;
use pactmesh::{
    common::{
        config::{ConfigLoader, NetworkIdentity, TomlConfigLoader},
        stats_manager::{LabelSet, LabelType, MetricName},
        trust_context::TrustDomainContext,
    },
    instance::instance::Instance,
    proto::common::SecureModeConfig,
    trust::{
        ACL_SCHEMA_VERSION, AclPolicy, AclRule, Action, Capabilities, DeviceFingerprint,
        MemberCert, NetworkLocalId, NetworkStatePayload, PortSpec, Proto, Selector, SignKey,
        SignedNetworkState, TagName, TrustDomainPool, TrustDomainRoot, UnsignedMemberCert,
        UnsignedNetworkState,
    },
    tunnel::{
        common::tests::wait_for_condition, packet_def::ZCPacket, ring::create_ring_tunnel_pair,
    },
};
use rand::rngs::OsRng;
use serial_test::serial;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use x25519_dalek::{PublicKey, StaticSecret};

const NETWORK_LOCAL_ID: &str = "office-net";
const NETWORK_STATE_VERSION: u64 = 1;

struct MemberFixture {
    sk_self: SignKey,
    cert: MemberCert,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

fn generate_secure_mode_config() -> SecureModeConfig {
    let private = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&private);
    SecureModeConfig {
        enabled: true,
        local_private_key: Some(BASE64_STANDARD.encode(private.as_bytes())),
        local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
    }
}

fn base_config(inst_name: &str, ipv4: &str) -> TomlConfigLoader {
    let cfg = TomlConfigLoader::default();
    cfg.set_inst_name(inst_name.to_owned());
    cfg.set_network_identity(NetworkIdentity::new("acl-e2e".to_owned()));
    cfg.set_secure_mode(Some(generate_secure_mode_config()));
    cfg.set_ipv4(Some(ipv4.parse().unwrap()));
    let mut flags = cfg.get_flags();
    flags.no_tun = true;
    cfg.set_flags(flags);
    cfg
}

fn make_member(root: &TrustDomainRoot, label: &str) -> MemberFixture {
    make_member_with_proxy(root, label, Vec::new())
}

fn make_member_with_proxy(
    root: &TrustDomainRoot,
    label: &str,
    proxy_cidrs: Vec<pnet::ipnetwork::IpNetwork>,
) -> MemberFixture {
    let sk_self = SignKey::generate();
    let verify_key = ed25519_dalek::VerifyingKey::from_bytes(&sk_self.verify_key().0).unwrap();
    let now = now_unix();
    let cert = UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str(NETWORK_LOCAL_ID).unwrap(),
        device_pk: verify_key,
        device_label: label.to_owned(),
        not_before: now.saturating_sub(60),
        expires_at: now + 3600,
        capabilities: Capabilities {
            can_be_exit_node: false,
            can_relay_data: true,
            can_relay_control: true,
            can_proxy_subnet: proxy_cidrs,
        },
        network_state_version_ref: NETWORK_STATE_VERSION,
        hostname: None,
    }
    .sign(root);
    MemberFixture { sk_self, cert }
}

fn device_fp(cert: &MemberCert) -> DeviceFingerprint {
    DeviceFingerprint::new(Sha256::digest(cert.details.device_pk.as_bytes()).into())
}

fn tag(name: &str) -> TagName {
    TagName::try_from_str(name).unwrap()
}

fn state(root: &TrustDomainRoot, version: u64, acl: AclPolicy) -> SignedNetworkState {
    UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str(NETWORK_LOCAL_ID).unwrap(),
        version,
        payload: NetworkStatePayload {
            member_cert_index: Vec::new(),
            revoked_certs: Vec::new(),
            disabled_certs: Vec::new(),
            acl: pactmesh::trust::to_canonical_cbor(&acl),
            routes: Vec::new(),
            peer_hints: Vec::new(),
        },
    }
    .sign(root)
}

fn pool(root: &TrustDomainRoot, state: SignedNetworkState) -> Arc<RwLock<TrustDomainPool>> {
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    pool.apply_network_state(state).unwrap();
    Arc::new(RwLock::new(pool))
}

async fn attach_trust_context(inst: &Instance, root: &TrustDomainRoot, member: &MemberFixture) {
    inst.get_global_ctx()
        .set_trust_context(Arc::new(TrustDomainContext::new(
            root.id(),
            member.cert.details.network_local_id.clone(),
            member.cert.clone(),
            member.sk_self.clone(),
        )))
        .await;
}

async fn connect(a: &Instance, b: &Instance) {
    let (a_tunnel, b_tunnel) = create_ring_tunnel_pair();
    let a_pm = a.get_peer_manager();
    let b_pm = b.get_peer_manager();
    let (a_ret, b_ret) = tokio::join!(
        a_pm.add_client_tunnel(a_tunnel, true),
        b_pm.add_tunnel_as_server(b_tunnel, true),
    );
    a_ret.unwrap();
    b_ret.unwrap();
    wait_for_condition(
        || {
            let a_pm = a_pm.clone();
            let b_pm = b_pm.clone();
            async move {
                !a_pm.get_peer_map().list_peers_with_conn().await.is_empty()
                    && !b_pm.get_peer_map().list_peers_with_conn().await.is_empty()
            }
        },
        Duration::from_secs(5),
    )
    .await;
}

async fn setup(
    root: &TrustDomainRoot,
    client: &MemberFixture,
    server: &MemberFixture,
    acl: AclPolicy,
) -> (Instance, Instance, Arc<RwLock<TrustDomainPool>>) {
    let state = state(root, NETWORK_STATE_VERSION, acl);
    let shared_pool = pool(root, state);
    let mut inst_a = Instance::new_with_trust_pool(
        base_config("client-a", "10.144.144.1"),
        Some(shared_pool.clone()),
    );
    let mut inst_c = Instance::new_with_trust_pool(
        base_config("server-c", "10.144.144.3"),
        Some(shared_pool.clone()),
    );
    attach_trust_context(&inst_a, root, client).await;
    attach_trust_context(&inst_c, root, server).await;
    inst_a.run().await.unwrap();
    inst_c.run().await.unwrap();
    connect(&inst_a, &inst_c).await;
    let peer_manager = inst_a.get_peer_manager();
    wait_for_condition(
        || {
            let peer_manager = peer_manager.clone();
            async move {
                peer_manager
                    .get_route()
                    .get_peer_id_by_ip(&IpAddr::from([10, 144, 144, 3]))
                    .await
                    .is_some()
            }
        },
        Duration::from_secs(5),
    )
    .await;
    (inst_a, inst_c, shared_pool)
}

fn policy(
    default_action: Action,
    rules: Vec<AclRule>,
    client: &MemberCert,
    server: &MemberCert,
) -> AclPolicy {
    let mut tags = BTreeMap::new();
    tags.insert(tag("client"), vec![device_fp(client)]);
    tags.insert(tag("server"), vec![device_fp(server)]);
    AclPolicy {
        tags,
        rules,
        default_action,
        schema_version: ACL_SCHEMA_VERSION,
    }
}

fn cidr_selector(text: &str) -> pactmesh::trust::Cidr {
    match text.parse::<pnet::ipnetwork::IpNetwork>().unwrap() {
        pnet::ipnetwork::IpNetwork::V4(net) => {
            pactmesh::trust::Cidr::new(IpAddr::V4(net.ip()), net.prefix())
        }
        pnet::ipnetwork::IpNetwork::V6(net) => {
            pactmesh::trust::Cidr::new(IpAddr::V6(net.ip()), net.prefix())
        }
    }
}

fn subnet_packet() -> ZCPacket {
    let mut payload = [0u8; 28];
    let payload_len = payload.len() as u16;
    payload[0] = 0x45;
    payload[2..4].copy_from_slice(&payload_len.to_be_bytes());
    payload[8] = 64;
    payload[9] = 1;
    payload[12..16].copy_from_slice(&[10, 144, 144, 1]);
    payload[16..20].copy_from_slice(&[10, 0, 0, 42]);
    payload[20] = 8;
    ZCPacket::new_with_payload(&payload)
}

fn tcp_packet(dst_port: u16) -> ZCPacket {
    let mut payload = [0u8; 40];
    let payload_len = payload.len() as u16;
    payload[0] = 0x45;
    payload[2..4].copy_from_slice(&payload_len.to_be_bytes());
    payload[8] = 64;
    payload[9] = 6;
    payload[12..16].copy_from_slice(&[10, 144, 144, 1]);
    payload[16..20].copy_from_slice(&[10, 144, 144, 3]);
    payload[20..22].copy_from_slice(&55555u16.to_be_bytes());
    payload[22..24].copy_from_slice(&dst_port.to_be_bytes());
    ZCPacket::new_with_payload(&payload)
}

fn icmp_packet() -> ZCPacket {
    let mut payload = [0u8; 28];
    let payload_len = payload.len() as u16;
    payload[0] = 0x45;
    payload[2..4].copy_from_slice(&payload_len.to_be_bytes());
    payload[8] = 64;
    payload[9] = 1;
    payload[12..16].copy_from_slice(&[10, 144, 144, 1]);
    payload[16..20].copy_from_slice(&[10, 144, 144, 3]);
    payload[20] = 8;
    ZCPacket::new_with_payload(&payload)
}

fn tx_bytes(inst: &Instance) -> u64 {
    let labels = LabelSet::new().with_label_type(LabelType::NetworkName(
        inst.get_global_ctx().get_network_name(),
    ));
    inst.get_global_ctx()
        .stats_manager()
        .get_metric(MetricName::TrafficBytesTx, &labels)
        .map(|metric| metric.value)
        .unwrap_or(0)
}

async fn send_to_server(inst: &Instance, packet: ZCPacket) {
    inst.get_peer_manager()
        .send_msg_by_ip(packet, IpAddr::from([10, 144, 144, 3]), false)
        .await
        .unwrap();
}

async fn send_to_proxy_subnet(inst: &Instance, packet: ZCPacket) {
    inst.get_peer_manager()
        .send_msg_by_ip(packet, IpAddr::from([10, 0, 0, 42]), false)
        .await
        .unwrap();
}

async fn assert_tx_increases(inst: &Instance, packet: ZCPacket) {
    let before = tx_bytes(inst);
    send_to_server(inst, packet).await;
    wait_for_condition(|| async { tx_bytes(inst) > before }, Duration::from_secs(5)).await;
}

async fn assert_tx_increases_to_proxy_subnet(inst: &Instance, packet: ZCPacket) {
    let before = tx_bytes(inst);
    send_to_proxy_subnet(inst, packet).await;
    wait_for_condition(|| async { tx_bytes(inst) > before }, Duration::from_secs(5)).await;
}

async fn assert_tx_unchanged(inst: &Instance, packet: ZCPacket) {
    let before = tx_bytes(inst);
    send_to_server(inst, packet).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(tx_bytes(inst), before);
}

async fn clear(mut instances: Vec<Instance>) {
    for inst in &mut instances {
        inst.clear_resources().await;
    }
}

async fn setup_proxy_topology(
    root: &TrustDomainRoot,
    client: &MemberFixture,
    proxy_c: &MemberFixture,
    proxy_d: &MemberFixture,
    acl: AclPolicy,
) -> (Instance, Instance, Instance, Arc<RwLock<TrustDomainPool>>) {
    let state = state(root, NETWORK_STATE_VERSION, acl);
    let shared_pool = pool(root, state);

    let mut inst_a = Instance::new_with_trust_pool(
        base_config("client-a", "10.144.144.1"),
        Some(shared_pool.clone()),
    );
    let mut inst_c = Instance::new_with_trust_pool(
        base_config("proxy-c", "10.144.144.3"),
        Some(shared_pool.clone()),
    );
    let mut inst_d = Instance::new_with_trust_pool(
        base_config("proxy-d", "10.144.144.4"),
        Some(shared_pool.clone()),
    );
    attach_trust_context(&inst_a, root, client).await;
    attach_trust_context(&inst_c, root, proxy_c).await;
    attach_trust_context(&inst_d, root, proxy_d).await;
    inst_a.run().await.unwrap();
    inst_c.run().await.unwrap();
    inst_d.run().await.unwrap();
    connect(&inst_a, &inst_c).await;
    connect(&inst_a, &inst_d).await;
    (inst_a, inst_c, inst_d, shared_pool)
}

#[tokio::test]
#[serial]
async fn test_acl_default_accept_allows_icmp() {
    let root = TrustDomainRoot::generate();
    let client = make_member(&root, "client-a");
    let server = make_member(&root, "server-c");
    let acl = policy(Action::Accept, Vec::new(), &client.cert, &server.cert);
    let (inst_a, inst_c, _) = setup(&root, &client, &server, acl).await;

    assert_tx_increases(&inst_a, icmp_packet()).await;

    clear(vec![inst_a, inst_c]).await;
}

#[tokio::test]
#[serial]
async fn test_acl_drops_client_to_server_tcp_22_but_allows_icmp() {
    let root = TrustDomainRoot::generate();
    let client = make_member(&root, "client-a");
    let server = make_member(&root, "server-c");
    let acl = policy(
        Action::Accept,
        vec![AclRule {
            action: Action::Drop,
            src: vec![Selector::Tag(tag("client"))],
            dst: vec![Selector::Tag(tag("server"))],
            proto: Proto::Tcp,
            ports: Some(vec![PortSpec::Single(22)]),
        }],
        &client.cert,
        &server.cert,
    );
    let (inst_a, inst_c, _) = setup(&root, &client, &server, acl).await;

    assert_tx_unchanged(&inst_a, tcp_packet(22)).await;
    assert_tx_increases(&inst_a, icmp_packet()).await;

    clear(vec![inst_a, inst_c]).await;
}

#[tokio::test]
#[serial]
async fn test_acl_default_drop_allows_after_whitelist_state_refresh() {
    let root = TrustDomainRoot::generate();
    let client = make_member(&root, "client-a");
    let server = make_member(&root, "server-c");
    let acl = policy(Action::Drop, Vec::new(), &client.cert, &server.cert);
    let (inst_a, inst_c, shared_pool) = setup(&root, &client, &server, acl).await;

    assert_tx_unchanged(&inst_a, icmp_packet()).await;

    let whitelist = policy(
        Action::Drop,
        vec![AclRule {
            action: Action::Accept,
            src: vec![Selector::Tag(tag("client"))],
            dst: vec![Selector::Tag(tag("server"))],
            proto: Proto::Icmp,
            ports: None,
        }],
        &client.cert,
        &server.cert,
    );
    shared_pool
        .write()
        .await
        .apply_network_state(state(&root, NETWORK_STATE_VERSION + 1, whitelist))
        .unwrap();

    assert_tx_increases(&inst_a, icmp_packet()).await;

    clear(vec![inst_a, inst_c]).await;
}

#[tokio::test]
#[serial]
async fn test_acl_proxy_subnet_route_moves_when_proxy_changes() {
    let root = TrustDomainRoot::generate();
    let proxy_cidr: pnet::ipnetwork::IpNetwork = "10.0.0.0/24".parse().unwrap();
    let client = make_member(&root, "client-a");
    let proxy_c = make_member_with_proxy(&root, "proxy-c", vec![proxy_cidr]);
    let proxy_d = make_member_with_proxy(&root, "proxy-d", vec![proxy_cidr]);

    let mut tags = BTreeMap::new();
    tags.insert(tag("client"), vec![device_fp(&client.cert)]);
    let acl = AclPolicy {
        tags,
        rules: vec![AclRule {
            action: Action::Accept,
            src: vec![Selector::Tag(tag("client"))],
            dst: vec![Selector::Subnet(cidr_selector("10.0.0.0/24"))],
            proto: Proto::Icmp,
            ports: None,
        }],
        default_action: Action::Drop,
        schema_version: ACL_SCHEMA_VERSION,
    };
    let (inst_a, inst_c, inst_d, _) =
        setup_proxy_topology(&root, &client, &proxy_c, &proxy_d, acl).await;
    let proxy: Ipv4Cidr = "10.0.0.0/24".parse().unwrap();
    let test_ip = proxy.first_address();

    inst_c
        .get_global_ctx()
        .config
        .add_proxy_cidr(proxy, None)
        .unwrap();
    wait_for_condition(
        || {
            let route = inst_a.get_peer_manager().get_route();
            let c_id = inst_c.get_peer_manager().my_peer_id();
            async move { route.get_peer_id_by_ipv4(&test_ip).await == Some(c_id) }
        },
        Duration::from_secs(10),
    )
    .await;
    assert_tx_increases_to_proxy_subnet(&inst_a, subnet_packet()).await;

    inst_d
        .get_global_ctx()
        .config
        .add_proxy_cidr(proxy, None)
        .unwrap();
    inst_c.get_global_ctx().config.remove_proxy_cidr(proxy);
    wait_for_condition(
        || {
            let route = inst_a.get_peer_manager().get_route();
            let d_id = inst_d.get_peer_manager().my_peer_id();
            async move { route.get_peer_id_by_ipv4(&test_ip).await == Some(d_id) }
        },
        Duration::from_secs(10),
    )
    .await;
    assert_tx_increases_to_proxy_subnet(&inst_a, subnet_packet()).await;

    clear(vec![inst_a, inst_c, inst_d]).await;
}
