use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, prelude::BASE64_STANDARD};
use easytier::common::config::{
    ConfigLoader, NetworkIdentity, PeerConfig, RelayServingEntryConfig, TomlConfigLoader,
    TrustDomainConfig,
};
use easytier::common::trust_context::TrustDomainContext;
use easytier::instance::instance::Instance;
use easytier::proto::common::SecureModeConfig;
use easytier::trust::{
    ActiveRelay, BorrowedRelayProof, Capabilities, MemberCert, NetworkBootstrap, NetworkLocalId,
    NetworkStatePayload, RelayCapabilities, SignKey, SignedNetworkState, SignedTrustDomainMeta,
    TrustDomainPool, TrustDomainRoot, UnsignedMemberCert, UnsignedNetworkState,
    UnsignedTrustDomainMeta,
};
use easytier::tunnel::{
    TunnelConnector,
    common::tests::wait_for_condition,
    ring::{RingTunnelConnector, create_ring_tunnel_pair},
};
use rand::rngs::OsRng;
use serial_test::serial;
use tokio::sync::RwLock;
use url::Url;
use x25519_dalek::{PublicKey, StaticSecret};

const NETWORK_LOCAL_ID: &str = "office-net";
const NETWORK_STATE_VERSION: u64 = 1;

#[derive(Clone)]
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

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{b:02x}").unwrap();
    }
    out
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

fn base_config(inst_name: &str, network_name: &str) -> TomlConfigLoader {
    let cfg = TomlConfigLoader::default();
    cfg.set_inst_name(inst_name.to_owned());
    cfg.set_network_identity(NetworkIdentity::new(network_name.to_owned()));
    cfg.set_secure_mode(Some(generate_secure_mode_config()));

    let mut flags = cfg.get_flags();
    flags.no_tun = true;
    cfg.set_flags(flags);
    cfg
}

fn make_member(root: &TrustDomainRoot, device_label: &str, expires_at: u64) -> MemberFixture {
    let sk_self = SignKey::generate();
    let verify_key = ed25519_dalek::VerifyingKey::from_bytes(&sk_self.verify_key().0).unwrap();
    let now = now_unix();
    let cert = UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str(NETWORK_LOCAL_ID).unwrap(),
        device_pk: verify_key,
        device_label: device_label.to_owned(),
        not_before: now.saturating_sub(60),
        expires_at,
        capabilities: Capabilities {
            can_relay_data: true,
            can_relay_control: true,
            can_proxy_subnet: Vec::new(),
        },
        network_state_version_ref: NETWORK_STATE_VERSION,
        hostname: None,
    }
    .sign(root);

    MemberFixture { sk_self, cert }
}

fn make_network_state(root: &TrustDomainRoot) -> SignedNetworkState {
    UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str(NETWORK_LOCAL_ID).unwrap(),
        version: NETWORK_STATE_VERSION,
        payload: NetworkStatePayload {
            member_cert_index: Vec::new(),
            revoked_certs: Vec::new(),
            disabled_certs: Vec::new(),
            acl: Vec::new(),
            routes: Vec::new(),
        },
    }
    .sign(root)
}

fn make_trust_domain_meta(
    root: &TrustDomainRoot,
    can_relay_data: bool,
    expires_at: u64,
) -> SignedTrustDomainMeta {
    let relay_sign = SignKey::generate();
    let relay_pk = ed25519_dalek::VerifyingKey::from_bytes(&relay_sign.verify_key().0).unwrap();

    UnsignedTrustDomainMeta {
        trust_domain_id: root.id(),
        version: 1,
        active_relays: vec![ActiveRelay {
            device_pk: relay_pk,
            device_label: "relay-r".to_owned(),
            capabilities: RelayCapabilities {
                can_relay_data,
                can_assist_holepunch: true,
            },
            expires_at,
        }],
        outbound_grants: Vec::new(),
    }
    .sign(root)
}

fn make_network_bootstrap(
    root: &TrustDomainRoot,
    network_name: &str,
    relay_url: Url,
) -> NetworkBootstrap {
    NetworkBootstrap {
        trust_domain_id: root.id(),
        pk_root: root.public_key(),
        network_local_id: NetworkLocalId::try_from_str(NETWORK_LOCAL_ID).unwrap(),
        bootstrap_seeds: vec![relay_url],
        trust_domain_label: Some("foreign-b".to_owned()),
        network_name: Some(network_name.to_owned()),
        description: Some("borrowed-relay target bootstrap".to_owned()),
    }
}

fn client_pool(
    local_root: &TrustDomainRoot,
    local_state: SignedNetworkState,
    foreign_root: &TrustDomainRoot,
    foreign_meta: SignedTrustDomainMeta,
    foreign_bootstrap: NetworkBootstrap,
) -> Arc<RwLock<TrustDomainPool>> {
    let mut pool = TrustDomainPool::new();
    pool.add_root(local_root.public_key().into());
    pool.apply_network_state(local_state).unwrap();
    pool.add_root(foreign_root.public_key().into());
    pool.apply_trust_domain_meta(foreign_meta).unwrap();
    pool.apply_network_bootstrap(&foreign_root.id(), foreign_bootstrap)
        .unwrap();
    Arc::new(RwLock::new(pool))
}

fn relay_pool(
    relay_root: &TrustDomainRoot,
    relay_state: SignedNetworkState,
    foreign_root: &TrustDomainRoot,
    foreign_state: SignedNetworkState,
) -> Arc<RwLock<TrustDomainPool>> {
    let mut pool = TrustDomainPool::new();
    pool.add_root(relay_root.public_key().into());
    pool.apply_network_state(relay_state).unwrap();
    pool.add_root(foreign_root.public_key().into());
    pool.apply_network_state(foreign_state).unwrap();
    Arc::new(RwLock::new(pool))
}

fn local_pool(root: &TrustDomainRoot, state: SignedNetworkState) -> Arc<RwLock<TrustDomainPool>> {
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    pool.apply_network_state(state).unwrap();
    Arc::new(RwLock::new(pool))
}

fn relay_config(network_name: &str, foreign_root: &TrustDomainRoot) -> TomlConfigLoader {
    let cfg = base_config("relay-r", network_name);
    cfg.set_trust_domain(Some(TrustDomainConfig {
        domain_dir: PathBuf::new(),
        network_local_id: NETWORK_LOCAL_ID.to_owned(),
        sk_self_password_env: "IGNORED".to_owned(),
        relay_serving: vec![RelayServingEntryConfig {
            foreign_root_pk_hex: encode_hex(foreign_root.public_key().as_bytes()),
            foreign_trust_domain_meta_pem: None,
            foreign_network_state_pem: None,
            foreign_bootstrap_cbor: None,
            can_relay_data: true,
            can_assist_holepunch: true,
            expires_at: now_unix() + 3600,
        }],
    }));
    cfg
}

fn client_config(
    network_name: &str,
    dead_uri: Url,
    target_bootstrap_path: &Path,
) -> TomlConfigLoader {
    let cfg = base_config("client-x", network_name);
    cfg.set_peers(vec![PeerConfig {
        uri: dead_uri,
        peer_public_key: None,
        target_bootstrap_path: Some(target_bootstrap_path.to_path_buf()),
    }]);
    cfg
}

async fn attach_trust_context(inst: &Instance, root: &TrustDomainRoot, member: &MemberFixture) {
    let ctx = TrustDomainContext::new(
        root.id(),
        member.cert.details.network_local_id.clone(),
        member.cert.clone(),
        member.sk_self.clone(),
    );
    inst.get_global_ctx().set_trust_context(Arc::new(ctx)).await;
}

async fn wait_for_ring_listener(inst: &Instance) -> Url {
    let ctx = inst.get_global_ctx();
    wait_for_condition(
        || {
            let ctx = ctx.clone();
            async move {
                ctx.get_running_listeners()
                    .into_iter()
                    .any(|url| url.scheme() == "ring")
            }
        },
        Duration::from_secs(5),
    )
    .await;

    ctx.get_running_listeners()
        .into_iter()
        .find(|url| url.scheme() == "ring")
        .unwrap()
}

async fn connect_target_to_relay(target: &Instance, relay: &Instance) {
    let (relay_tunnel, target_tunnel) = create_ring_tunnel_pair();
    let target_pm = target.get_peer_manager();
    let relay_pm = relay.get_peer_manager();
    let (target_ret, relay_ret) = tokio::join!(
        target_pm.add_client_tunnel(target_tunnel, true),
        relay_pm.add_tunnel_as_server(relay_tunnel, true),
    );
    target_ret.unwrap();
    relay_ret.unwrap();

    wait_for_condition(
        || {
            let target_pm = target_pm.clone();
            let relay_pm = relay_pm.clone();
            async move {
                !target_pm
                    .get_peer_map()
                    .list_peers_with_conn()
                    .await
                    .is_empty()
                    && !relay_pm
                        .get_peer_map()
                        .list_peers_with_conn()
                        .await
                        .is_empty()
            }
        },
        Duration::from_secs(5),
    )
    .await;
}

async fn wait_for_borrowed_connection(
    client: &Instance,
    relay: &Instance,
    foreign_network_name: &str,
) {
    let client_pm = client.get_peer_manager();
    let relay_pm = relay.get_peer_manager();
    let deadline = Instant::now() + Duration::from_secs(10);

    loop {
        let client_foreign = client_pm
            .get_foreign_network_client()
            .get_peer_map()
            .list_peers_with_conn()
            .await;
        let relay_foreigns = relay_pm
            .get_foreign_network_manager()
            .list_foreign_networks()
            .await;
        let relay_has_entry = relay_foreigns
            .foreign_networks
            .get(foreign_network_name)
            .is_some_and(|entry| !entry.peers.is_empty());

        if !client_foreign.is_empty() && relay_has_entry {
            return;
        }
        if Instant::now() >= deadline {
            let relay_keys = relay_foreigns
                .foreign_networks
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            panic!(
                "timeout waiting borrowed connection: client_foreign={client_foreign:?}, relay_foreign_networks={relay_keys:?}"
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn clear_instances(instances: &mut [Instance]) {
    for inst in instances {
        inst.clear_resources().await;
    }
}

#[tokio::test]
#[serial]
async fn test_borrowed_relay_fallback_connects_to_relay_seed() {
    easytier::set_global_var!(MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS, 1);

    let now = now_unix();
    let bootstrap_dir = tempfile::tempdir().unwrap();

    let root_a = TrustDomainRoot::generate();
    let client_member = make_member(&root_a, "client-x", now + 3600);
    let state_a = make_network_state(&root_a);

    let root_b = TrustDomainRoot::generate();
    let relay_member = make_member(&root_b, "relay-r", now + 3600);
    let target_member = make_member(&root_b, "target-y", now + 3600);
    let state_b = make_network_state(&root_b);

    let relay_cfg = relay_config("net-b", &root_a);
    let relay_pool = relay_pool(&root_b, state_b.clone(), &root_a, state_a.clone());
    let mut relay = Instance::new_with_trust_pool(relay_cfg, Some(relay_pool));
    attach_trust_context(&relay, &root_b, &relay_member).await;
    relay.run().await.unwrap();
    let relay_ring_url = wait_for_ring_listener(&relay).await;

    let target_cfg = base_config("target-y", "net-b");
    let target_pool = local_pool(&root_b, state_b.clone());
    let mut target = Instance::new_with_trust_pool(target_cfg, Some(target_pool));
    attach_trust_context(&target, &root_b, &target_member).await;
    target.run().await.unwrap();
    connect_target_to_relay(&target, &relay).await;

    let bootstrap = make_network_bootstrap(&root_b, "net-b", relay_ring_url);
    let bootstrap_path = bootstrap_dir.path().join("target-b-bootstrap.pem");
    std::fs::write(&bootstrap_path, bootstrap.to_pem()).unwrap();

    let client_cfg = client_config(
        "net-a",
        "tcp://127.0.0.1:1".parse().unwrap(),
        &bootstrap_path,
    );
    let client_pool = client_pool(
        &root_a,
        state_a,
        &root_b,
        make_trust_domain_meta(&root_b, true, now + 3600),
        bootstrap,
    );
    let mut client = Instance::new_with_trust_pool(client_cfg, Some(client_pool));
    attach_trust_context(&client, &root_a, &client_member).await;
    client.run().await.unwrap();

    wait_for_borrowed_connection(&client, &relay, "net-a").await;

    clear_instances(&mut [client, relay, target]).await;
}

#[tokio::test]
#[serial]
async fn test_borrowed_relay_without_relay_seed_does_not_connect() {
    easytier::set_global_var!(MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS, 1);

    let now = now_unix();
    let bootstrap_dir = tempfile::tempdir().unwrap();

    let root_a = TrustDomainRoot::generate();
    let client_member = make_member(&root_a, "client-x", now + 3600);
    let state_a = make_network_state(&root_a);

    let root_b = TrustDomainRoot::generate();
    let relay_member = make_member(&root_b, "relay-r", now + 3600);
    let target_member = make_member(&root_b, "target-y", now + 3600);
    let state_b = make_network_state(&root_b);

    let relay_cfg = relay_config("net-b", &root_a);
    let relay_pool = relay_pool(&root_b, state_b.clone(), &root_a, state_a.clone());
    let mut relay = Instance::new_with_trust_pool(relay_cfg, Some(relay_pool));
    attach_trust_context(&relay, &root_b, &relay_member).await;
    relay.run().await.unwrap();

    let target_cfg = base_config("target-y", "net-b");
    let target_pool = local_pool(&root_b, state_b);
    let mut target = Instance::new_with_trust_pool(target_cfg, Some(target_pool));
    attach_trust_context(&target, &root_b, &target_member).await;
    target.run().await.unwrap();
    let target_ring_url = wait_for_ring_listener(&target).await;
    connect_target_to_relay(&target, &relay).await;

    let bootstrap = make_network_bootstrap(&root_b, "net-b", target_ring_url);
    let bootstrap_path = bootstrap_dir.path().join("target-b-bootstrap.pem");
    std::fs::write(&bootstrap_path, bootstrap.to_pem()).unwrap();

    let client_cfg = client_config(
        "net-a",
        "tcp://127.0.0.1:1".parse().unwrap(),
        &bootstrap_path,
    );
    let client_pool = client_pool(
        &root_a,
        state_a,
        &root_b,
        make_trust_domain_meta(&root_b, true, now + 3600),
        bootstrap,
    );
    let mut client = Instance::new_with_trust_pool(client_cfg, Some(client_pool));
    attach_trust_context(&client, &root_a, &client_member).await;
    client.run().await.unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        client
            .get_peer_manager()
            .get_foreign_network_client()
            .get_peer_map()
            .list_peers_with_conn()
            .await
            .is_empty()
    );
    assert!(
        !relay
            .get_peer_manager()
            .get_foreign_network_manager()
            .list_foreign_networks()
            .await
            .foreign_networks
            .contains_key("net-a")
    );

    clear_instances(&mut [client, relay, target]).await;
}

#[tokio::test]
#[serial]
async fn test_borrowed_relay_stale_proof_is_rejected() {
    let now = now_unix();

    let root_a = TrustDomainRoot::generate();
    let client_member = make_member(&root_a, "client-x", now + 3600);
    let state_a = make_network_state(&root_a);

    let root_b = TrustDomainRoot::generate();
    let relay_member = make_member(&root_b, "relay-r", now + 3600);
    let state_b = make_network_state(&root_b);

    let relay_cfg = relay_config("net-b", &root_a);
    let relay_pool = relay_pool(&root_b, state_b, &root_a, state_a.clone());
    let mut relay = Instance::new_with_trust_pool(relay_cfg, Some(relay_pool));
    attach_trust_context(&relay, &root_b, &relay_member).await;
    relay.run().await.unwrap();
    let relay_ring_url = wait_for_ring_listener(&relay).await;

    let client_cfg = base_config("client-x", "net-a");
    let client_pool = local_pool(&root_a, state_a);
    let mut client = Instance::new_with_trust_pool(client_cfg, Some(client_pool));
    attach_trust_context(&client, &root_a, &client_member).await;
    client.run().await.unwrap();

    let stale_proof = BorrowedRelayProof {
        trust_domain_id: root_a.id(),
        member_cert: client_member.cert.clone(),
        timestamp: now.saturating_sub(301),
    };
    let _ = client
        .get_peer_manager()
        .try_direct_connect_with_borrowed_proof(
            Box::new(RingTunnelConnector::new(relay_ring_url)) as Box<dyn TunnelConnector>,
            stale_proof,
        )
        .await;

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        client
            .get_peer_manager()
            .get_foreign_network_client()
            .get_peer_map()
            .list_peers_with_conn()
            .await
            .is_empty()
    );
    assert!(
        !relay
            .get_peer_manager()
            .get_foreign_network_manager()
            .list_foreign_networks()
            .await
            .foreign_networks
            .contains_key("net-a")
    );

    clear_instances(&mut [client, relay]).await;
}
