use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use tokio::sync::RwLock;

use crate::common::config::NetworkIdentity;
use crate::common::global_ctx::tests::get_mock_global_ctx_with_network;
use crate::common::new_peer_id;
use crate::common::trust_context::TrustDomainContext;
use crate::connector::udp_hole_punch::tests::replace_stun_info_collector;
use crate::peers::create_packet_recv_chan;
use crate::peers::peer_conn::PeerConn;
use crate::peers::peer_conn::tests::set_secure_mode_cfg;
use crate::peers::peer_manager::{PeerManager, RouteAlgoType};
use crate::peers::peer_session::PeerSessionStore;
use crate::proto::common::NatType;
use crate::proto::peer_rpc::{PeerIdentityType, SecureAuthLevel};
use crate::tests::trust_pool_fixture::{
    trust_pool_with_cert, trust_pool_with_disabled_cert, trust_pool_with_expired_cert,
    trust_pool_with_revoked_cert,
};
use crate::trust::{
    Capabilities, DisabledCert, MemberCert, NetworkLocalId, NetworkStatePayload, RevokedCert,
    SignKey, TrustDomainPool, TrustDomainRoot, UnsignedMemberCert, UnsignedNetworkState,
};
use crate::tunnel::common::tests::wait_for_condition;
use crate::tunnel::filter::{PacketRecorderTunnelFilter, TunnelWithFilter};
use crate::tunnel::packet_def::PacketType;
use crate::tunnel::ring::create_ring_tunnel_pair;

const CERT_NOT_BEFORE: u64 = 1_715_000_000;
const CERT_EXPIRES_AT: u64 = 4_102_444_800;
const NETWORK_STATE_VERSION: u64 = 42;

async fn attach_trust_context(
    ctx: &crate::common::global_ctx::ArcGlobalCtx,
    trust_ctx: TrustDomainContext,
) {
    ctx.set_trust_context(Arc::new(trust_ctx)).await;
}

fn sample_member_cert_for_network(
    root: &TrustDomainRoot,
    sk_self: &SignKey,
    network_local_id: &str,
    device_label: &str,
) -> MemberCert {
    let device_pk =
        VerifyingKey::from_bytes(&sk_self.verify_key().0).expect("verify key bytes valid");
    UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str(network_local_id).unwrap(),
        device_pk,
        device_label: device_label.to_owned(),
        not_before: CERT_NOT_BEFORE,
        expires_at: CERT_EXPIRES_AT,
        capabilities: Capabilities {
            can_relay_data: true,
            can_relay_control: true,
            can_proxy_subnet: Vec::new(),
            can_be_exit_node: false,
        },
        network_state_version_ref: NETWORK_STATE_VERSION,
        hostname: None,
    }
    .sign(root)
}

fn sample_network_state(
    root: &TrustDomainRoot,
    cert: &MemberCert,
    revoked: Option<RevokedCert>,
    disabled: Option<DisabledCert>,
) -> crate::trust::SignedNetworkState {
    UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: cert.details.network_local_id.clone(),
        version: NETWORK_STATE_VERSION,
        payload: NetworkStatePayload {
            member_cert_index: Vec::new(),
            revoked_certs: revoked.into_iter().collect(),
            disabled_certs: disabled.into_iter().collect(),
            acl: Vec::new(),
            routes: Vec::new(),
            peer_hints: Vec::new(),
            ip_assignments: Vec::new(),
            capability_grants: Vec::new(),
            hostname_bindings: Vec::new(),
        },
    }
    .sign(root)
}

fn pool_with_entries(entries: &[(&TrustDomainRoot, &MemberCert)]) -> Arc<RwLock<TrustDomainPool>> {
    let mut pool = TrustDomainPool::new();
    for (root, cert) in entries {
        pool.add_root(root.public_key().into());
        pool.apply_network_state(sample_network_state(root, cert, None, None))
            .unwrap();
    }
    Arc::new(RwLock::new(pool))
}

async fn make_peer_conn_pair(
    client_network_name: &str,
    server_network_name: &str,
    client_trust_ctx: TrustDomainContext,
    server_trust_ctx: TrustDomainContext,
    trust_pool: Arc<RwLock<TrustDomainPool>>,
    secure_mode: bool,
) -> (PeerConn, PeerConn) {
    let (c, s) = create_ring_tunnel_pair();
    let c_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
        client_network_name.to_owned(),
    )));
    let s_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
        server_network_name.to_owned(),
    )));

    if secure_mode {
        set_secure_mode_cfg(&c_ctx, true);
        set_secure_mode_cfg(&s_ctx, true);
    }

    attach_trust_context(&c_ctx, client_trust_ctx).await;
    attach_trust_context(&s_ctx, server_trust_ctx).await;

    let ps = Arc::new(PeerSessionStore::new());
    let client = PeerConn::new(
        new_peer_id(),
        c_ctx,
        Box::new(c),
        ps.clone(),
        Some(trust_pool.clone()),
    );
    let server = PeerConn::new(new_peer_id(), s_ctx, Box::new(s), ps, Some(trust_pool));
    (client, server)
}

async fn handshake_peer_conns(
    mut client: PeerConn,
    mut server: PeerConn,
) -> (
    Result<(), crate::common::error::Error>,
    Result<(), crate::common::error::Error>,
    PeerConn,
    PeerConn,
) {
    let (c_ret, s_ret) = tokio::join!(
        client.do_handshake_as_client(),
        server.do_handshake_as_server()
    );
    (c_ret, s_ret, client, server)
}

fn make_trust_context(
    root: &TrustDomainRoot,
    cert: &MemberCert,
    sk_self: &SignKey,
) -> TrustDomainContext {
    TrustDomainContext::new(
        root.id(),
        cert.details.network_local_id.clone(),
        cert.clone(),
        sk_self.clone(),
    )
}

async fn create_peer_manager_with_trust(
    network_name: &str,
    trust_ctx: Option<TrustDomainContext>,
    trust_pool: Option<Arc<RwLock<TrustDomainPool>>>,
) -> Arc<PeerManager> {
    let (s, _r) = create_packet_recv_chan();
    let global_ctx =
        get_mock_global_ctx_with_network(Some(NetworkIdentity::new(network_name.to_owned())));
    let peer_mgr = Arc::new(PeerManager::new(
        RouteAlgoType::Ospf,
        global_ctx.clone(),
        s,
        trust_pool,
    ));
    replace_stun_info_collector(peer_mgr.clone(), NatType::Unknown);
    let mut flags = peer_mgr.get_global_ctx().get_flags();
    flags.disable_upnp = true;
    peer_mgr.get_global_ctx().set_flags(flags);
    if let Some(ctx) = trust_ctx {
        peer_mgr
            .get_global_ctx()
            .set_trust_context(Arc::new(ctx))
            .await;
    }
    peer_mgr.run().await.unwrap();
    peer_mgr
}

fn set_private_mode(peer_mgr: &PeerManager, enabled: bool) {
    let global_ctx = peer_mgr.get_global_ctx();
    let mut flags = global_ctx.get_flags();
    flags.private_mode = enabled;
    global_ctx.set_flags(flags);
}

async fn connect_client_and_server(
    client: Arc<PeerManager>,
    server: Arc<PeerManager>,
) -> (
    Result<(u32, uuid::Uuid), crate::common::error::Error>,
    Result<(), crate::common::error::Error>,
) {
    let (client_ring, server_ring) = create_ring_tunnel_pair();
    tokio::join!(
        {
            let client = client.clone();
            async move { client.add_client_tunnel(client_ring, false).await }
        },
        {
            let server = server.clone();
            async move { server.add_tunnel_as_server(server_ring, true).await }
        }
    )
}

async fn wait_for_local_peer(server: Arc<PeerManager>) {
    wait_for_condition(
        || {
            let server = server.clone();
            async move {
                !server
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

async fn wait_for_foreign_network(server: Arc<PeerManager>, network_name: &str) {
    let network_name = network_name.to_owned();
    wait_for_condition(
        || {
            let server = server.clone();
            let network_name = network_name.clone();
            async move {
                server
                    .get_foreign_network_manager()
                    .list_foreign_networks()
                    .await
                    .foreign_networks
                    .contains_key(&network_name)
            }
        },
        Duration::from_secs(5),
    )
    .await;
}

#[tokio::test]
async fn test_noise_two_peers_same_trust_domain_handshake_succeeds() {
    let root = TrustDomainRoot::generate();
    let client_sk = SignKey::generate();
    let server_sk = SignKey::generate();
    let client_cert = sample_member_cert_for_network(&root, &client_sk, "office-net", "client-a");
    let server_cert = sample_member_cert_for_network(&root, &server_sk, "office-net", "server-b");
    let pool = trust_pool_with_cert(&root, &client_cert);

    let (client, server) = make_peer_conn_pair(
        "net-a",
        "net-a",
        make_trust_context(&root, &client_cert, &client_sk),
        make_trust_context(&root, &server_cert, &server_sk),
        pool,
        true,
    )
    .await;

    let (c_ret, s_ret, client, server) = handshake_peer_conns(client, server).await;
    assert!(c_ret.is_ok());
    assert!(s_ret.is_ok());
    assert_eq!(
        server.get_conn_info().secure_auth_level,
        SecureAuthLevel::TrustDomainVerified as i32
    );
    assert_eq!(
        server.get_conn_info().peer_identity_type,
        PeerIdentityType::Admin as i32
    );
    assert_eq!(
        client.get_conn_info().secure_auth_level,
        SecureAuthLevel::TrustDomainVerified as i32
    );
}

#[tokio::test]
async fn test_noise_member_cert_signed_by_wrong_root_rejected() {
    let client_root = TrustDomainRoot::generate();
    let server_root = TrustDomainRoot::generate();
    let client_sk = SignKey::generate();
    let server_sk = SignKey::generate();
    let client_cert =
        sample_member_cert_for_network(&client_root, &client_sk, "office-net", "client-a");
    let server_cert =
        sample_member_cert_for_network(&server_root, &server_sk, "office-net", "server-b");
    let pool = trust_pool_with_cert(&server_root, &server_cert);

    let (client, server) = make_peer_conn_pair(
        "net-a",
        "net-a",
        make_trust_context(&client_root, &client_cert, &client_sk),
        make_trust_context(&server_root, &server_cert, &server_sk),
        pool,
        true,
    )
    .await;

    let (_c_ret, s_ret, _client, _server) = handshake_peer_conns(client, server).await;
    assert!(s_ret.is_err());
}

#[tokio::test]
async fn test_noise_revoked_member_cert_rejected() {
    let root = TrustDomainRoot::generate();
    let client_sk = SignKey::generate();
    let server_sk = SignKey::generate();
    let client_cert = sample_member_cert_for_network(&root, &client_sk, "office-net", "client-a");
    let server_cert = sample_member_cert_for_network(&root, &server_sk, "office-net", "server-b");
    let pool = trust_pool_with_revoked_cert(&root, &client_cert);

    let (client, server) = make_peer_conn_pair(
        "net-a",
        "net-a",
        make_trust_context(&root, &client_cert, &client_sk),
        make_trust_context(&root, &server_cert, &server_sk),
        pool,
        true,
    )
    .await;

    let (_c_ret, s_ret, _client, _server) = handshake_peer_conns(client, server).await;
    assert!(s_ret.is_err());
}

#[tokio::test]
async fn test_noise_disabled_member_cert_rejected_until_expected() {
    let root = TrustDomainRoot::generate();
    let client_sk = SignKey::generate();
    let server_sk = SignKey::generate();
    let client_cert = sample_member_cert_for_network(&root, &client_sk, "office-net", "client-a");
    let server_cert = sample_member_cert_for_network(&root, &server_sk, "office-net", "server-b");
    let pool = trust_pool_with_disabled_cert(&root, &client_cert);

    let (client, server) = make_peer_conn_pair(
        "net-a",
        "net-a",
        make_trust_context(&root, &client_cert, &client_sk),
        make_trust_context(&root, &server_cert, &server_sk),
        pool,
        true,
    )
    .await;

    let (_c_ret, s_ret, _client, _server) = handshake_peer_conns(client, server).await;
    assert!(s_ret.is_err());
}

#[tokio::test]
async fn test_noise_expired_member_cert_rejected() {
    let root = TrustDomainRoot::generate();
    let client_sk = SignKey::generate();
    let server_sk = SignKey::generate();
    let mut client_cert =
        sample_member_cert_for_network(&root, &client_sk, "office-net", "client-a");
    client_cert.details.expires_at = 1;
    let server_cert = sample_member_cert_for_network(&root, &server_sk, "office-net", "server-b");
    let pool = trust_pool_with_expired_cert(&root, &client_cert);

    let (client, server) = make_peer_conn_pair(
        "net-a",
        "net-a",
        make_trust_context(&root, &client_cert, &client_sk),
        make_trust_context(&root, &server_cert, &server_sk),
        pool,
        true,
    )
    .await;

    let (_c_ret, s_ret, _client, _server) = handshake_peer_conns(client, server).await;
    assert!(s_ret.is_err());
}

#[tokio::test]
async fn test_plain_path_member_cert_exchange() {
    let root = TrustDomainRoot::generate();
    let client_sk = SignKey::generate();
    let server_sk = SignKey::generate();
    let client_cert = sample_member_cert_for_network(&root, &client_sk, "office-net", "client-a");
    let server_cert = sample_member_cert_for_network(&root, &server_sk, "office-net", "server-b");
    let pool = trust_pool_with_cert(&root, &client_cert);

    let (client, server) = make_peer_conn_pair(
        "net-a",
        "net-a",
        make_trust_context(&root, &client_cert, &client_sk),
        make_trust_context(&root, &server_cert, &server_sk),
        pool,
        false,
    )
    .await;

    let (c_ret, s_ret, _client, _server) = handshake_peer_conns(client, server).await;
    assert!(c_ret.is_ok());
    assert!(s_ret.is_ok());
}

#[tokio::test]
async fn test_plain_path_signature_invalid_rejected() {
    let root = TrustDomainRoot::generate();
    let client_sk = SignKey::generate();
    let server_sk = SignKey::generate();
    let wrong_sk = SignKey::generate();
    let client_cert = sample_member_cert_for_network(&root, &client_sk, "office-net", "client-a");
    let server_cert = sample_member_cert_for_network(&root, &server_sk, "office-net", "server-b");
    let pool = trust_pool_with_cert(&root, &client_cert);

    let (client, server) = make_peer_conn_pair(
        "net-a",
        "net-a",
        make_trust_context(&root, &client_cert, &wrong_sk),
        make_trust_context(&root, &server_cert, &server_sk),
        pool,
        false,
    )
    .await;

    let (_c_ret, s_ret, _client, _server) = handshake_peer_conns(client, server).await;
    assert!(s_ret.is_err());
}

#[tokio::test]
async fn test_plain_path_replay_old_nonce_rejected() {
    let root = TrustDomainRoot::generate();
    let client_sk = SignKey::generate();
    let server_sk = SignKey::generate();
    let client_cert = sample_member_cert_for_network(&root, &client_sk, "office-net", "client-a");
    let server_cert = sample_member_cert_for_network(&root, &server_sk, "office-net", "server-b");
    let pool = trust_pool_with_cert(&root, &client_cert);

    let (c, s) = create_ring_tunnel_pair();
    let client_recorder = Arc::new(PacketRecorderTunnelFilter::new());
    let c = TunnelWithFilter::new(c, client_recorder.clone());

    let c_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new("net-a".to_owned())));
    let s_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new("net-a".to_owned())));
    attach_trust_context(&c_ctx, make_trust_context(&root, &client_cert, &client_sk)).await;
    attach_trust_context(&s_ctx, make_trust_context(&root, &server_cert, &server_sk)).await;

    let ps = Arc::new(PeerSessionStore::new());
    let mut client = PeerConn::new(
        new_peer_id(),
        c_ctx,
        Box::new(c),
        ps.clone(),
        Some(pool.clone()),
    );
    let mut server = PeerConn::new(new_peer_id(), s_ctx, Box::new(s), ps, Some(pool));

    let (c_ret, s_ret) = tokio::join!(
        client.do_handshake_as_client(),
        server.do_handshake_as_server()
    );
    assert!(c_ret.is_ok());
    assert!(s_ret.is_ok());

    let replayed_packet = client_recorder
        .sent
        .lock()
        .unwrap()
        .iter()
        .find(|pkt| {
            pkt.peer_manager_header()
                .is_some_and(|hdr| hdr.packet_type == PacketType::HandShake as u8)
        })
        .cloned()
        .expect("captured plain handshake packet");

    client.send_msg(replayed_packet).await.unwrap();
    let err = server.do_handshake_as_server().await.unwrap_err();
    assert!(format!("{err:?}").contains("replayed applicant nonce"));
}

#[tokio::test]
async fn test_plain_path_cross_trust_domain_rejected_by_caller() {
    let client_root = TrustDomainRoot::generate();
    let server_root = TrustDomainRoot::generate();
    let client_sk = SignKey::generate();
    let server_sk = SignKey::generate();
    let client_cert =
        sample_member_cert_for_network(&client_root, &client_sk, "tenant-a", "client-a");
    let server_cert =
        sample_member_cert_for_network(&server_root, &server_sk, "public", "server-b");
    let pool = pool_with_entries(&[(&client_root, &client_cert), (&server_root, &server_cert)]);

    let client = create_peer_manager_with_trust(
        "tenant-a",
        Some(make_trust_context(&client_root, &client_cert, &client_sk)),
        Some(pool.clone()),
    )
    .await;
    let server = create_peer_manager_with_trust(
        "public",
        Some(make_trust_context(&server_root, &server_cert, &server_sk)),
        Some(pool),
    )
    .await;
    set_private_mode(&server, true);

    let (client_ret, server_ret) = connect_client_and_server(client, server).await;
    let _ = client_ret;
    assert!(server_ret.is_err());
}

#[tokio::test]
async fn test_no_trust_context_rejects_all_inbound() {
    let root = TrustDomainRoot::generate();
    let client_sk = SignKey::generate();
    let client_cert = sample_member_cert_for_network(&root, &client_sk, "office-net", "client-a");
    let pool = trust_pool_with_cert(&root, &client_cert);

    let client = create_peer_manager_with_trust(
        "net-a",
        Some(make_trust_context(&root, &client_cert, &client_sk)),
        Some(pool),
    )
    .await;
    let server = create_peer_manager_with_trust("net-a", None, None).await;

    let (client_ret, server_ret) = connect_client_and_server(client, server).await;
    let _ = client_ret;
    assert!(server_ret.is_err());
}

#[tokio::test]
async fn test_same_root_same_network_routes_to_local() {
    let root = TrustDomainRoot::generate();
    let client_sk = SignKey::generate();
    let server_sk = SignKey::generate();
    let client_cert = sample_member_cert_for_network(&root, &client_sk, "office-net", "client-a");
    let server_cert = sample_member_cert_for_network(&root, &server_sk, "office-net", "server-b");
    let pool = trust_pool_with_cert(&root, &client_cert);

    let client = create_peer_manager_with_trust(
        "net-a",
        Some(make_trust_context(&root, &client_cert, &client_sk)),
        Some(pool.clone()),
    )
    .await;
    let server = create_peer_manager_with_trust(
        "net-a",
        Some(make_trust_context(&root, &server_cert, &server_sk)),
        Some(pool),
    )
    .await;

    let (client_ret, server_ret) = connect_client_and_server(client, server.clone()).await;
    let _ = client_ret.unwrap();
    server_ret.unwrap();

    wait_for_local_peer(server.clone()).await;
    assert!(
        server
            .get_foreign_network_manager()
            .list_foreign_networks()
            .await
            .foreign_networks
            .is_empty()
    );
}

#[tokio::test]
async fn test_same_root_different_network_routes_to_foreign() {
    let root = TrustDomainRoot::generate();
    let client_sk = SignKey::generate();
    let server_sk = SignKey::generate();
    let client_cert = sample_member_cert_for_network(&root, &client_sk, "tenant-a", "client-a");
    let server_cert = sample_member_cert_for_network(&root, &server_sk, "public", "server-b");
    let pool = pool_with_entries(&[(&root, &client_cert), (&root, &server_cert)]);

    let client = create_peer_manager_with_trust(
        "tenant-a",
        Some(make_trust_context(&root, &client_cert, &client_sk)),
        Some(pool.clone()),
    )
    .await;
    let server = create_peer_manager_with_trust(
        "public",
        Some(make_trust_context(&root, &server_cert, &server_sk)),
        Some(pool),
    )
    .await;

    let (_client_ret, server_ret) = connect_client_and_server(client, server.clone()).await;
    server_ret.unwrap();

    wait_for_foreign_network(server.clone(), "tenant-a").await;
    assert!(
        server
            .get_peer_map()
            .list_peers_with_conn()
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn test_different_root_rejected_in_private_mode() {
    let client_root = TrustDomainRoot::generate();
    let server_root = TrustDomainRoot::generate();
    let client_sk = SignKey::generate();
    let server_sk = SignKey::generate();
    let client_cert =
        sample_member_cert_for_network(&client_root, &client_sk, "tenant-a", "client-a");
    let server_cert =
        sample_member_cert_for_network(&server_root, &server_sk, "public", "server-b");
    let pool = pool_with_entries(&[(&client_root, &client_cert), (&server_root, &server_cert)]);

    let client = create_peer_manager_with_trust(
        "tenant-a",
        Some(make_trust_context(&client_root, &client_cert, &client_sk)),
        Some(pool.clone()),
    )
    .await;
    let server = create_peer_manager_with_trust(
        "public",
        Some(make_trust_context(&server_root, &server_cert, &server_sk)),
        Some(pool),
    )
    .await;
    set_private_mode(&server, true);

    let (_client_ret, server_ret) = connect_client_and_server(client, server).await;
    assert!(server_ret.is_err());
}

#[tokio::test]
async fn test_different_root_routes_to_foreign_in_open_mode() {
    let client_root = TrustDomainRoot::generate();
    let server_root = TrustDomainRoot::generate();
    let client_sk = SignKey::generate();
    let server_sk = SignKey::generate();
    let client_cert =
        sample_member_cert_for_network(&client_root, &client_sk, "tenant-a", "client-a");
    let server_cert =
        sample_member_cert_for_network(&server_root, &server_sk, "public", "server-b");
    let pool = pool_with_entries(&[(&client_root, &client_cert), (&server_root, &server_cert)]);

    let client = create_peer_manager_with_trust(
        "tenant-a",
        Some(make_trust_context(&client_root, &client_cert, &client_sk)),
        Some(pool.clone()),
    )
    .await;
    let server = create_peer_manager_with_trust(
        "public",
        Some(make_trust_context(&server_root, &server_cert, &server_sk)),
        Some(pool),
    )
    .await;
    set_private_mode(&server, false);

    let (_client_ret, server_ret) = connect_client_and_server(client, server.clone()).await;
    server_ret.unwrap();

    wait_for_foreign_network(server.clone(), "tenant-a").await;
    assert!(
        server
            .get_peer_map()
            .list_peers_with_conn()
            .await
            .is_empty()
    );
}
