use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, prelude::BASE64_STANDARD};
use easytier::common::config::{ConfigLoader, NetworkIdentity, TomlConfigLoader};
use easytier::common::error::Error;
use easytier::common::global_ctx::{GlobalCtx, NetworkIdentity as GlobalNetworkIdentity};
use easytier::common::trust_context::TrustDomainContext;
use easytier::peers::create_packet_recv_chan;
use easytier::peers::foreign_network_manager::{
    ForeignNetworkManager, GlobalForeignNetworkAccessor,
};
use easytier::peers::peer_conn::PeerConn;
use easytier::peers::peer_session::PeerSessionStore;
use easytier::proto::common::SecureModeConfig;
use easytier::proto::peer_rpc::{PeerConnNoiseMsg1Pb, PeerConnNoiseMsg2Pb, PeerConnNoiseMsg3Pb};
use easytier::trust::{
    BorrowedRelayProof, Capabilities, MemberCert, NetworkLocalId, NetworkStatePayload,
    RelayCapabilities, RelayGrantEntry, RelayGrantTable, SignKey, TrustDomainPool, TrustDomainRoot,
    UnsignedMemberCert, UnsignedNetworkState, from_cbor, to_canonical_cbor,
};
use easytier::tunnel::packet_def::{PacketType, ZCPacket};
use easytier::tunnel::ring::create_ring_tunnel_pair;
use ed25519_dalek::VerifyingKey;
use futures::{SinkExt, StreamExt};
use prost::Message;
use rand::rngs::OsRng;
use snow::params::NoiseParams;
use tokio::sync::RwLock;

const NETWORK_LOCAL_ID: &str = "office-net";
const NETWORK_NAME: &str = "N1";

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

fn make_secure_mode_config(private: &x25519_dalek::StaticSecret) -> SecureModeConfig {
    let public = x25519_dalek::PublicKey::from(private);
    SecureModeConfig {
        enabled: true,
        local_private_key: Some(BASE64_STANDARD.encode(private.as_bytes())),
        local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
    }
}

fn sample_member_cert(root: &TrustDomainRoot, sk_self: &SignKey, device_label: &str) -> MemberCert {
    let device_pk =
        VerifyingKey::from_bytes(&sk_self.verify_key().0).expect("verify key bytes valid");
    let now = now_unix();
    UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str(NETWORK_LOCAL_ID).unwrap(),
        device_pk,
        device_label: device_label.to_owned(),
        not_before: now.saturating_sub(60),
        expires_at: now + 3600,
        capabilities: Capabilities {
            can_relay_data: true,
            can_relay_control: true,
            can_proxy_subnet: Vec::new(),
        },
        network_state_version_ref: 1,
        hostname: None,
    }
    .sign(root)
}

fn sample_network_state(
    root: &TrustDomainRoot,
    cert: &MemberCert,
) -> easytier::trust::SignedNetworkState {
    UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: cert.details.network_local_id.clone(),
        version: 1,
        payload: NetworkStatePayload {
            member_cert_index: Vec::new(),
            revoked_certs: Vec::new(),
            disabled_certs: Vec::new(),
            acl: Vec::new(),
            routes: Vec::new(),
            peer_hints: Vec::new(),
        },
    }
    .sign(root)
}

fn trust_pool_with_entries(
    entries: &[(&TrustDomainRoot, &MemberCert)],
) -> Arc<RwLock<TrustDomainPool>> {
    let mut pool = TrustDomainPool::new();
    for (root, cert) in entries {
        pool.add_root(root.public_key().into());
        pool.apply_network_state(sample_network_state(root, cert))
            .unwrap();
    }
    Arc::new(RwLock::new(pool))
}

fn make_global_ctx(network_name: &str, private: &x25519_dalek::StaticSecret) -> Arc<GlobalCtx> {
    let config = TomlConfigLoader::default();
    config.set_network_identity(NetworkIdentity::new(network_name.to_owned()));
    config.set_secure_mode(Some(make_secure_mode_config(private)));
    Arc::new(GlobalCtx::new(config))
}

async fn attach_trust_context(
    ctx: &Arc<GlobalCtx>,
    root: &TrustDomainRoot,
    cert: &MemberCert,
    sk_self: &SignKey,
) {
    ctx.set_trust_context(Arc::new(TrustDomainContext::new(
        root.id(),
        cert.details.network_local_id.clone(),
        cert.clone(),
        sk_self.clone(),
    )))
    .await;
}

async fn run_noise_client_with_proof(
    client_tunnel: Box<dyn easytier::tunnel::Tunnel>,
    client_peer_id: u32,
    server_peer_id: u32,
    network_name: &str,
    client_private: &x25519_dalek::StaticSecret,
    encrypt_algo: &str,
    member_cert: &MemberCert,
    proof: Option<&BorrowedRelayProof>,
) {
    let (mut stream, mut sink) = client_tunnel.split();
    let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
    let prologue = b"easytier-peerconn-noise".to_vec();
    let mut hs = snow::Builder::new(params)
        .prologue(&prologue)
        .unwrap()
        .local_private_key(client_private.as_bytes())
        .unwrap()
        .build_initiator()
        .unwrap();

    let a_conn_id = uuid::Uuid::new_v4();
    let msg1_pb = PeerConnNoiseMsg1Pb {
        version: 1,
        a_network_name: network_name.to_owned(),
        a_session_generation: None,
        a_conn_id: Some(a_conn_id.into()),
        client_encryption_algorithm: encrypt_algo.to_owned(),
    };
    let payload = msg1_pb.encode_to_vec();
    let mut out = vec![0u8; 4096];
    let out_len = hs.write_message(&payload, &mut out).unwrap();
    let mut pkt = ZCPacket::new_with_payload(&out[..out_len]);
    pkt.fill_peer_manager_hdr(
        client_peer_id,
        server_peer_id,
        PacketType::NoiseHandshakeMsg1 as u8,
    );
    sink.send(pkt).await.unwrap();

    let msg2_pkt = stream.next().await.unwrap().unwrap();
    let mut out = vec![0u8; 4096];
    let out_len = hs.read_message(msg2_pkt.payload(), &mut out).unwrap();
    let msg2_pb = PeerConnNoiseMsg2Pb::decode(&out[..out_len]).unwrap();

    let msg3_pb = PeerConnNoiseMsg3Pb {
        a_conn_id_echo: Some(a_conn_id.into()),
        b_conn_id_echo: msg2_pb.b_conn_id,
        member_cert_cbor: to_canonical_cbor(member_cert),
        borrowed_relay_proof: proof.map(to_canonical_cbor),
    };
    let payload = msg3_pb.encode_to_vec();
    let mut out = vec![0u8; 4096];
    let out_len = hs.write_message(&payload, &mut out).unwrap();
    let mut pkt = ZCPacket::new_with_payload(&out[..out_len]);
    pkt.fill_peer_manager_hdr(
        client_peer_id,
        server_peer_id,
        PacketType::NoiseHandshakeMsg3 as u8,
    );
    sink.send(pkt).await.unwrap();
}

async fn perform_borrowed_handshake(
    proof: Option<BorrowedRelayProof>,
    sent_cert: MemberCert,
    pool: Arc<RwLock<TrustDomainPool>>,
) -> Result<PeerConn, Error> {
    let client_peer_id = 1001;
    let server_peer_id = 2002;

    let client_noise_private = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let server_noise_private = x25519_dalek::StaticSecret::random_from_rng(OsRng);

    let server_root = TrustDomainRoot::generate();
    let server_sk_self = SignKey::generate();
    let server_cert = sample_member_cert(&server_root, &server_sk_self, "server-relay");

    let server_ctx = make_global_ctx(NETWORK_NAME, &server_noise_private);
    attach_trust_context(&server_ctx, &server_root, &server_cert, &server_sk_self).await;

    let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
    let peer_session_store = Arc::new(PeerSessionStore::new());
    let mut server = PeerConn::new(
        server_peer_id,
        server_ctx.clone(),
        server_tunnel,
        peer_session_store,
        Some(pool),
    );

    let encrypt_algo = server_ctx.get_flags().encryption_algorithm.clone();
    let client_future = run_noise_client_with_proof(
        client_tunnel,
        client_peer_id,
        server_peer_id,
        NETWORK_NAME,
        &client_noise_private,
        &encrypt_algo,
        &sent_cert,
        proof.as_ref(),
    );
    let server_future = server.do_handshake_as_server();
    let (_, server_result) = tokio::join!(client_future, server_future);
    server_result?;
    Ok(server)
}

struct EmptyAccessor;

#[async_trait::async_trait]
impl GlobalForeignNetworkAccessor for EmptyAccessor {
    async fn list_global_foreign_peer(
        &self,
        _network_identity: &GlobalNetworkIdentity,
    ) -> Vec<u32> {
        Vec::new()
    }
}

fn relay_grants_for(tdid: easytier::trust::TrustDomainId) -> Arc<RelayGrantTable> {
    Arc::new(RelayGrantTable::from_entries(vec![RelayGrantEntry {
        foreign_root_pk: tdid,
        capabilities: RelayCapabilities {
            can_relay_data: true,
            can_assist_holepunch: true,
        },
        expires_at: now_unix() + 3600,
    }]))
}

#[test]
fn test_proof_round_trip_cbor() {
    let root = TrustDomainRoot::generate();
    let sk_self = SignKey::generate();
    let cert = sample_member_cert(&root, &sk_self, "client-a");
    let proof = BorrowedRelayProof {
        trust_domain_id: root.id(),
        member_cert: cert,
        timestamp: now_unix(),
    };

    let bytes = to_canonical_cbor(&proof);
    let decoded: BorrowedRelayProof = from_cbor(&bytes).unwrap();

    assert_eq!(decoded, proof);
}

#[tokio::test]
async fn test_borrowed_handshake_cross_root_succeeds() {
    let client_root = TrustDomainRoot::generate();
    let client_sk_self = SignKey::generate();
    let client_cert = sample_member_cert(&client_root, &client_sk_self, "client-a");
    let pool = trust_pool_with_entries(&[(&client_root, &client_cert)]);
    let proof = BorrowedRelayProof {
        trust_domain_id: client_root.id(),
        member_cert: client_cert.clone(),
        timestamp: now_unix(),
    };

    let server = perform_borrowed_handshake(Some(proof), client_cert, pool)
        .await
        .unwrap();

    assert!(server.get_borrowed_proof().is_some());
}

#[tokio::test]
async fn test_borrowed_handshake_missing_proof_rejected() {
    let client_root = TrustDomainRoot::generate();
    let client_sk_self = SignKey::generate();
    let client_cert = sample_member_cert(&client_root, &client_sk_self, "client-a");
    let pool = trust_pool_with_entries(&[(&client_root, &client_cert)]);

    let err = perform_borrowed_handshake(None, client_cert, pool)
        .await
        .unwrap_err();

    assert!(matches!(err, Error::TrustDomainMismatch));
}

#[tokio::test]
async fn test_borrowed_handshake_replay_old_timestamp_rejected() {
    let client_root = TrustDomainRoot::generate();
    let client_sk_self = SignKey::generate();
    let client_cert = sample_member_cert(&client_root, &client_sk_self, "client-a");
    let pool = trust_pool_with_entries(&[(&client_root, &client_cert)]);
    let proof = BorrowedRelayProof {
        trust_domain_id: client_root.id(),
        member_cert: client_cert.clone(),
        timestamp: now_unix().saturating_sub(301),
    };

    let err = perform_borrowed_handshake(Some(proof), client_cert, pool)
        .await
        .unwrap_err();

    assert!(matches!(err, Error::TrustDomainMismatch));
}

#[tokio::test]
async fn test_borrowed_handshake_proof_cert_fingerprint_mismatch_rejected() {
    let client_root = TrustDomainRoot::generate();
    let client_sk_self = SignKey::generate();
    let client_cert = sample_member_cert(&client_root, &client_sk_self, "client-a");
    let other_sk_self = SignKey::generate();
    let other_cert = sample_member_cert(&client_root, &other_sk_self, "client-b");
    let pool = trust_pool_with_entries(&[(&client_root, &client_cert)]);
    let proof = BorrowedRelayProof {
        trust_domain_id: client_root.id(),
        member_cert: other_cert,
        timestamp: now_unix(),
    };

    let err = perform_borrowed_handshake(Some(proof), client_cert, pool)
        .await
        .unwrap_err();

    assert!(matches!(err, Error::TrustDomainMismatch));
}

#[tokio::test]
async fn test_foreign_network_manager_admits_borrowed_client() {
    let client_root = TrustDomainRoot::generate();
    let client_sk_self = SignKey::generate();
    let client_cert = sample_member_cert(&client_root, &client_sk_self, "client-a");
    let proof = BorrowedRelayProof {
        trust_domain_id: client_root.id(),
        member_cert: client_cert.clone(),
        timestamp: now_unix(),
    };

    let allowed_pool = trust_pool_with_entries(&[(&client_root, &client_cert)]);
    let server_conn =
        perform_borrowed_handshake(Some(proof.clone()), client_cert.clone(), allowed_pool)
            .await
            .unwrap();

    let config = TomlConfigLoader::default();
    config.set_network_identity(NetworkIdentity::new("relay-net".to_owned()));
    let global_ctx = Arc::new(GlobalCtx::new(config));
    let (tx, _rx) = create_packet_recv_chan();
    let allowed_mgr = ForeignNetworkManager::new(
        7001,
        global_ctx.clone(),
        Arc::new(PeerSessionStore::new()),
        tx,
        Box::new(EmptyAccessor),
        relay_grants_for(client_root.id()),
    );
    allowed_mgr.add_peer_conn(server_conn).await.unwrap();

    let denied_pool = trust_pool_with_entries(&[(&client_root, &client_cert)]);
    let denied_conn = perform_borrowed_handshake(Some(proof), client_cert, denied_pool)
        .await
        .unwrap();

    let (tx, _rx) = create_packet_recv_chan();
    let denied_mgr = ForeignNetworkManager::new(
        7002,
        global_ctx,
        Arc::new(PeerSessionStore::new()),
        tx,
        Box::new(EmptyAccessor),
        Arc::new(RelayGrantTable::empty()),
    );
    let err = denied_mgr.add_peer_conn(denied_conn).await.unwrap_err();
    let err_str = err.to_string();
    assert!(
        err_str.contains("not permitted"),
        "unexpected error: {err_str}"
    );
}
