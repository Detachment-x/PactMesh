use easytier::proto::peer_rpc::{HandshakeRequest, PeerConnNoiseMsg3Pb, SecureAuthLevel};
use prost::Message;

#[test]
fn test_handshake_request_round_trip_with_member_cert_cbor() {
    let req = HandshakeRequest {
        magic: 0x1234_5678,
        my_peer_id: 7,
        version: 42,
        features: vec!["noise".to_owned(), "trust".to_owned()],
        network_name: "office-net".to_owned(),
        member_cert_cbor: vec![0x82, 0x01, 0x02],
        applicant_nonce: vec![0x11; 16],
        applicant_signature: vec![0x22; 64],
    };

    let encoded = req.encode_to_vec();
    let decoded = HandshakeRequest::decode(encoded.as_slice()).unwrap();

    assert_eq!(decoded, req);
}

#[test]
fn test_noise_msg3_round_trip_with_member_cert_cbor() {
    let msg = PeerConnNoiseMsg3Pb {
        a_conn_id_echo: None,
        b_conn_id_echo: None,
        member_cert_cbor: vec![0xa1, 0x01, 0x02],
        borrowed_relay_proof: None,
    };

    let encoded = msg.encode_to_vec();
    let decoded = PeerConnNoiseMsg3Pb::decode(encoded.as_slice()).unwrap();

    assert_eq!(decoded, msg);
}

#[test]
fn test_noise_msg2_round_trip_with_member_cert_cbor() {
    let msg = easytier::proto::peer_rpc::PeerConnNoiseMsg2Pb {
        b_network_name: "office-net".to_owned(),
        role_hint: 1,
        action: easytier::proto::peer_rpc::PeerConnSessionActionPb::Join as i32,
        b_session_generation: 7,
        root_key_32: Some(vec![0x11; 32]),
        initial_epoch: 42,
        b_conn_id: None,
        a_conn_id_echo: None,
        server_encryption_algorithm: "Noise_XX_25519_ChaChaPoly_SHA256".to_owned(),
        member_cert_cbor: vec![0xa1, 0x01, 0x02],
    };

    let encoded = msg.encode_to_vec();
    let decoded = easytier::proto::peer_rpc::PeerConnNoiseMsg2Pb::decode(encoded.as_slice()).unwrap();

    assert_eq!(decoded, msg);
}

#[test]
fn test_secure_auth_level_trust_domain_verified_is_3() {
    assert_eq!(SecureAuthLevel::TrustDomainVerified as i32, 3);
}
