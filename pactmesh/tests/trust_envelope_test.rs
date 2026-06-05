use pactmesh::proto::peer_rpc::{
    JoinRequestEnvelope, MemberCertEnvelope, NetworkStateEnvelope, TrustDomainMetaEnvelope,
};
use pactmesh::trust::{
    ActiveRelay, Capabilities, JoinRequest, MemberCert, NetworkLocalId, NetworkStatePayload,
    RelayCapabilities, SignKey, SignedNetworkState, SignedTrustDomainMeta, TrustDomainRoot,
    UnsignedMemberCert, UnsignedNetworkState, UnsignedTrustDomainMeta, from_cbor,
    to_canonical_cbor,
};
use prost::Message;

const NETWORK_LOCAL_ID: &str = "office-net";

fn root() -> TrustDomainRoot {
    TrustDomainRoot::generate()
}

fn network_local_id() -> NetworkLocalId {
    NetworkLocalId::try_from_str(NETWORK_LOCAL_ID).unwrap()
}

fn member_cert(root: &TrustDomainRoot) -> MemberCert {
    let sk = SignKey::generate();
    UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: network_local_id(),
        device_pk: ed25519_dalek::VerifyingKey::from_bytes(&sk.verify_key().0).unwrap(),
        device_label: "device-a".to_owned(),
        not_before: 1,
        expires_at: 3600,
        capabilities: Capabilities {
            can_be_exit_node: false,
            can_relay_data: true,
            can_relay_control: false,
            can_proxy_subnet: Vec::new(),
        },
        network_state_version_ref: 7,
        hostname: None,
    }
    .sign(root)
}

fn network_state(root: &TrustDomainRoot) -> SignedNetworkState {
    UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: network_local_id(),
        version: 7,
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

fn trust_domain_meta(root: &TrustDomainRoot) -> SignedTrustDomainMeta {
    let relay_sk = SignKey::generate();
    UnsignedTrustDomainMeta {
        trust_domain_id: root.id(),
        version: 3,
        active_relays: vec![ActiveRelay {
            device_pk: ed25519_dalek::VerifyingKey::from_bytes(&relay_sk.verify_key().0).unwrap(),
            device_label: "relay-a".to_owned(),
            capabilities: RelayCapabilities {
                can_relay_data: true,
                can_assist_holepunch: true,
            },
            expires_at: 3600,
        }],
        outbound_grants: Vec::new(),
    }
    .sign(root)
}

fn join_request(root: &TrustDomainRoot) -> JoinRequest {
    JoinRequest::new_signed(
        root.id(),
        network_local_id(),
        &SignKey::generate(),
        "device-b".to_owned(),
        "join hint".to_owned(),
    )
}

fn round_trip<M>(message: M) -> M
where
    M: Message + Default,
{
    M::decode(message.encode_to_vec().as_slice()).unwrap()
}

#[test]
fn test_member_cert_envelope_round_trip() {
    let root = root();
    let cbor = to_canonical_cbor(&member_cert(&root));
    let decoded = round_trip(MemberCertEnvelope { cbor: cbor.clone() });

    assert_eq!(decoded.cbor, cbor);
    let cert: MemberCert = from_cbor(&decoded.cbor).unwrap();
    cert.verify(&root.public_key()).unwrap();
}

#[test]
fn test_network_state_envelope_round_trip() {
    let root = root();
    let cbor = to_canonical_cbor(&network_state(&root));
    let decoded = round_trip(NetworkStateEnvelope { cbor: cbor.clone() });

    assert_eq!(decoded.cbor, cbor);
    let state: SignedNetworkState = from_cbor(&decoded.cbor).unwrap();
    state.verify(&root.public_key().into()).unwrap();
}

#[test]
fn test_trust_domain_meta_envelope_round_trip() {
    let root = root();
    let cbor = to_canonical_cbor(&trust_domain_meta(&root));
    let decoded = round_trip(TrustDomainMetaEnvelope { cbor: cbor.clone() });

    assert_eq!(decoded.cbor, cbor);
    let meta: SignedTrustDomainMeta = from_cbor(&decoded.cbor).unwrap();
    meta.verify(&root.public_key().into()).unwrap();
}

#[test]
fn test_join_request_envelope_round_trip() {
    let root = root();
    let cbor = to_canonical_cbor(&join_request(&root));
    let decoded = round_trip(JoinRequestEnvelope { cbor: cbor.clone() });

    assert_eq!(decoded.cbor, cbor);
    let request: JoinRequest = from_cbor(&decoded.cbor).unwrap();
    request.verify_self_signature().unwrap();
}
