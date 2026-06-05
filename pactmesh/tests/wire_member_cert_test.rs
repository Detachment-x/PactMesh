use pactmesh::proto::peer_rpc::MemberCertEnvelope;
use pactmesh::trust::{
    Capabilities, MemberCert, NetworkLocalId, SignKey, TrustDomainRoot, UnsignedMemberCert,
    WireError, member_cert_from_envelope, member_cert_to_envelope,
};
use pnet::ipnetwork::IpNetwork;

fn cert_with_capabilities(capabilities: Capabilities) -> (TrustDomainRoot, MemberCert) {
    let root = TrustDomainRoot::generate();
    let sk = SignKey::generate();
    let cert = UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str("office-net").unwrap(),
        device_pk: ed25519_dalek::VerifyingKey::from_bytes(&sk.verify_key().0).unwrap(),
        device_label: "device-a".to_owned(),
        not_before: 1,
        expires_at: 3600,
        capabilities,
        network_state_version_ref: 1,
        hostname: None,
    }
    .sign(&root);
    (root, cert)
}

fn basic_capabilities() -> Capabilities {
    Capabilities {
        can_be_exit_node: false,
        can_relay_data: true,
        can_relay_control: true,
        can_proxy_subnet: Vec::new(),
    }
}

#[test]
fn test_round_trip_basic() {
    let (root, cert) = cert_with_capabilities(basic_capabilities());
    let env = member_cert_to_envelope(&cert);
    let decoded = member_cert_from_envelope(&env).unwrap();

    assert_eq!(decoded, cert);
    decoded.verify(&root.public_key()).unwrap();
}

#[test]
fn test_empty_envelope_rejected() {
    let err = member_cert_from_envelope(&MemberCertEnvelope { cbor: Vec::new() }).unwrap_err();

    assert_eq!(err, WireError::EnvelopeEmpty);
}

#[test]
fn test_corrupted_cbor_rejected() {
    let err = member_cert_from_envelope(&MemberCertEnvelope {
        cbor: vec![0xff, 0x00, 0x01],
    })
    .unwrap_err();

    assert!(matches!(err, WireError::CborDecodeFailed(_)));
}

#[test]
fn test_round_trip_with_d5_empty_device_pk() {
    let (_, cert) = cert_with_capabilities(basic_capabilities());
    let env = member_cert_to_envelope(&cert);
    let decoded = member_cert_from_envelope(&env).unwrap();

    assert_eq!(decoded.details.device_pk, cert.details.device_pk);
}

#[test]
fn test_round_trip_with_capabilities() {
    let subnet: IpNetwork = "10.10.0.0/16".parse().unwrap();
    let capabilities = Capabilities {
        can_be_exit_node: false,
        can_relay_data: false,
        can_relay_control: true,
        can_proxy_subnet: vec![subnet],
    };
    let (_, cert) = cert_with_capabilities(capabilities.clone());
    let decoded = member_cert_from_envelope(&member_cert_to_envelope(&cert)).unwrap();

    assert_eq!(decoded.details.capabilities, capabilities);
}
