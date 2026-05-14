//! Tests for `trust::member_cert` (T-030..T-034) plus hostname charset (T-034).

use std::str::FromStr;

use ed25519_dalek::SigningKey;
use pactmesh::trust::cbor::ArmorError;
use pactmesh::trust::hostname::{HostnameError, HostnameLabel, check_hostname_unique};
use pactmesh::trust::member_cert::{
    Capabilities, MemberCert, ParseError, UnsignedMemberCert, VerifyError,
};
use pactmesh::trust::{
    MemberCertFingerprint, TrustDomainId, TrustDomainRoot, from_cbor, to_canonical_cbor,
    wrap_armored,
};
use pnet::ipnetwork::IpNetwork as IpNet;
use rand::rngs::OsRng;

fn sample_unsigned_member_cert() -> UnsignedMemberCert {
    let device_pk = SigningKey::generate(&mut OsRng).verifying_key();

    UnsignedMemberCert {
        trust_domain_id: TrustDomainId::from_root_pubkey(&device_pk),
        network_local_id: "office-net".parse().unwrap(),
        device_pk,
        device_label: "laptop-a".to_owned(),
        not_before: 1_715_000_000,
        expires_at: 1_716_000_000,
        capabilities: Capabilities {
            can_relay_data: true,
            can_relay_control: false,
            can_proxy_subnet: vec![
                IpNet::from_str("10.0.0.0/24").unwrap(),
                IpNet::from_str("2001:db8::/64").unwrap(),
            ],
        },
        hostname: None,
        network_state_version_ref: 42,
    }
}

fn sample_unsigned_member_cert_for_root(root: &TrustDomainRoot) -> UnsignedMemberCert {
    let mut cert = sample_unsigned_member_cert();
    cert.trust_domain_id = root.id();
    cert
}

fn sample_member_cert() -> MemberCert {
    let root = TrustDomainRoot::generate();
    sample_unsigned_member_cert_for_root(&root).sign(&root)
}

fn sample_fingerprint(byte: u8) -> MemberCertFingerprint {
    MemberCertFingerprint([byte; 32])
}

#[test]
fn test_capabilities_round_trip_cbor() {
    let caps = Capabilities {
        can_relay_data: true,
        can_relay_control: false,
        can_proxy_subnet: vec![
            IpNet::from_str("10.0.0.0/24").unwrap(),
            IpNet::from_str("2001:db8::/64").unwrap(),
        ],
    };

    let encoded = to_canonical_cbor(&caps);
    let decoded: Capabilities = from_cbor(&encoded).unwrap();

    assert_eq!(decoded, caps);
    assert_eq!(to_canonical_cbor(&decoded), encoded);
}

#[test]
fn test_capabilities_subset_logic() {
    let allowed = Capabilities {
        can_relay_data: true,
        can_relay_control: true,
        can_proxy_subnet: vec![
            IpNet::from_str("10.0.0.0/16").unwrap(),
            IpNet::from_str("2001:db8::/48").unwrap(),
        ],
    };
    let narrower = Capabilities {
        can_relay_data: true,
        can_relay_control: false,
        can_proxy_subnet: vec![
            IpNet::from_str("10.0.1.0/24").unwrap(),
            IpNet::from_str("2001:db8:0:1::/64").unwrap(),
        ],
    };
    let wider = Capabilities {
        can_relay_data: true,
        can_relay_control: true,
        can_proxy_subnet: vec![IpNet::from_str("10.0.0.0/8").unwrap()],
    };
    let wrong_family = Capabilities {
        can_relay_data: true,
        can_relay_control: false,
        can_proxy_subnet: vec![IpNet::from_str("::ffff:10.0.1.0/120").unwrap()],
    };

    assert!(narrower.is_subset_of(&allowed));
    assert!(!allowed.is_subset_of(&narrower));
    assert!(!wider.is_subset_of(&allowed));
    assert!(!wrong_family.is_subset_of(&allowed));
}

fn assert_unsigned_cert_marshal_deterministic() {
    let cert = sample_unsigned_member_cert();

    let left = cert.marshal_for_signing();
    let right = cert.marshal_for_signing();

    assert_eq!(left, right);
    assert_eq!(left, to_canonical_cbor(&cert));
}

fn assert_unsigned_cert_round_trip() {
    let cert = sample_unsigned_member_cert();

    let encoded = to_canonical_cbor(&cert);
    let decoded: UnsignedMemberCert = from_cbor(&encoded).unwrap();

    assert_eq!(decoded, cert);
    assert_eq!(decoded.device_pk.to_bytes(), cert.device_pk.to_bytes());
    assert_eq!(to_canonical_cbor(&decoded), encoded);
}

fn assert_sign_verify_happy_path() {
    let root = TrustDomainRoot::generate();
    let cert = sample_unsigned_member_cert_for_root(&root).sign(&root);

    assert_eq!(cert.verify(&root.public_key()), Ok(()));
    assert_eq!(cert.fingerprint(), cert.fingerprint());
    assert_eq!(cert.fingerprint(), MemberCert::clone(&cert).fingerprint());
}

fn assert_verify_wrong_root_rejected() {
    let root = TrustDomainRoot::generate();
    let wrong_root = TrustDomainRoot::generate();
    let cert = sample_unsigned_member_cert_for_root(&root).sign(&root);

    assert_eq!(
        cert.verify(&wrong_root.public_key()),
        Err(VerifyError::DomainMismatch)
    );
}

fn assert_verify_tampered_field_rejected() {
    let root = TrustDomainRoot::generate();
    let mut cert = sample_unsigned_member_cert_for_root(&root).sign(&root);
    cert.details.device_label.push_str("-tampered");

    assert_eq!(
        cert.verify(&root.public_key()),
        Err(VerifyError::BadSignature)
    );
}

fn assert_verify_invalid_time_window_rejected() {
    let root = TrustDomainRoot::generate();
    let mut details = sample_unsigned_member_cert_for_root(&root);
    details.not_before = details.expires_at;
    let cert = details.sign(&root);

    assert_eq!(
        cert.verify(&root.public_key()),
        Err(VerifyError::BadTimeWindow {
            nb: cert.details.not_before,
            ea: cert.details.expires_at,
        })
    );
}

fn assert_pem_round_trip() {
    let cert = sample_member_cert();
    let pem = cert.to_pem();
    let decoded = MemberCert::from_pem(&pem).unwrap();

    assert_eq!(decoded, cert);
    assert_eq!(decoded.to_pem(), pem);
}

fn assert_pem_wrong_label_rejected() {
    let cert = sample_member_cert();
    let wrong = wrap_armored("PNW-NETWORK-STATE", &to_canonical_cbor(&cert));

    assert_eq!(
        MemberCert::from_pem(&wrong),
        Err(ParseError::Armor(ArmorError::LabelMismatch {
            expected: "PNW-MEMBER-CERT".to_owned(),
            found: "PNW-NETWORK-STATE".to_owned(),
        }))
    );
}

fn assert_cert_with_hostname_round_trip() {
    let mut cert = sample_unsigned_member_cert();
    cert.hostname = Some(HostnameLabel::try_from_str("Server-01").unwrap());

    let encoded = to_canonical_cbor(&cert);
    let decoded: UnsignedMemberCert = from_cbor(&encoded).unwrap();

    assert_eq!(decoded, cert);
    assert_eq!(decoded.hostname.unwrap().as_str(), "server-01");
}

fn assert_cert_without_hostname_decodes_as_none() {
    #[derive(minicbor::Encode)]
    struct LegacyUnsignedMemberCert<'a> {
        #[n(0)]
        trust_domain_id: TrustDomainId,
        #[n(1)]
        network_local_id: &'a pactmesh::trust::NetworkLocalId,
        #[n(2)]
        #[cbor(with = "minicbor::bytes")]
        device_pk: &'a [u8],
        #[n(3)]
        device_label: &'a str,
        #[n(4)]
        not_before: u64,
        #[n(5)]
        expires_at: u64,
        #[n(6)]
        capabilities: &'a Capabilities,
        #[n(7)]
        network_state_version_ref: u64,
    }

    let cert = sample_unsigned_member_cert();
    let legacy = LegacyUnsignedMemberCert {
        trust_domain_id: cert.trust_domain_id,
        network_local_id: &cert.network_local_id,
        device_pk: cert.device_pk.as_bytes(),
        device_label: &cert.device_label,
        not_before: cert.not_before,
        expires_at: cert.expires_at,
        capabilities: &cert.capabilities,
        network_state_version_ref: cert.network_state_version_ref,
    };

    let encoded = to_canonical_cbor(&legacy);
    let decoded: UnsignedMemberCert = from_cbor(&encoded).unwrap();

    assert_eq!(decoded.hostname, None);
    assert_eq!(
        decoded.network_state_version_ref,
        cert.network_state_version_ref
    );
}

fn assert_check_hostname_unique_accepts_unused() {
    let new = HostnameLabel::try_from_str("laptop").unwrap();
    let existing = vec![
        (
            sample_fingerprint(1),
            Some(HostnameLabel::try_from_str("server").unwrap()),
        ),
        (sample_fingerprint(2), None),
    ];

    assert_eq!(check_hostname_unique(&new, &existing), Ok(()));
}

fn assert_check_hostname_unique_rejects_taken() {
    let new = HostnameLabel::try_from_str("server").unwrap();
    let taken_by = sample_fingerprint(7);
    let existing = vec![(
        taken_by,
        Some(HostnameLabel::try_from_str("server").unwrap()),
    )];

    assert_eq!(
        check_hostname_unique(&new, &existing),
        Err(HostnameError::Conflict {
            name: "server".to_owned(),
            taken_by,
        })
    );
}

fn assert_check_hostname_unique_revoked_releases_name() {
    let new = HostnameLabel::try_from_str("server").unwrap();
    let existing = vec![(sample_fingerprint(2), None)];

    assert_eq!(check_hostname_unique(&new, &existing), Ok(()));
}

#[test]
fn test_unsigned_cert_marshal_deterministic() {
    assert_unsigned_cert_marshal_deterministic();
}

#[test]
fn test_unsigned_cert_round_trip() {
    assert_unsigned_cert_round_trip();
}

#[test]
fn test_unsigned_member_cert() {
    assert_unsigned_cert_marshal_deterministic();
    assert_unsigned_cert_round_trip();
}

#[test]
fn test_sign_verify_happy_path() {
    assert_sign_verify_happy_path();
}

#[test]
fn test_verify_wrong_root_rejected() {
    assert_verify_wrong_root_rejected();
}

#[test]
fn test_verify_tampered_field_rejected() {
    assert_verify_tampered_field_rejected();
}

#[test]
fn test_verify_invalid_time_window_rejected() {
    assert_verify_invalid_time_window_rejected();
}

#[test]
fn test_member_cert_sign() {
    assert_sign_verify_happy_path();
    assert_verify_wrong_root_rejected();
    assert_verify_tampered_field_rejected();
    assert_verify_invalid_time_window_rejected();
}

#[test]
fn test_pem_round_trip() {
    assert_pem_round_trip();
}

#[test]
fn test_pem_wrong_label_rejected() {
    assert_pem_wrong_label_rejected();
}

#[test]
fn test_member_cert_pem() {
    assert_pem_round_trip();
    assert_pem_wrong_label_rejected();
}

#[test]
fn test_cert_with_hostname_round_trip() {
    assert_cert_with_hostname_round_trip();
}

#[test]
fn test_cert_without_hostname_decodes_as_none() {
    assert_cert_without_hostname_decodes_as_none();
}

#[test]
fn test_check_hostname_unique_accepts_unused() {
    assert_check_hostname_unique_accepts_unused();
}

#[test]
fn test_check_hostname_unique_rejects_taken() {
    assert_check_hostname_unique_rejects_taken();
}

#[test]
fn test_check_hostname_unique_revoked_releases_name() {
    assert_check_hostname_unique_revoked_releases_name();
}

#[test]
fn test_label_charset_lowercase_normalized() {
    let label = HostnameLabel::try_from_str("node-1").unwrap();
    assert_eq!(label.as_str(), "node-1");
}

#[test]
fn test_label_uppercase_normalized_to_lower() {
    let label = HostnameLabel::try_from_str("Server-01").unwrap();
    assert_eq!(label.as_str(), "server-01");
}

#[test]
fn test_label_leading_hyphen_rejected() {
    assert_eq!(
        HostnameLabel::try_from_str("-node"),
        Err(HostnameError::EdgeHyphen)
    );
}

#[test]
fn test_label_trailing_hyphen_rejected() {
    assert_eq!(
        HostnameLabel::try_from_str("node-"),
        Err(HostnameError::EdgeHyphen)
    );
}

#[test]
fn test_label_too_long_64_rejected() {
    let too_long = "a".repeat(64);
    assert_eq!(
        HostnameLabel::try_from_str(&too_long),
        Err(HostnameError::Length(64))
    );
}

#[test]
fn test_label_empty_rejected() {
    assert_eq!(HostnameLabel::try_from_str(""), Err(HostnameError::Empty));
}

#[test]
fn test_label_unicode_rejected() {
    assert_eq!(
        HostnameLabel::try_from_str("中文"),
        Err(HostnameError::Charset(0xe4))
    );
}

#[test]
fn test_label_serde_round_trip_cbor() {
    let label = HostnameLabel::try_from_str("edge-gw").unwrap();
    let encoded = to_canonical_cbor(&label);
    let decoded: HostnameLabel = from_cbor(&encoded).unwrap();

    assert_eq!(decoded, label);
    assert_eq!(decoded.to_string(), "edge-gw");
}
