use easytier::trust::network_bootstrap::{BootstrapError, NetworkBootstrap, bootstrap_to_qr_svg};
use easytier::trust::{
    NetworkLocalId, TrustDomainId, TrustDomainRoot, from_cbor, to_canonical_cbor,
};
use url::Url;

fn sample_bootstrap() -> NetworkBootstrap {
    let root = TrustDomainRoot::generate();
    NetworkBootstrap {
        trust_domain_id: root.id(),
        pk_root: root.public_key(),
        network_local_id: NetworkLocalId::try_from_str("office-net").unwrap(),
        bootstrap_seeds: vec![
            Url::parse("tcp://203.0.113.10:11010").unwrap(),
            Url::parse("udp://198.51.100.2:22020").unwrap(),
        ],
        trust_domain_label: Some("团队网络🚀".to_owned()),
        network_name: Some("ops-backbone".to_owned()),
        description: Some("bootstrap bundle".to_owned()),
    }
}

#[test]
fn test_bootstrap_round_trip_cbor() {
    let bootstrap = sample_bootstrap();

    let encoded = to_canonical_cbor(&bootstrap);
    let decoded: NetworkBootstrap = from_cbor(&encoded).unwrap();

    assert_eq!(decoded, bootstrap);
    decoded.verify_self_consistency().unwrap();
}

#[test]
fn test_bootstrap_self_consistency_pk_mismatch_rejected() {
    let mut bootstrap = sample_bootstrap();
    let other_root = TrustDomainRoot::generate();
    bootstrap.trust_domain_id = TrustDomainId::from_root_pubkey(&other_root.public_key());

    let err = bootstrap.verify_self_consistency().unwrap_err();
    assert!(matches!(err, BootstrapError::TrustDomainIdMismatch { .. }));
}

#[test]
fn test_url_round_trip_basic_fields() {
    let bootstrap = sample_bootstrap();

    let url = bootstrap.to_url().unwrap();
    let decoded = NetworkBootstrap::from_url(&url).unwrap();

    assert_eq!(decoded, bootstrap);
}

#[test]
fn test_url_with_unicode_label_url_encoded_correctly() {
    let bootstrap = sample_bootstrap();

    let url = bootstrap.to_url().unwrap();
    assert!(url.as_str().contains("label="));
    assert!(!url.as_str().contains("团队网络🚀"));

    let decoded = NetworkBootstrap::from_url(&url).unwrap();
    assert_eq!(decoded.trust_domain_label, bootstrap.trust_domain_label);
}

#[test]
fn test_url_too_long_returns_error() {
    let mut bootstrap = sample_bootstrap();
    bootstrap.description = Some("x".repeat(2_100));

    let err = bootstrap.to_url().unwrap_err();
    assert!(matches!(err, BootstrapError::TooLongForQr(_)));
}

#[test]
fn test_file_pem_round_trip() {
    let bootstrap = sample_bootstrap();

    let pem = bootstrap.to_pem();
    let decoded = NetworkBootstrap::from_pem(&pem).unwrap();

    assert_eq!(decoded, bootstrap);
}

#[test]
fn test_qr_svg_renders_non_empty() {
    let bootstrap = sample_bootstrap();

    let svg = bootstrap_to_qr_svg(&bootstrap).unwrap();

    assert!(svg.contains("<svg"));
    assert!(svg.contains("path"));
}

#[test]
fn test_import_writes_pk_root_to_local_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let bootstrap = sample_bootstrap();

    bootstrap.import_into_domain_dir(dir.path()).unwrap();
    let pem = std::fs::read_to_string(dir.path().join("pk_root.pem")).unwrap();
    assert!(pem.contains("BEGIN PNW-PK-ROOT"));

    bootstrap.import_into_domain_dir(dir.path()).unwrap();
}

#[test]
fn test_import_mismatched_existing_pk_root_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let bootstrap = sample_bootstrap();
    bootstrap.import_into_domain_dir(dir.path()).unwrap();

    let mut other = sample_bootstrap();
    let other_root = TrustDomainRoot::generate();
    other.pk_root = other_root.public_key();
    other.trust_domain_id = other_root.id();

    let err = other.import_into_domain_dir(dir.path()).unwrap_err();
    assert!(matches!(
        err,
        BootstrapError::PkRootAlreadyExistsAndMismatches
    ));
}
