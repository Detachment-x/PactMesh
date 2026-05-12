//! Tests for `trust::hostname` (T-034).

use easytier::trust::hostname::{HostnameError, HostnameLabel};
use easytier::trust::{from_cbor, to_canonical_cbor};

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
