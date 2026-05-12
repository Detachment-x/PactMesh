//! Tests for `trust::revocation` (T-040 RevokedCert / DisabledCert).

use easytier::trust::revocation::{DisabledCert, RevocationReason, RevokedCert};
use easytier::trust::{MemberCertFingerprint, from_cbor, to_canonical_cbor};

fn fingerprint(byte: u8) -> MemberCertFingerprint {
    MemberCertFingerprint([byte; 32])
}

#[test]
fn test_revoked_always_active() {
    let revoked = RevokedCert {
        cert_fingerprint: fingerprint(1),
        revoked_at: 1_700_000_000,
        reason_code: RevocationReason::Removed,
        reason_note: Some("member left".to_owned()),
    };

    assert!(revoked.is_active_at(0));
    assert!(revoked.is_active_at(revoked.revoked_at));
    assert!(revoked.is_active_at(revoked.revoked_at + 10_000));
}

#[test]
fn test_disabled_recovery_after_expected_until() {
    let disabled = DisabledCert {
        cert_fingerprint: fingerprint(2),
        disabled_at: 1_700_000_000,
        expected_until: Some(1_700_000_100),
        reason_note: Some("maintenance".to_owned()),
    };
    let indefinite = DisabledCert {
        cert_fingerprint: fingerprint(3),
        disabled_at: 1_700_000_000,
        expected_until: None,
        reason_note: None,
    };

    assert!(disabled.is_active_at(1_700_000_000));
    assert!(disabled.is_active_at(1_700_000_100));
    assert!(!disabled.is_active_at(1_700_000_101));
    assert!(indefinite.is_active_at(u64::MAX));
}

#[test]
fn test_round_trip_cbor() {
    let revoked = RevokedCert {
        cert_fingerprint: fingerprint(4),
        revoked_at: 1_710_000_000,
        reason_code: RevocationReason::KeyCompromise,
        reason_note: Some("lost laptop".to_owned()),
    };
    let disabled = DisabledCert {
        cert_fingerprint: fingerprint(5),
        disabled_at: 1_710_000_111,
        expected_until: Some(1_710_000_999),
        reason_note: Some("debug freeze".to_owned()),
    };

    let revoked_bytes = to_canonical_cbor(&revoked);
    let disabled_bytes = to_canonical_cbor(&disabled);
    let revoked_decoded: RevokedCert = from_cbor(&revoked_bytes).unwrap();
    let disabled_decoded: DisabledCert = from_cbor(&disabled_bytes).unwrap();

    assert_eq!(revoked_decoded, revoked);
    assert_eq!(disabled_decoded, disabled);
    assert_eq!(to_canonical_cbor(&revoked_decoded), revoked_bytes);
    assert_eq!(to_canonical_cbor(&disabled_decoded), disabled_bytes);
}
