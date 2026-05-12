//! Tests for `trust::cbor` (T-010 canonical encode/decode, T-011 PEM armor).

use easytier::trust::cbor::{ArmorError, CborError};
use easytier::trust::{from_cbor, to_canonical_cbor, unwrap_armored, wrap_armored};
use minicbor::{Decode, Encode, Encoder, encode::Write};

#[derive(Debug, Encode, Decode, PartialEq, Eq)]
struct RoundTripFixture {
    #[n(0)]
    id: u64,
    #[n(1)]
    name: String,
}

struct NonCanonicalMapFixture;

impl Encode<()> for NonCanonicalMapFixture {
    fn encode<W: Write>(
        &self,
        encoder: &mut Encoder<W>,
        _ctx: &mut (),
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.map(3)?;
        encoder.str("b")?.u64(2)?;
        encoder.str("aa")?.u64(3)?;
        encoder.str("a")?.u64(1)?;
        Ok(())
    }
}

#[test]
fn test_canonical_round_trip() {
    let value = RoundTripFixture {
        id: 7,
        name: "alpha".to_owned(),
    };

    let encoded = to_canonical_cbor(&value);
    let decoded: RoundTripFixture = from_cbor(&encoded).unwrap();

    assert_eq!(decoded, value);
    assert_eq!(to_canonical_cbor(&decoded), encoded);
}

#[test]
fn test_canonical_map_key_order() {
    let encoded = to_canonical_cbor(&NonCanonicalMapFixture);

    assert_eq!(
        encoded,
        vec![
            0xa3, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02, 0x62, 0x61, 0x61, 0x03
        ]
    );
}

#[test]
fn test_canonical_rejects_trailing_bytes() {
    let encoded = to_canonical_cbor(&RoundTripFixture {
        id: 1,
        name: "x".to_owned(),
    });
    let mut with_trailing = encoded;
    with_trailing.push(0xf6);

    let err = from_cbor::<RoundTripFixture>(&with_trailing).unwrap_err();
    assert_eq!(err, CborError::TrailingBytes);
}

#[test]
fn test_armor_round_trip() {
    let payload = (0u8..96).collect::<Vec<_>>();
    let armored = wrap_armored("PNW-TEST", &payload);
    let lines = armored.lines().collect::<Vec<_>>();

    assert_eq!(lines.len(), 4);
    assert_eq!(lines[0], "-----BEGIN PNW-TEST-----");
    assert_eq!(lines[1].len(), 64);
    assert_eq!(lines[2].len(), 64);
    assert_eq!(lines[3], "-----END PNW-TEST-----");
    assert!(armored.ends_with('\n'));
    assert_eq!(unwrap_armored(&armored, "PNW-TEST").unwrap(), payload);
}

#[test]
fn test_armor_wrong_label_rejected() {
    let armored = wrap_armored("PNW-MEMBER-CERT", b"payload");
    let err = unwrap_armored(&armored, "PNW-NETWORK-STATE").unwrap_err();

    assert_eq!(
        err,
        ArmorError::LabelMismatch {
            expected: "PNW-NETWORK-STATE".to_owned(),
            found: "PNW-MEMBER-CERT".to_owned(),
        }
    );
}
