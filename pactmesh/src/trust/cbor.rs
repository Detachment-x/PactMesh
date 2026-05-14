//! CBOR Deterministic Encoding (RFC 8949 §4.2) helpers and PEM-style armor.
//!
//! - `to_canonical_cbor`: encode with `minicbor` ensuring map-key bytewise
//!   ordering and shortest integer form.
//! - `from_cbor`: decode with strict mode (no trailing bytes accepted).
//! - `wrap_armored` / `unwrap_armored`: standard `-----BEGIN <LABEL>-----` /
//!   `-----END <LABEL>-----` base64 envelope (T-011), label is checked at
//!   unwrap time.

use base64::{Engine as _, prelude::BASE64_STANDARD};
use minicbor::{Decode, Decoder, Encode, Encoder, data::Int, data::Tag, data::Type};
use thiserror::Error;

const ARMOR_LINE_LEN: usize = 64;
const ARMOR_BEGIN_PREFIX: &str = "-----BEGIN ";
const ARMOR_END_PREFIX: &str = "-----END ";
const ARMOR_SUFFIX: &str = "-----";

#[derive(Debug, Clone, PartialEq)]
enum CanonicalValue {
    Unsigned(u64),
    Negative(Int),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CanonicalValue>),
    Map(Vec<(CanonicalValue, CanonicalValue)>),
    Tag(Tag, Box<CanonicalValue>),
    Bool(bool),
    Null,
    Undefined,
    F32(f32),
    F64(f64),
}

/// Encode a value to canonical CBOR bytes (RFC 8949 §4.2).
pub fn to_canonical_cbor<T: Encode<()>>(value: &T) -> Vec<u8> {
    let encoded = minicbor::to_vec(value).expect("Vec writer is infallible");
    parse_canonical_value(&mut Decoder::new(&encoded))
        .map(|parsed| encode_canonical_value(&parsed).expect("Vec writer is infallible"))
        .expect("re-encoding generated CBOR must succeed")
}

/// Decode a value from CBOR bytes; rejects trailing bytes.
pub fn from_cbor<'b, T: Decode<'b, ()>>(bytes: &'b [u8]) -> Result<T, CborError> {
    let mut canonical_decoder = Decoder::new(bytes);
    let parsed = parse_canonical_value(&mut canonical_decoder)
        .map_err(|err| CborError::Decode(err.to_string()))?;
    if canonical_decoder.position() != bytes.len() {
        return Err(CborError::TrailingBytes);
    }
    let canonical =
        encode_canonical_value(&parsed).map_err(|err| CborError::Encode(err.to_string()))?;
    if canonical != bytes {
        return Err(CborError::NonCanonical);
    }

    let mut decoder = Decoder::new(bytes);
    let value = decoder
        .decode::<T>()
        .map_err(|err| CborError::Decode(err.to_string()))?;
    if decoder.position() != bytes.len() {
        return Err(CborError::TrailingBytes);
    }
    Ok(value)
}

/// CBOR encode/decode error envelope.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CborError {
    #[error("encode: {0}")]
    Encode(String),
    #[error("decode: {0}")]
    Decode(String),
    #[error("non-canonical encoding (RFC 8949 §4.2)")]
    NonCanonical,
    #[error("unexpected trailing bytes")]
    TrailingBytes,
}

/// Wrap a binary blob in a `-----BEGIN <LABEL>-----` / `-----END <LABEL>-----` envelope.
pub fn wrap_armored(label: &str, payload: &[u8]) -> String {
    let encoded = BASE64_STANDARD.encode(payload);
    let mut armored = String::with_capacity(
        encoded.len() + (encoded.len() / ARMOR_LINE_LEN) + label.len() * 2 + 32,
    );

    armored.push_str(ARMOR_BEGIN_PREFIX);
    armored.push_str(label);
    armored.push_str(ARMOR_SUFFIX);
    armored.push('\n');

    for chunk in encoded.as_bytes().chunks(ARMOR_LINE_LEN) {
        armored.push_str(std::str::from_utf8(chunk).expect("base64 output is ASCII"));
        armored.push('\n');
    }

    armored.push_str(ARMOR_END_PREFIX);
    armored.push_str(label);
    armored.push_str(ARMOR_SUFFIX);
    armored.push('\n');
    armored
}

/// Unwrap a PEM-style envelope; rejects label mismatch and base64 errors.
pub fn unwrap_armored(text: &str, expected_label: &str) -> Result<Vec<u8>, ArmorError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(ArmorError::Boundary);
    }

    let lines = trimmed.lines().map(str::trim).collect::<Vec<_>>();
    if lines.len() < 2 {
        return Err(ArmorError::Boundary);
    }

    let found_label =
        parse_armor_label(lines[0], ARMOR_BEGIN_PREFIX).ok_or(ArmorError::Boundary)?;
    let footer_label = parse_armor_label(lines.last().expect("len checked"), ARMOR_END_PREFIX)
        .ok_or(ArmorError::Boundary)?;
    if found_label != footer_label {
        return Err(ArmorError::Boundary);
    }
    if found_label != expected_label {
        return Err(ArmorError::LabelMismatch {
            expected: expected_label.to_owned(),
            found: found_label.to_owned(),
        });
    }

    let payload = lines[1..lines.len() - 1].concat();
    BASE64_STANDARD
        .decode(payload)
        .map_err(|err| ArmorError::Base64(err.to_string()))
}

/// PEM armor decode errors.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ArmorError {
    #[error("missing or malformed armor header/footer")]
    Boundary,
    #[error("expected label '{expected}', found '{found}'")]
    LabelMismatch { expected: String, found: String },
    #[error("base64 payload decode failed: {0}")]
    Base64(String),
}

fn parse_armor_label<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    line.strip_prefix(prefix)?.strip_suffix(ARMOR_SUFFIX)
}
fn parse_canonical_value(
    decoder: &mut Decoder<'_>,
) -> Result<CanonicalValue, minicbor::decode::Error> {
    Ok(match decoder.datatype()? {
        Type::U8 | Type::U16 | Type::U32 | Type::U64 => CanonicalValue::Unsigned(decoder.u64()?),
        Type::I8 | Type::I16 | Type::I32 | Type::I64 | Type::Int => {
            CanonicalValue::Negative(decoder.int()?)
        }
        Type::Bytes => CanonicalValue::Bytes(decoder.bytes()?.to_vec()),
        Type::String => CanonicalValue::Text(decoder.str()?.to_owned()),
        Type::BytesIndef | Type::StringIndef => {
            return Err(minicbor::decode::Error::message(
                "indefinite bytes/text are not canonical",
            ));
        }
        Type::Array => {
            let len = decoder
                .array()?
                .expect("definite array type must report a length");
            let mut items = Vec::with_capacity(len as usize);
            for _ in 0..len {
                items.push(parse_canonical_value(decoder)?);
            }
            CanonicalValue::Array(items)
        }
        Type::ArrayIndef => {
            decoder.array()?;
            let mut items = Vec::new();
            loop {
                if decoder.datatype()? == Type::Break {
                    decoder.skip()?;
                    break;
                }
                items.push(parse_canonical_value(decoder)?);
            }
            CanonicalValue::Array(items)
        }
        Type::Map => {
            let len = decoder
                .map()?
                .expect("definite map type must report a length");
            let mut entries = Vec::with_capacity(len as usize);
            for _ in 0..len {
                let key = parse_canonical_value(decoder)?;
                let value = parse_canonical_value(decoder)?;
                entries.push((key, value));
            }
            CanonicalValue::Map(entries)
        }
        Type::MapIndef => {
            decoder.map()?;
            let mut entries = Vec::new();
            loop {
                if decoder.datatype()? == Type::Break {
                    decoder.skip()?;
                    break;
                }
                let key = parse_canonical_value(decoder)?;
                let value = parse_canonical_value(decoder)?;
                entries.push((key, value));
            }
            CanonicalValue::Map(entries)
        }
        Type::Tag => {
            let tag = decoder.tag()?;
            let value = parse_canonical_value(decoder)?;
            CanonicalValue::Tag(tag, Box::new(value))
        }
        Type::Bool => CanonicalValue::Bool(decoder.bool()?),
        Type::Null => {
            decoder.null()?;
            CanonicalValue::Null
        }
        Type::Undefined => {
            decoder.undefined()?;
            CanonicalValue::Undefined
        }
        Type::F32 => CanonicalValue::F32(decoder.f32()?),
        Type::F64 => CanonicalValue::F64(decoder.f64()?),
        Type::F16 => {
            return Err(minicbor::decode::Error::message(
                "f16 support unavailable in this build",
            ));
        }
        Type::Simple | Type::Break | Type::Unknown(_) => {
            return Err(minicbor::decode::Error::message(
                "unsupported CBOR token for canonical helper",
            ));
        }
    })
}

fn encode_canonical_value(
    value: &CanonicalValue,
) -> Result<Vec<u8>, minicbor::encode::Error<std::convert::Infallible>> {
    let mut out = Vec::new();
    let mut encoder = Encoder::new(&mut out);
    encode_canonical_into(&mut encoder, value)?;
    Ok(out)
}

fn encode_canonical_into(
    encoder: &mut Encoder<&mut Vec<u8>>,
    value: &CanonicalValue,
) -> Result<(), minicbor::encode::Error<std::convert::Infallible>> {
    match value {
        CanonicalValue::Unsigned(n) => {
            encoder.u64(*n)?;
        }
        CanonicalValue::Negative(n) => {
            encoder.int(*n)?;
        }
        CanonicalValue::Bytes(bytes) => {
            encoder.bytes(bytes)?;
        }
        CanonicalValue::Text(text) => {
            encoder.str(text)?;
        }
        CanonicalValue::Array(items) => {
            encoder.array(items.len() as u64)?;
            for item in items {
                encode_canonical_into(encoder, item)?;
            }
        }
        CanonicalValue::Map(entries) => {
            let mut encoded_entries = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                let encoded_key = encode_canonical_value(key)?;
                let encoded_value = encode_canonical_value(value)?;
                encoded_entries.push((encoded_key, encoded_value));
            }
            encoded_entries.sort_by(|(left_key, _), (right_key, _)| left_key.cmp(right_key));

            encoder.map(encoded_entries.len() as u64)?;
            for (encoded_key, encoded_value) in encoded_entries {
                encoder.writer_mut().extend_from_slice(&encoded_key);
                encoder.writer_mut().extend_from_slice(&encoded_value);
            }
        }
        CanonicalValue::Tag(tag, inner) => {
            encoder.tag(*tag)?;
            encode_canonical_into(encoder, inner)?;
        }
        CanonicalValue::Bool(value) => {
            encoder.bool(*value)?;
        }
        CanonicalValue::Null => {
            encoder.null()?;
        }
        CanonicalValue::Undefined => {
            encoder.undefined()?;
        }
        CanonicalValue::F32(value) => {
            encoder.f32(*value)?;
        }
        CanonicalValue::F64(value) => {
            encoder.f64(*value)?;
        }
    }
    Ok(())
}
