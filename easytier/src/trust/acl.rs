//! ACL policy wire types for `network_state.payload.acl`.
//!
//! See `acl-schema-draft.md` §1 / §3 and
//! `trust-and-config-design.md` §17.4.

use std::{collections::BTreeMap, net::IpAddr, str::FromStr};

use minicbor::{Decode, Decoder, Encode, Encoder, data::Type, encode::Write};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::hostname::HostnameLabel;

/// Current ACL schema version.
pub const ACL_SCHEMA_VERSION: u8 = 1;
/// Maximum number of tag entries in one policy.
pub const MAX_TAGS: usize = 64;
/// Maximum number of rules in one policy.
pub const MAX_RULES: usize = 256;
/// Maximum number of bytes in one tag name.
pub const MAX_TAG_NAME_LEN: usize = 32;
/// Maximum number of members bound to one tag.
pub const MAX_TAG_MEMBERS: usize = 1024;
/// Maximum number of selectors in one src/dst list.
pub const MAX_SELECTORS_PER_RULE: usize = 32;

/// Top-level ACL policy embedded into `network_state.payload.acl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclPolicy {
    pub tags: BTreeMap<TagName, Vec<DeviceFingerprint>>,
    pub rules: Vec<AclRule>,
    pub default_action: Action,
    pub schema_version: u8,
}

impl<Ctx> Encode<Ctx> for AclPolicy {
    fn encode<W: Write>(
        &self,
        encoder: &mut Encoder<W>,
        ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let field_count = if self.schema_version == ACL_SCHEMA_VERSION {
            3
        } else {
            4
        };
        encoder.map(field_count)?;

        encoder.u8(1)?;
        encoder.map(self.tags.len() as u64)?;
        for (tag, members) in &self.tags {
            tag.encode(encoder, ctx)?;
            let mut sorted = members.clone();
            sorted.sort_unstable();
            encoder.array(sorted.len() as u64)?;
            for member in sorted {
                member.encode(encoder, ctx)?;
            }
        }

        encoder.u8(2)?;
        self.rules.encode(encoder, ctx)?;

        encoder.u8(3)?;
        self.default_action.encode(encoder, ctx)?;

        if self.schema_version != ACL_SCHEMA_VERSION {
            encoder.u8(4)?;
            encoder.u8(self.schema_version)?;
        }

        Ok(())
    }
}

impl<'b, Ctx> Decode<'b, Ctx> for AclPolicy {
    fn decode(decoder: &mut Decoder<'b>, ctx: &mut Ctx) -> Result<Self, minicbor::decode::Error> {
        let len = decode_map_len(decoder, "acl policy")?;
        let mut tags = None;
        let mut rules = None;
        let mut default_action = None;
        let mut schema_version = ACL_SCHEMA_VERSION;

        for _ in 0..len {
            match decoder.u64()? {
                1 => {
                    let tag_count = decode_map_len(decoder, "tags")?;
                    let mut decoded = BTreeMap::new();
                    for _ in 0..tag_count {
                        let tag = TagName::decode(decoder, ctx)?;
                        let members = Vec::<DeviceFingerprint>::decode(decoder, ctx)?;
                        decoded.insert(tag, members);
                    }
                    tags = Some(decoded);
                }
                2 => rules = Some(Vec::<AclRule>::decode(decoder, ctx)?),
                3 => default_action = Some(Action::decode(decoder, ctx)?),
                4 => schema_version = decoder.u8()?,
                key => {
                    return Err(minicbor::decode::Error::message(format!(
                        "unknown acl policy field {key}"
                    )));
                }
            }
        }

        Ok(Self {
            tags: required_field(tags, "tags")?,
            rules: required_field(rules, "rules")?,
            default_action: required_field(default_action, "default_action")?,
            schema_version,
        })
    }
}

/// Rule action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Action {
    Drop = 0,
    Accept = 1,
}

impl<Ctx> Encode<Ctx> for Action {
    fn encode<W: Write>(
        &self,
        encoder: &mut Encoder<W>,
        _ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let value = match self {
            Self::Drop => 0,
            Self::Accept => 1,
        };
        encoder.u8(value)?;
        Ok(())
    }
}

impl<'b, Ctx> Decode<'b, Ctx> for Action {
    fn decode(decoder: &mut Decoder<'b>, _ctx: &mut Ctx) -> Result<Self, minicbor::decode::Error> {
        match decoder.u8()? {
            0 => Ok(Self::Drop),
            1 => Ok(Self::Accept),
            value => Err(minicbor::decode::Error::message(format!(
                "invalid action {value}"
            ))),
        }
    }
}

/// One ACL rule evaluated in first-match order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclRule {
    pub action: Action,
    pub src: Vec<Selector>,
    pub dst: Vec<Selector>,
    pub proto: Proto,
    pub ports: Option<Vec<PortSpec>>,
}

impl<Ctx> Encode<Ctx> for AclRule {
    fn encode<W: Write>(
        &self,
        encoder: &mut Encoder<W>,
        ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let mut field_count = 3;
        if self.proto != Proto::Wildcard {
            field_count += 1;
        }
        if self.ports.is_some() {
            field_count += 1;
        }

        encoder.map(field_count)?;
        encoder.u8(1)?;
        self.action.encode(encoder, ctx)?;
        encoder.u8(2)?;
        self.src.encode(encoder, ctx)?;
        encoder.u8(3)?;
        self.dst.encode(encoder, ctx)?;

        if self.proto != Proto::Wildcard {
            encoder.u8(4)?;
            self.proto.encode(encoder, ctx)?;
        }
        if let Some(ports) = &self.ports {
            encoder.u8(5)?;
            ports.encode(encoder, ctx)?;
        }

        Ok(())
    }
}

impl<'b, Ctx> Decode<'b, Ctx> for AclRule {
    fn decode(decoder: &mut Decoder<'b>, ctx: &mut Ctx) -> Result<Self, minicbor::decode::Error> {
        let len = decode_map_len(decoder, "acl rule")?;
        let mut action = None;
        let mut src = None;
        let mut dst = None;
        let mut proto = Proto::Wildcard;
        let mut ports = None;

        for _ in 0..len {
            match decoder.u64()? {
                1 => action = Some(Action::decode(decoder, ctx)?),
                2 => src = Some(Vec::<Selector>::decode(decoder, ctx)?),
                3 => dst = Some(Vec::<Selector>::decode(decoder, ctx)?),
                4 => proto = Proto::decode(decoder, ctx)?,
                5 => ports = Some(Vec::<PortSpec>::decode(decoder, ctx)?),
                key => {
                    return Err(minicbor::decode::Error::message(format!(
                        "unknown acl rule field {key}"
                    )));
                }
            }
        }

        Ok(Self {
            action: required_field(action, "action")?,
            src: required_field(src, "src")?,
            dst: required_field(dst, "dst")?,
            proto,
            ports,
        })
    }
}

/// Supported IP protocol selectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Proto {
    Wildcard = 0xff,
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
}

impl<Ctx> Encode<Ctx> for Proto {
    fn encode<W: Write>(
        &self,
        encoder: &mut Encoder<W>,
        _ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let value = match self {
            Self::Wildcard => 0xff,
            Self::Icmp => 1,
            Self::Tcp => 6,
            Self::Udp => 17,
        };
        encoder.u8(value)?;
        Ok(())
    }
}

impl<'b, Ctx> Decode<'b, Ctx> for Proto {
    fn decode(decoder: &mut Decoder<'b>, _ctx: &mut Ctx) -> Result<Self, minicbor::decode::Error> {
        match decoder.u8()? {
            0xff => Ok(Self::Wildcard),
            1 => Ok(Self::Icmp),
            6 => Ok(Self::Tcp),
            17 => Ok(Self::Udp),
            value => Err(minicbor::decode::Error::message(format!(
                "invalid proto {value}"
            ))),
        }
    }
}

/// One port or a closed port range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortSpec {
    Single(u16),
    Range(u16, u16),
}

impl<Ctx> Encode<Ctx> for PortSpec {
    fn encode<W: Write>(
        &self,
        encoder: &mut Encoder<W>,
        _ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::Single(port) => {
                encoder.u16(*port)?;
            }
            Self::Range(low, high) => {
                encoder.array(2)?;
                encoder.u16(*low)?;
                encoder.u16(*high)?;
            }
        }
        Ok(())
    }
}

impl<'b, Ctx> Decode<'b, Ctx> for PortSpec {
    fn decode(decoder: &mut Decoder<'b>, _ctx: &mut Ctx) -> Result<Self, minicbor::decode::Error> {
        match decoder.datatype()? {
            Type::U8 | Type::U16 | Type::U32 | Type::U64 => Ok(Self::Single(decoder.u16()?)),
            Type::Array => {
                decode_array_len(decoder, "port range", 2)?;
                let low = decoder.u16()?;
                let high = decoder.u16()?;
                Ok(Self::Range(low, high))
            }
            ty => Err(minicbor::decode::Error::message(format!(
                "invalid port spec type {ty:?}"
            ))),
        }
    }
}

/// Supported ACL selectors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Selector {
    Wildcard,
    Tag(TagName),
    Device(DeviceFingerprint),
    Subnet(Cidr),
    Hostname(HostnameLabel),
}

impl<Ctx> Encode<Ctx> for Selector {
    fn encode<W: Write>(
        &self,
        encoder: &mut Encoder<W>,
        ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::Wildcard => {
                encoder.u8(0)?;
            }
            Self::Tag(tag) => {
                encoder.array(2)?;
                encoder.u8(1)?;
                tag.encode(encoder, ctx)?;
            }
            Self::Device(fingerprint) => {
                encoder.array(2)?;
                encoder.u8(2)?;
                fingerprint.encode(encoder, ctx)?;
            }
            Self::Subnet(cidr) => {
                encoder.array(2)?;
                encoder.u8(3)?;
                cidr.encode(encoder, ctx)?;
            }
            Self::Hostname(name) => {
                encoder.array(2)?;
                encoder.u8(4)?;
                encoder.str(name.as_str())?;
            }
        }
        Ok(())
    }
}

impl<'b, Ctx> Decode<'b, Ctx> for Selector {
    fn decode(decoder: &mut Decoder<'b>, ctx: &mut Ctx) -> Result<Self, minicbor::decode::Error> {
        match decoder.datatype()? {
            Type::U8 | Type::U16 | Type::U32 | Type::U64 => match decoder.u8()? {
                0 => Ok(Self::Wildcard),
                value => Err(minicbor::decode::Error::message(format!(
                    "invalid wildcard selector {value}"
                ))),
            },
            Type::Array => {
                decode_array_len(decoder, "selector", 2)?;
                match decoder.u8()? {
                    1 => Ok(Self::Tag(TagName::decode(decoder, ctx)?)),
                    2 => Ok(Self::Device(DeviceFingerprint::decode(decoder, ctx)?)),
                    3 => Ok(Self::Subnet(Cidr::decode(decoder, ctx)?)),
                    4 => {
                        let raw = decoder.str()?;
                        let name = HostnameLabel::try_from_str(raw)
                            .map_err(|err| minicbor::decode::Error::message(err.to_string()))?;
                        Ok(Self::Hostname(name))
                    }
                    kind => Err(minicbor::decode::Error::message(format!(
                        "invalid selector kind {kind}"
                    ))),
                }
            }
            ty => Err(minicbor::decode::Error::message(format!(
                "invalid selector type {ty:?}"
            ))),
        }
    }
}

/// Validated tag name with D9-C charset rules.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TagName(String);

impl TagName {
    /// Parse and validate a tag name.
    pub fn try_from_str(s: &str) -> Result<Self, TagNameError> {
        let len = s.len();
        if !(1..=MAX_TAG_NAME_LEN).contains(&len) {
            return Err(TagNameError::Length(len));
        }

        for byte in s.bytes() {
            let valid = byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-');
            if !valid {
                return Err(TagNameError::Charset(byte));
            }
        }

        Ok(Self(s.to_owned()))
    }

    /// Borrow the validated string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TagName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for TagName {
    type Err = TagNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from_str(s)
    }
}

impl<Ctx> Encode<Ctx> for TagName {
    fn encode<W: Write>(
        &self,
        encoder: &mut Encoder<W>,
        _ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.str(&self.0)?;
        Ok(())
    }
}

impl<'b, Ctx> Decode<'b, Ctx> for TagName {
    fn decode(decoder: &mut Decoder<'b>, _ctx: &mut Ctx) -> Result<Self, minicbor::decode::Error> {
        let raw = decoder.str()?;
        Self::try_from_str(raw).map_err(|err| minicbor::decode::Error::message(err.to_string()))
    }
}

/// Tag-name validation error.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum TagNameError {
    #[error("tag name must be 1..=32 bytes, got {0}")]
    Length(usize),
    #[error("tag name contains invalid byte 0x{0:02x} (allowed: [A-Za-z0-9_.-])")]
    Charset(u8),
}

/// SHA-256 fingerprint of a device public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeviceFingerprint(pub [u8; 32]);

impl DeviceFingerprint {
    /// Build from raw 32 bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl<Ctx> Encode<Ctx> for DeviceFingerprint {
    fn encode<W: Write>(
        &self,
        encoder: &mut Encoder<W>,
        _ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.bytes(&self.0)?;
        Ok(())
    }
}

impl<'b, Ctx> Decode<'b, Ctx> for DeviceFingerprint {
    fn decode(decoder: &mut Decoder<'b>, _ctx: &mut Ctx) -> Result<Self, minicbor::decode::Error> {
        let bytes = decoder.bytes()?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| minicbor::decode::Error::message("device fingerprint must be 32 bytes"))?;
        Ok(Self(bytes))
    }
}

/// CIDR selector payload stored as `[addr_bytes, prefix_len]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl Cidr {
    /// Build a CIDR wrapper from address + prefix.
    pub const fn new(addr: IpAddr, prefix_len: u8) -> Self {
        Self { addr, prefix_len }
    }
}

impl<Ctx> Encode<Ctx> for Cidr {
    fn encode<W: Write>(
        &self,
        encoder: &mut Encoder<W>,
        _ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(2)?;
        match self.addr {
            IpAddr::V4(addr) => encoder.bytes(&addr.octets())?,
            IpAddr::V6(addr) => encoder.bytes(&addr.octets())?,
        };
        encoder.u8(self.prefix_len)?;
        Ok(())
    }
}

impl<'b, Ctx> Decode<'b, Ctx> for Cidr {
    fn decode(decoder: &mut Decoder<'b>, _ctx: &mut Ctx) -> Result<Self, minicbor::decode::Error> {
        decode_array_len(decoder, "cidr", 2)?;
        let bytes = decoder.bytes()?;
        let addr = match bytes.len() {
            4 => IpAddr::from(<[u8; 4]>::try_from(bytes).expect("length checked")),
            16 => IpAddr::from(<[u8; 16]>::try_from(bytes).expect("length checked")),
            len => {
                return Err(minicbor::decode::Error::message(format!(
                    "cidr address bytes must be 4 or 16 bytes, got {len}"
                )));
            }
        };
        let prefix_len = decoder.u8()?;
        Ok(Self { addr, prefix_len })
    }
}

fn decode_array_len(
    decoder: &mut Decoder<'_>,
    name: &str,
    expected: u64,
) -> Result<(), minicbor::decode::Error> {
    let len = decoder.array()?.ok_or_else(|| {
        minicbor::decode::Error::message(format!("indefinite {name} not supported"))
    })?;
    if len != expected {
        return Err(minicbor::decode::Error::message(format!(
            "{name} must have {expected} items, got {len}"
        )));
    }
    Ok(())
}

fn decode_map_len(decoder: &mut Decoder<'_>, name: &str) -> Result<u64, minicbor::decode::Error> {
    decoder
        .map()?
        .ok_or_else(|| minicbor::decode::Error::message(format!("indefinite {name} not supported")))
}

fn required_field<T>(value: Option<T>, name: &str) -> Result<T, minicbor::decode::Error> {
    value.ok_or_else(|| minicbor::decode::Error::message(format!("missing field {name}")))
}
