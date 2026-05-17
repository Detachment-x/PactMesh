//! Core newtypes and the unified `TrustError` enum.
//!
//! See `trust-and-config-design.md` §6 for wire-format scope and
//! `acl-schema-draft.md` §3 for related ACL types.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// 32-byte SHA-256 of the trust-domain root public key. Identifies a trust domain.
#[derive(
    minicbor::Encode, minicbor::Decode, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct TrustDomainId(
    #[n(0)]
    #[cbor(with = "minicbor::bytes")]
    pub [u8; 32],
);

impl TrustDomainId {
    /// Build a `TrustDomainId` from an ed25519 root pubkey via SHA-256.
    pub fn from_root_pubkey(pk: &VerifyingKey) -> Self {
        Self(Sha256::digest(pk.as_bytes()).into())
    }

    /// Render as base64 (URL-safe, no padding) for human display.
    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for TrustDomainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base64())
    }
}

/// 32-byte SHA-256 fingerprint of a serialized `MemberCert`.
#[derive(
    minicbor::Encode, minicbor::Decode, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord,
)]
pub struct MemberCertFingerprint(
    #[n(0)]
    #[cbor(with = "minicbor::bytes")]
    pub [u8; 32],
);

impl MemberCertFingerprint {
    /// Compute fingerprint from canonical-CBOR cert bytes.
    pub fn from_cert_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Render as base64 for human display.
    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for MemberCertFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base64())
    }
}

/// Trust-domain-local network name. LDH charset, 1..=63 bytes, no leading/trailing `-`.
#[derive(
    minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord,
)]
pub struct NetworkLocalId(#[n(0)] pub String);

impl NetworkLocalId {
    /// Parse and validate. Returns `NetworkLocalIdError` on charset / length violation.
    pub fn try_from_str(s: &str) -> Result<Self, NetworkLocalIdError> {
        let len = s.len();
        if !(1..=63).contains(&len) {
            return Err(NetworkLocalIdError::Length(len));
        }
        if s.starts_with('-') || s.ends_with('-') {
            return Err(NetworkLocalIdError::EdgeHyphen);
        }
        for byte in s.bytes() {
            let valid = byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-';
            if !valid {
                return Err(NetworkLocalIdError::Charset(byte));
            }
        }
        Ok(Self(s.to_owned()))
    }

    /// Borrow the underlying validated string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NetworkLocalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for NetworkLocalId {
    type Err = NetworkLocalIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from_str(s)
    }
}

/// Validation error for `NetworkLocalId`.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum NetworkLocalIdError {
    #[error("network_local_id must be 1..=63 bytes, got {0}")]
    Length(usize),
    #[error("network_local_id contains invalid byte 0x{0:02x} (allowed: [a-z0-9-])")]
    Charset(u8),
    #[error("network_local_id must not begin or end with '-'")]
    EdgeHyphen,
}

/// Top-level error for the trust layer; sub-modules map their errors here.
#[derive(Error, Debug)]
pub enum TrustError {
    #[error("CBOR encode/decode: {0}")]
    Cbor(String),
    #[error("PEM armor: {0}")]
    Armor(String),
    #[error("identity I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("identity seal/unseal: {0}")]
    Seal(String),
    #[error("signature verification failed")]
    BadSignature,
    #[error("certificate field invariant violated: {0}")]
    BadCert(String),
    #[error("cert revoked: {0:?}")]
    Revoked(MemberCertFingerprint),
    #[error("cert disabled: {0:?}")]
    Disabled(MemberCertFingerprint),
    #[error("network_local_id: {0}")]
    NetworkLocalId(#[from] NetworkLocalIdError),
    #[error("hostname: {0}")]
    Hostname(#[from] crate::trust::hostname::HostnameError),
    #[error("trust domain not registered for id {0:?}")]
    UnknownTrustDomain(TrustDomainId),
    #[error("network_state version regressed: have {have}, got {got}")]
    StaleVersion { have: u64, got: u64 },
}
