//! `HostnameLabel`: DNS-LDH label embedded into a `MemberCert` (D14-A).
//!
//! Charset `[a-z0-9-]`, length 1..=63, no leading/trailing `-`.
//! Uppercase input is normalized to lowercase before validation.
//! Uniqueness within `(trust_domain_id, network_local_id)` is enforced
//! at signing time by the trust-domain root (T-034 / VR12).
//!
//! See `trust-and-config-design.md` §6.2 / §18 and
//! `acl-schema-draft.md` §10.

use thiserror::Error;

use super::types::MemberCertFingerprint;

/// Validated DNS-LDH label, lowercase-normalized, 1..=63 bytes.
#[derive(
    serde::Serialize,
    serde::Deserialize,
    minicbor::Encode,
    minicbor::Decode,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
)]
pub struct HostnameLabel(#[n(0)] pub String);

impl HostnameLabel {
    /// Parse, lowercase-normalize and validate. Returns `HostnameError` on violation.
    pub fn try_from_str(s: &str) -> Result<Self, HostnameError> {
        if s.is_empty() {
            return Err(HostnameError::Empty);
        }

        let normalized = s.to_ascii_lowercase();
        let len = normalized.len();
        if !(1..=63).contains(&len) {
            return Err(HostnameError::Length(len));
        }
        if normalized.starts_with('-') || normalized.ends_with('-') {
            return Err(HostnameError::EdgeHyphen);
        }

        for byte in normalized.bytes() {
            let valid = byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-';
            if !valid {
                return Err(HostnameError::Charset(byte));
            }
        }

        Ok(Self(normalized))
    }

    /// Borrow the underlying lowercase string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for HostnameLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for HostnameLabel {
    type Err = HostnameError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from_str(s)
    }
}

/// Validation / uniqueness errors for `HostnameLabel`.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum HostnameError {
    #[error("hostname must be 1..=63 bytes, got {0}")]
    Length(usize),
    #[error("hostname contains invalid byte 0x{0:02x} (allowed: [a-z0-9-])")]
    Charset(u8),
    #[error("hostname must not begin or end with '-'")]
    EdgeHyphen,
    #[error("hostname empty")]
    Empty,
    #[error("hostname '{name}' already taken by cert {taken_by:?}")]
    Conflict {
        name: String,
        taken_by: MemberCertFingerprint,
    },
}

/// Pure check: would `new` collide with any live (non-revoked, non-expired) entry?
///
/// `existing_live` is a slice the caller assembled from the current network's
/// member-cert index (already filtered against `revoked_certs` / `expires_at`).
/// `disabled` certs **still occupy** their hostname per design §6.2.
pub fn check_hostname_unique(
    new: &HostnameLabel,
    existing_live: &[(MemberCertFingerprint, Option<HostnameLabel>)],
) -> Result<(), HostnameError> {
    for (fingerprint, existing) in existing_live {
        if existing.as_ref() == Some(new) {
            return Err(HostnameError::Conflict {
                name: new.as_str().to_owned(),
                taken_by: *fingerprint,
            });
        }
    }

    Ok(())
}
