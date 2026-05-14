//! Revocation and disable lists (`network_state.payload.revoked_certs` / `disabled_certs`).
//!
//! See `trust-and-config-design.md` §10. Revoke is permanent; disable is reversible.

use super::types::MemberCertFingerprint;

/// Reason codes (RFC 5280 §5.3.1 inspired). Audit-only; not used by node verification.
#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, Copy, PartialEq, Eq)]
#[cbor(index_only)]
pub enum RevocationReason {
    #[n(0)]
    Unspecified,
    #[n(1)]
    KeyCompromise,
    #[n(2)]
    DeviceLost,
    #[n(3)]
    Removed,
    #[n(4)]
    Superseded,
}

/// Permanently revoked certificate entry.
#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq)]
pub struct RevokedCert {
    #[n(0)]
    pub cert_fingerprint: MemberCertFingerprint,
    #[n(1)]
    pub revoked_at: u64,
    #[n(2)]
    pub reason_code: RevocationReason,
    #[n(3)]
    pub reason_note: Option<String>,
}

impl RevokedCert {
    /// Revoked entries are unconditionally active (no recovery).
    pub fn is_active_at(&self, _now: u64) -> bool {
        true
    }
}

/// Temporarily disabled certificate entry.
#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq)]
pub struct DisabledCert {
    #[n(0)]
    pub cert_fingerprint: MemberCertFingerprint,
    #[n(1)]
    pub disabled_at: u64,
    #[n(2)]
    pub expected_until: Option<u64>,
    #[n(3)]
    pub reason_note: Option<String>,
}

impl DisabledCert {
    /// Disabled entries are inactive once `expected_until` < `now` (auto-recovery).
    pub fn is_active_at(&self, now: u64) -> bool {
        self.expected_until
            .is_none_or(|expected_until| expected_until >= now)
    }
}
