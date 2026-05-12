//! Cross-trust-domain relay borrowing (placeholder).
//!
//! See `trust-and-config-design.md` §3.5 / §11.9 and the M3 implementation
//! tasks T-110 (RelayGrantTable), T-111 (BorrowedRelayProof),
//! T-112 (BorrowedRelayResolver). The full byte layout is not finalized
//! until M3; this module exists in M0 only to anchor type names referenced
//! by the rest of the trust layer.

use super::member_cert::MemberCert;
use super::pool::TrustDomainPool;
use super::trust_domain_meta::RelayCapabilities;
use super::types::TrustDomainId;
use ed25519_dalek::VerifyingKey;
use url::Url;

/// Per-relay grant: which trust domains the local relay node will serve.
///
/// Lives on a relay node's local config (out-of-band coordination with the
/// borrowing trust-domain root, §3.5). NOT a wire type.
#[derive(Debug, Clone)]
pub struct RelayGrantTable {
    entries: Vec<RelayGrantEntry>,
}

/// One relay-serving grant entry for a foreign trust domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayGrantEntry {
    pub foreign_root_pk: TrustDomainId,
    pub capabilities: RelayCapabilities,
    pub expires_at: u64,
}

impl RelayGrantTable {
    pub fn from_entries(entries: Vec<RelayGrantEntry>) -> Self {
        Self { entries }
    }

    pub fn empty() -> Self {
        Self { entries: Vec::new() }
    }

    /// Returns grant capabilities iff the trust domain is permitted and not expired.
    pub fn permits(&self, td: &TrustDomainId, now: u64) -> Option<&RelayCapabilities> {
        self.entries
            .iter()
            .find(|entry| &entry.foreign_root_pk == td && entry.expires_at > now)
            .map(|entry| &entry.capabilities)
    }
}

/// Proof a session-initiator presents to a borrowed relay.
#[derive(Debug, Clone, minicbor::Encode, minicbor::Decode, PartialEq, Eq)]
pub struct BorrowedRelayProof {
    #[n(0)]
    pub trust_domain_id: TrustDomainId,
    #[n(1)]
    pub member_cert: MemberCert,
    #[n(2)]
    pub timestamp: u64,
}

/// One relay candidate discovered for a foreign trust domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCandidate {
    pub relay_url: Url,
    pub foreign_trust_domain_id: TrustDomainId,
    pub foreign_root_pk: VerifyingKey,
}

/// Relay-side resolver: validates `BorrowedRelayProof` against the relay's
/// `RelayGrantTable` + locally cached `PK_root`s.
#[derive(Debug, Clone)]
pub struct BorrowedRelayResolver;

impl BorrowedRelayResolver {
    pub fn validate(
        &self,
        proof: &BorrowedRelayProof,
        relay_grants: &RelayGrantTable,
        now: u64,
    ) -> Result<TrustDomainId, BorrowedRelayError> {
        if relay_grants.permits(&proof.trust_domain_id, now).is_none() {
            return Err(BorrowedRelayError::NotServing(proof.trust_domain_id));
        }
        if proof.member_cert.details.expires_at <= now {
            return Err(BorrowedRelayError::Expired);
        }
        if proof.timestamp.abs_diff(now) > 300 {
            return Err(BorrowedRelayError::BadTimestamp);
        }

        Ok(proof.trust_domain_id)
    }

    pub fn candidates_for_target(
        target_trust_domain_id: &TrustDomainId,
        trust_pool: &TrustDomainPool,
    ) -> Vec<RelayCandidate> {
        let Some(meta) = trust_pool.trust_domain_meta(target_trust_domain_id) else {
            return Vec::new();
        };
        let Some(seeds) = trust_pool.bootstrap_seeds(target_trust_domain_id) else {
            return Vec::new();
        };
        let Some(root_pk) = trust_pool.root_verify_key(target_trust_domain_id) else {
            return Vec::new();
        };
        let Ok(foreign_root_pk) = VerifyingKey::from_bytes(&root_pk.0) else {
            return Vec::new();
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        let has_active_relay = meta.details.active_relays.iter().any(|relay| {
            relay.capabilities.can_relay_data && relay.expires_at > now
        });
        if !has_active_relay {
            return Vec::new();
        }

        seeds
            .iter()
            .cloned()
            .map(|relay_url| RelayCandidate {
                relay_url,
                foreign_trust_domain_id: *target_trust_domain_id,
                foreign_root_pk,
            })
            .collect()
    }
}

/// `BorrowedRelayResolver` errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BorrowedRelayError {
    /// Trust-domain id is not on this relay's whitelist.
    NotServing(TrustDomainId),
    /// `trust_domain_meta` signature failed.
    BadMeta,
    /// `member_cert` signature or field check failed.
    BadCert,
    /// `expires_at` reached.
    Expired,
    /// Borrowed proof timestamp skew exceeds the allowed window.
    BadTimestamp,
}
