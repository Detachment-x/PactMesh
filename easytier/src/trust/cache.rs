//! `CachedMemberCert`: post-verification, pre-computed cert handle.
//!
//! Mirrors Nebula's `CachedCertificate`. Holds the verified `MemberCert`
//! plus pre-computed quantities (fingerprint, signer id, normalized
//! proxy-subnet set) so hot-path lookups don't re-parse the cert.

use std::collections::BTreeSet;

use pnet::ipnetwork::IpNetwork as IpNet;

use super::member_cert::MemberCert;
use super::types::{MemberCertFingerprint, TrustDomainId};

/// Post-verification cached cert. Holds canonical fingerprint and
/// pre-computed proxy-subnet set for quick `selector_match` lookups.
#[derive(Debug, Clone)]
pub struct CachedMemberCert {
    pub cert: MemberCert,
    pub fingerprint: MemberCertFingerprint,
    pub signer_id: TrustDomainId,
    /// Canonicalized CIDRs from `Capabilities::can_proxy_subnet`.
    pub proxy_subnets_set: BTreeSet<IpNet>,
}

impl CachedMemberCert {
    /// Build from a verified cert + the trust-domain id of its signer.
    pub fn from_verified(cert: MemberCert, signer_id: TrustDomainId) -> Self {
        let fingerprint = cert.fingerprint();
        let proxy_subnets_set = cert
            .details
            .capabilities
            .can_proxy_subnet
            .iter()
            .copied()
            .collect();

        Self {
            cert,
            fingerprint,
            signer_id,
            proxy_subnets_set,
        }
    }

    /// Active iff `cert.details.not_before <= now < cert.details.expires_at`.
    pub fn is_active_at(&self, now: u64) -> bool {
        self.cert.details.not_before <= now && now < self.cert.details.expires_at
    }
}
