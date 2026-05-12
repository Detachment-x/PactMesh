//! `TrustDomainPool`: the in-process state cache for one node.
//!
//! Holds `(PK_root, latest network_state per network, latest trust_domain_meta)`
//! per trust domain, mirroring Nebula's `CAPool` but organized around the
//! self-managed-domain model (no parent CA, multiple peer trust domains).
//!
//! See `trust-and-config-design.md` §6.5 / §7 / §11.2 / §11.6.

use std::collections::BTreeMap;

use ed25519_dalek::VerifyingKey;
use thiserror::Error;

use super::cache::CachedMemberCert;
use super::network_bootstrap::NetworkBootstrap;
use super::identity::VerifyKey;
use super::member_cert::{MemberCert, VerifyError as MemberCertVerifyError};
use super::network_state::SignedNetworkState;
use super::trust_domain_meta::SignedTrustDomainMeta;
use super::types::{NetworkLocalId, TrustDomainId};

/// One trust-domain entry inside the pool.
#[derive(Debug, Clone)]
pub struct TrustDomainEntry {
    pub pk_root: VerifyKey,
    pub trust_domain_meta: Option<SignedTrustDomainMeta>,
    pub network_bootstrap: Option<NetworkBootstrap>,
    /// Latest accepted `network_state` per local network id.
    pub networks: BTreeMap<NetworkLocalId, SignedNetworkState>,
}

/// Multi-domain in-process pool. Routing is by `cert.trust_domain_id`.
#[derive(Debug, Clone, Default)]
pub struct TrustDomainPool {
    domains: BTreeMap<TrustDomainId, TrustDomainEntry>,
}

impl TrustDomainPool {
    /// Empty pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new trust-domain root. Returns the derived id.
    pub fn add_root(&mut self, pk: VerifyKey) -> TrustDomainId {
        let id = TrustDomainId::from_root_pubkey(
            &ed25519_dalek::VerifyingKey::from_bytes(&pk.0)
                .expect("stored public key must be valid"),
        );
        self.domains.entry(id).or_insert_with(|| TrustDomainEntry {
            pk_root: pk,
            trust_domain_meta: None,
            network_bootstrap: None,
            networks: BTreeMap::new(),
        });
        id
    }

    /// Apply a `SignedNetworkState`: verify, monotonicity-check, swap in.
    pub fn apply_network_state(
        &mut self,
        state: SignedNetworkState,
    ) -> Result<(), PoolApplyError> {
        let entry = self
            .domains
            .get_mut(&state.details.trust_domain_id)
            .ok_or(PoolApplyError::UnknownDomain)?;
        state
            .verify(&entry.pk_root)
            .map_err(|_| PoolApplyError::BadSignature)?;

        let network_local_id = state.details.network_local_id.clone();
        if let Some(existing) = entry.networks.get(&network_local_id)
            && state.details.version <= existing.details.version
        {
            return Err(PoolApplyError::StaleVersion {
                have: existing.details.version,
                got: state.details.version,
            });
        }

        entry.networks.insert(network_local_id, state);
        Ok(())
    }

    /// Apply a `SignedTrustDomainMeta`: verify, monotonicity-check, swap in.
    pub fn apply_trust_domain_meta(
        &mut self,
        meta: SignedTrustDomainMeta,
    ) -> Result<(), PoolApplyError> {
        let entry = self
            .domains
            .get_mut(&meta.details.trust_domain_id)
            .ok_or(PoolApplyError::UnknownDomain)?;
        meta.verify(&entry.pk_root)
            .map_err(|_| PoolApplyError::BadSignature)?;

        if let Some(existing) = &entry.trust_domain_meta
            && meta.details.version <= existing.details.version
        {
            return Err(PoolApplyError::StaleVersion {
                have: existing.details.version,
                got: meta.details.version,
            });
        }

        entry.trust_domain_meta = Some(meta);
        Ok(())
    }


    /// Cache one network bootstrap for a trust domain.
    pub fn apply_network_bootstrap(
        &mut self,
        td: &TrustDomainId,
        bootstrap: NetworkBootstrap,
    ) -> Result<(), PoolApplyError> {
        if &bootstrap.trust_domain_id != td {
            return Err(PoolApplyError::BadSignature);
        }
        bootstrap
            .verify_self_consistency()
            .map_err(|_| PoolApplyError::BadSignature)?;

        let entry = self.domains.get_mut(td).ok_or(PoolApplyError::UnknownDomain)?;
        entry.network_bootstrap = Some(bootstrap);
        Ok(())
    }

    /// Run the full §7.3 verification pipeline; produce a `CachedMemberCert` on success.
    pub fn verify_member_cert(
        &self,
        cert: &MemberCert,
        now: u64,
    ) -> Result<CachedMemberCert, PoolVerifyError> {
        let entry = self
            .domains
            .get(&cert.details.trust_domain_id)
            .ok_or(PoolVerifyError::UnknownDomain)?;
        let root_pk = ed25519_dalek::VerifyingKey::from_bytes(&entry.pk_root.0)
            .expect("stored public key must be valid");
        Self::verify_cert_against_root_pk(cert, &root_pk, now)?;

        let state = entry
            .networks
            .get(&cert.details.network_local_id)
            .ok_or(PoolVerifyError::NoNetworkState {
                td: cert.details.trust_domain_id,
                nlid: cert.details.network_local_id.clone(),
            })?;

        if cert.details.network_state_version_ref > state.details.version {
            return Err(PoolVerifyError::FutureVersionRef {
                have: state.details.version,
                got: cert.details.network_state_version_ref,
            });
        }
        if cert.details.expires_at <= now {
            return Err(PoolVerifyError::Expired {
                now,
                ea: cert.details.expires_at,
            });
        }

        let fingerprint = cert.fingerprint();
        if state
            .details
            .payload
            .revoked_certs
            .iter()
            .any(|revoked| revoked.cert_fingerprint == fingerprint && revoked.is_active_at(now))
        {
            return Err(PoolVerifyError::Revoked);
        }
        if state
            .details
            .payload
            .disabled_certs
            .iter()
            .any(|disabled| disabled.cert_fingerprint == fingerprint && disabled.is_active_at(now))
        {
            return Err(PoolVerifyError::Disabled);
        }

        Ok(CachedMemberCert::from_verified(
            cert.clone(),
            cert.details.trust_domain_id,
        ))
    }

    /// Verify a cert against an externally supplied trust-domain root key.
    pub fn verify_with_external_root(
        &self,
        cert: &MemberCert,
        external_root_pk: &VerifyingKey,
        now_unix: u64,
    ) -> Result<(), TrustDomainPoolError> {
        Self::verify_cert_against_root_pk(cert, external_root_pk, now_unix)
    }

    /// Iterate over registered trust-domain ids.
    pub fn ids(&self) -> impl Iterator<Item = &TrustDomainId> {
        self.domains.keys()
    }

    /// Return the configured root verify key for one trust domain.
    pub fn root_verify_key(&self, td: &TrustDomainId) -> Option<&VerifyKey> {
        self.domains.get(td).map(|entry| &entry.pk_root)
    }

    /// Return the cached signed trust-domain metadata for one trust domain.
    pub fn trust_domain_meta(&self, td: &TrustDomainId) -> Option<&SignedTrustDomainMeta> {
        self.domains
            .get(td)
            .and_then(|entry| entry.trust_domain_meta.as_ref())
    }

    /// Return cached bootstrap seeds for one trust domain.
    pub fn bootstrap_seeds(&self, td: &TrustDomainId) -> Option<&[url::Url]> {
        self.domains
            .get(td)
            .and_then(|entry| entry.network_bootstrap.as_ref())
            .map(|bootstrap| bootstrap.bootstrap_seeds.as_slice())
    }

    /// Return the cached signed network state for one `(trust_domain_id, network_local_id)`.
    pub fn network_state(
        &self,
        td: &TrustDomainId,
        network_local_id: &NetworkLocalId,
    ) -> Option<&SignedNetworkState> {
        self.domains
            .get(td)
            .and_then(|entry| entry.networks.get(network_local_id))
    }

    /// Snapshot the known network-local ids for one trust domain.
    pub fn network_local_ids(&self, td: &TrustDomainId) -> Vec<NetworkLocalId> {
        self.domains
            .get(td)
            .map(|entry| entry.networks.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn verify_cert_against_root_pk(
        cert: &MemberCert,
        root_pk: &VerifyingKey,
        now: u64,
    ) -> Result<(), PoolVerifyError> {
        cert.verify(root_pk).map_err(|err| match err {
            MemberCertVerifyError::BadSignature
            | MemberCertVerifyError::BadTimeWindow { .. }
            | MemberCertVerifyError::DomainMismatch => PoolVerifyError::BadSignature,
            MemberCertVerifyError::Expired { now, ea } => PoolVerifyError::Expired { now, ea },
            MemberCertVerifyError::FutureVersionRef { have, got } => {
                PoolVerifyError::FutureVersionRef { have, got }
            }
        })?;

        if cert.details.expires_at <= now {
            return Err(PoolVerifyError::Expired {
                now,
                ea: cert.details.expires_at,
            });
        }

        Ok(())
    }
}

pub type TrustDomainPoolError = PoolVerifyError;

/// `apply_*` failure modes.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PoolApplyError {
    #[error("trust domain not registered")]
    UnknownDomain,
    #[error("signature mismatch")]
    BadSignature,
    #[error("version regressed: have {have}, got {got}")]
    StaleVersion { have: u64, got: u64 },
}

/// `verify_member_cert` failure modes (mirror §7.3 ordering).
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PoolVerifyError {
    #[error("trust domain not registered")]
    UnknownDomain,
    #[error("signature mismatch")]
    BadSignature,
    #[error("network_state_version_ref {got} > local {have}")]
    FutureVersionRef { have: u64, got: u64 },
    #[error("expired (now {now} >= expires_at {ea})")]
    Expired { now: u64, ea: u64 },
    #[error("revoked")]
    Revoked,
    #[error("disabled")]
    Disabled,
    #[error("no network_state cached for ({td:?}, {nlid})")]
    NoNetworkState {
        td: TrustDomainId,
        nlid: NetworkLocalId,
    },
}
