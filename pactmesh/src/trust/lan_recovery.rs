//! Trust validation for opportunistic LAN recovery.
//!
//! LAN discovery only yields candidates. Any recovered state must still be root-signed
//! and scoped to the local trust domain / network before it can influence reconnects.

use thiserror::Error;

use super::{NetworkLocalId, SignedNetworkState, TrustDomainId, TrustDomainPool};
use crate::trust::pool::PoolApplyError;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum LanRecoveryError {
    #[error("trust_domain_id mismatch")]
    TrustDomainMismatch,
    #[error("network_local_id mismatch")]
    NetworkMismatch,
    #[error("pool apply failed: {0}")]
    PoolApply(#[from] PoolApplyError),
}

/// Apply a network state obtained from a LAN peer after validating local scope.
pub fn apply_lan_recovered_network_state(
    pool: &mut TrustDomainPool,
    expected_trust_domain_id: &TrustDomainId,
    expected_network_local_id: &NetworkLocalId,
    state: SignedNetworkState,
) -> Result<(), LanRecoveryError> {
    if &state.details.trust_domain_id != expected_trust_domain_id {
        return Err(LanRecoveryError::TrustDomainMismatch);
    }
    if &state.details.network_local_id != expected_network_local_id {
        return Err(LanRecoveryError::NetworkMismatch);
    }
    pool.apply_network_state(state)?;
    Ok(())
}
