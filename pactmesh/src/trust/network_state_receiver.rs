use std::path::{Path, PathBuf};

use thiserror::Error;
use tokio::sync::RwLock;

use super::{NetworkLocalId, SignedNetworkState, TrustDomainId, TrustDomainPool};
use crate::trust::pool::PoolApplyError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkStateReceiveReport {
    pub source: String,
    pub trust_domain_id: TrustDomainId,
    pub network_local_id: NetworkLocalId,
    pub old_version: Option<u64>,
    pub new_version: u64,
    pub persisted_path: Option<PathBuf>,
}

#[derive(Error, Debug)]
pub enum NetworkStateReceiveError {
    #[error("trust_domain_id mismatch")]
    TrustDomainMismatch,
    #[error("network_local_id mismatch")]
    NetworkLocalIdMismatch,
    #[error("pool apply failed: {0}")]
    PoolApply(#[from] PoolApplyError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub async fn receive_network_state(
    pool: &RwLock<TrustDomainPool>,
    expected_trust_domain_id: &TrustDomainId,
    expected_network_local_id: &NetworkLocalId,
    state: SignedNetworkState,
    persist_domain_dir: Option<&Path>,
    source: impl Into<String>,
) -> Result<NetworkStateReceiveReport, NetworkStateReceiveError> {
    if &state.details.trust_domain_id != expected_trust_domain_id {
        return Err(NetworkStateReceiveError::TrustDomainMismatch);
    }
    if &state.details.network_local_id != expected_network_local_id {
        return Err(NetworkStateReceiveError::NetworkLocalIdMismatch);
    }

    let trust_domain_id = state.details.trust_domain_id;
    let network_local_id = state.details.network_local_id.clone();
    let new_version = state.details.version;

    let mut guard = pool.write().await;
    let old_version = guard
        .network_state(&trust_domain_id, &network_local_id)
        .map(|existing| existing.details.version);
    guard.apply_network_state(state.clone())?;

    let persisted_path = match persist_domain_dir {
        Some(domain_dir) => {
            let path = network_state_path(domain_dir, &network_local_id);
            persist_network_state(&path, &state)?;
            Some(path)
        }
        None => None,
    };
    drop(guard);

    let report = NetworkStateReceiveReport {
        source: source.into(),
        trust_domain_id,
        network_local_id,
        old_version,
        new_version,
        persisted_path,
    };
    tracing::info!(
        source = %report.source,
        trust_domain_id = %report.trust_domain_id,
        network_local_id = %report.network_local_id,
        old_version = ?report.old_version,
        new_version = report.new_version,
        persist_path = ?report.persisted_path,
        "accepted network_state update"
    );
    Ok(report)
}

pub fn network_state_path(domain_dir: &Path, network_local_id: &NetworkLocalId) -> PathBuf {
    domain_dir
        .join("networks")
        .join(network_local_id.as_str())
        .join("network_state.cbor.pem")
}

fn persist_network_state(path: &Path, state: &SignedNetworkState) -> Result<(), std::io::Error> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "network_state path has no parent directory",
        )
    })?;
    std::fs::create_dir_all(parent)?;
    let tmp_path = path.with_extension("cbor.pem.tmp");
    std::fs::write(&tmp_path, state.to_pem())?;
    std::fs::rename(tmp_path, path)?;
    Ok(())
}
