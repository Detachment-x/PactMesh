use std::path::{Path, PathBuf};

use thiserror::Error;
use tokio::sync::RwLock;

use super::{
    SignedTrustDomainMeta, TrustDomainId, TrustDomainPool, to_canonical_cbor, wrap_armored,
};
use crate::trust::pool::PoolApplyError;

pub const TRUST_DOMAIN_META_PEM_LABEL: &str = "PNW-TRUST-DOMAIN-META";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustDomainMetaReceiveReport {
    pub source: String,
    pub trust_domain_id: TrustDomainId,
    pub old_version: Option<u64>,
    pub new_version: u64,
    pub persisted_path: Option<PathBuf>,
}

#[derive(Error, Debug)]
pub enum TrustDomainMetaReceiveError {
    #[error("trust_domain_id mismatch")]
    TrustDomainMismatch,
    #[error("pool apply failed: {0}")]
    PoolApply(#[from] PoolApplyError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub async fn receive_trust_domain_meta(
    pool: &RwLock<TrustDomainPool>,
    expected_trust_domain_id: &TrustDomainId,
    meta: SignedTrustDomainMeta,
    persist_domain_dir: Option<&Path>,
    source: impl Into<String>,
) -> Result<TrustDomainMetaReceiveReport, TrustDomainMetaReceiveError> {
    if &meta.details.trust_domain_id != expected_trust_domain_id {
        return Err(TrustDomainMetaReceiveError::TrustDomainMismatch);
    }

    let trust_domain_id = meta.details.trust_domain_id;
    let new_version = meta.details.version;
    let mut guard = pool.write().await;
    let old_version = guard
        .trust_domain_meta(&trust_domain_id)
        .map(|existing| existing.details.version);
    guard.apply_trust_domain_meta(meta.clone())?;

    let persisted_path = match persist_domain_dir {
        Some(domain_dir) => {
            let path = trust_domain_meta_path(domain_dir);
            persist_trust_domain_meta(&path, &meta)?;
            Some(path)
        }
        None => None,
    };
    drop(guard);

    let report = TrustDomainMetaReceiveReport {
        source: source.into(),
        trust_domain_id,
        old_version,
        new_version,
        persisted_path,
    };
    tracing::info!(
        source = %report.source,
        trust_domain_id = %report.trust_domain_id,
        old_version = ?report.old_version,
        new_version = report.new_version,
        persist_path = ?report.persisted_path,
        "accepted trust_domain_meta update"
    );
    Ok(report)
}

pub fn trust_domain_meta_path(domain_dir: &Path) -> PathBuf {
    domain_dir.join("trust_domain_meta.pem")
}

fn persist_trust_domain_meta(
    path: &Path,
    meta: &SignedTrustDomainMeta,
) -> Result<(), std::io::Error> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "trust_domain_meta path has no parent directory",
        )
    })?;
    std::fs::create_dir_all(parent)?;
    let tmp_path = path.with_extension("pem.tmp");
    std::fs::write(
        &tmp_path,
        wrap_armored(TRUST_DOMAIN_META_PEM_LABEL, &to_canonical_cbor(meta)),
    )?;
    std::fs::rename(tmp_path, path)?;
    Ok(())
}
