use std::sync::Arc;

use pactmesh::trust::{
    TRUST_DOMAIN_META_PEM_LABEL, TrustDomainMetaReceiveError, TrustDomainPool, TrustDomainRoot,
    UnsignedTrustDomainMeta, from_cbor, receive_trust_domain_meta, trust_domain_meta_path,
    unwrap_armored,
};
use tokio::sync::RwLock;

fn meta(root: &TrustDomainRoot, version: u64) -> pactmesh::trust::SignedTrustDomainMeta {
    UnsignedTrustDomainMeta {
        trust_domain_id: root.id(),
        version,
        active_relays: Vec::new(),
        outbound_grants: Vec::new(),
    }
    .sign(root)
}

fn pool(root: &TrustDomainRoot) -> Arc<RwLock<TrustDomainPool>> {
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    Arc::new(RwLock::new(pool))
}

#[tokio::test]
async fn test_receive_trust_domain_meta_accepts_and_persists_newer_meta() {
    let root = TrustDomainRoot::generate();
    let pool = pool(&root);
    receive_trust_domain_meta(&pool, &root.id(), meta(&root, 1), None, "initial")
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let updated = meta(&root, 2);

    let report = receive_trust_domain_meta(
        &pool,
        &root.id(),
        updated.clone(),
        Some(dir.path()),
        "test-source",
    )
    .await
    .unwrap();

    assert_eq!(report.old_version, Some(1));
    assert_eq!(report.new_version, 2);
    let path = report.persisted_path.unwrap();
    assert_eq!(path, trust_domain_meta_path(dir.path()));
    let payload = unwrap_armored(
        &std::fs::read_to_string(path).unwrap(),
        TRUST_DOMAIN_META_PEM_LABEL,
    )
    .unwrap();
    let persisted: pactmesh::trust::SignedTrustDomainMeta = from_cbor(&payload).unwrap();
    assert_eq!(persisted, updated);
}

#[tokio::test]
async fn test_receive_trust_domain_meta_rejects_stale_without_overwriting_disk() {
    let root = TrustDomainRoot::generate();
    let pool = pool(&root);
    let dir = tempfile::tempdir().unwrap();
    let current = meta(&root, 2);
    receive_trust_domain_meta(
        &pool,
        &root.id(),
        current.clone(),
        Some(dir.path()),
        "current",
    )
    .await
    .unwrap();

    let err =
        receive_trust_domain_meta(&pool, &root.id(), meta(&root, 1), Some(dir.path()), "stale")
            .await
            .unwrap_err();

    assert!(matches!(
        err,
        TrustDomainMetaReceiveError::PoolApply(
            pactmesh::trust::pool::PoolApplyError::StaleVersion { have: 2, got: 1 }
        )
    ));
    let payload = unwrap_armored(
        &std::fs::read_to_string(trust_domain_meta_path(dir.path())).unwrap(),
        TRUST_DOMAIN_META_PEM_LABEL,
    )
    .unwrap();
    let persisted: pactmesh::trust::SignedTrustDomainMeta = from_cbor(&payload).unwrap();
    assert_eq!(persisted, current);
}

#[tokio::test]
async fn test_receive_trust_domain_meta_rejects_wrong_domain_and_tamper() {
    let root = TrustDomainRoot::generate();
    let other = TrustDomainRoot::generate();
    let pool = pool(&root);

    let err = receive_trust_domain_meta(&pool, &root.id(), meta(&other, 1), None, "wrong-domain")
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        TrustDomainMetaReceiveError::TrustDomainMismatch
    ));

    let mut tampered = meta(&root, 1);
    tampered.details.version = 2;
    let err = receive_trust_domain_meta(&pool, &root.id(), tampered, None, "tampered")
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        TrustDomainMetaReceiveError::PoolApply(pactmesh::trust::pool::PoolApplyError::BadSignature)
    ));
}
