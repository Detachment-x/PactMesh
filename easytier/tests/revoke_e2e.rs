mod test_harness;

use std::time::{SystemTime, UNIX_EPOCH};

use easytier::trust::pool::TrustDomainPoolError;
use test_harness::*;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

async fn setup_joined_three_node() -> (tempfile::TempDir, String, easytier::trust::MemberCert, easytier::trust::MemberCert) {
    let root_dir = tempfile::tempdir().unwrap();
    let node_a_dir = tempfile::tempdir().unwrap();
    let node_b_dir = tempfile::tempdir().unwrap();
    let trust_domain_id = create_domain(root_dir.path());
    create_network(root_dir.path(), &trust_domain_id);
    let invite = invite_url(root_dir.path(), &trust_domain_id);
    let join_a = accept_invite(node_a_dir.path(), &invite, "node-a");
    let join_b = accept_invite(node_b_dir.path(), &invite, "node-b");
    let root = root_instance(root_dir.path(), &trust_domain_id);
    let cert_a = approve_join(&root, &join_a).await;
    let cert_b = approve_join(&root, &join_b).await;
    rewrite_network_state_with_members(root_dir.path(), &trust_domain_id, &[cert_a.clone(), cert_b.clone()]);
    (root_dir, trust_domain_id, cert_a, cert_b)
}

#[tokio::test]
async fn test_revoke_e2e_rejects_revoked_member_cert() {
    let (root_dir, trust_domain_id, cert_a, cert_b) = setup_joined_three_node().await;
    let before = trust_pool(root_dir.path(), &trust_domain_id);
    before.read().await.verify_member_cert(&cert_a, now_unix()).unwrap();
    before.read().await.verify_member_cert(&cert_b, now_unix()).unwrap();

    revoke_member(root_dir.path(), &trust_domain_id, &cert_b);

    let after = trust_pool(root_dir.path(), &trust_domain_id);
    after.read().await.verify_member_cert(&cert_a, now_unix()).unwrap();
    let err = after.read().await.verify_member_cert(&cert_b, now_unix()).unwrap_err();
    assert_eq!(err, TrustDomainPoolError::Revoked);
}

#[tokio::test]
async fn test_revoke_e2e_network_state_version_advances() {
    let (root_dir, trust_domain_id, _cert_a, cert_b) = setup_joined_three_node().await;
    let before = read_network_state(root_dir.path(), &trust_domain_id).details.version;

    revoke_member(root_dir.path(), &trust_domain_id, &cert_b);

    let after = read_network_state(root_dir.path(), &trust_domain_id);
    assert_eq!(after.details.version, before + 1);
    assert!(after.details.payload.revoked_certs.iter().any(|revoked| revoked.cert_fingerprint == cert_b.fingerprint()));
}

#[tokio::test]
async fn test_revoke_e2e_old_pool_still_accepts_until_state_refresh() {
    let (root_dir, trust_domain_id, _cert_a, cert_b) = setup_joined_three_node().await;
    let old_pool = trust_pool(root_dir.path(), &trust_domain_id);

    revoke_member(root_dir.path(), &trust_domain_id, &cert_b);

    old_pool.read().await.verify_member_cert(&cert_b, now_unix()).unwrap();
    let refreshed_pool = trust_pool(root_dir.path(), &trust_domain_id);
    assert_eq!(
        refreshed_pool.read().await.verify_member_cert(&cert_b, now_unix()).unwrap_err(),
        TrustDomainPoolError::Revoked
    );
}
