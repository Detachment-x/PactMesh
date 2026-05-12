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

async fn join_device_to_domain(
    device_dir: &std::path::Path,
    root_dir: &std::path::Path,
    label: &str,
) -> (
    String,
    easytier::trust::JoinRequest,
    easytier::trust::MemberCert,
) {
    let trust_domain_id = create_domain(root_dir);
    create_network(root_dir, &trust_domain_id);
    let invite = invite_url(root_dir, &trust_domain_id);
    let join = accept_invite(device_dir, &invite, label);
    let root = root_instance(root_dir, &trust_domain_id);
    let cert = approve_join(&root, &join).await;
    rewrite_network_state_with_members(root_dir, &trust_domain_id, std::slice::from_ref(&cert));
    write_member_cert(device_dir, &trust_domain_id, &cert);
    (trust_domain_id, join, cert)
}

#[tokio::test]
async fn test_multi_domain_reuses_one_device_key_for_two_member_certs() {
    let device_dir = tempfile::tempdir().unwrap();
    let root_a_dir = tempfile::tempdir().unwrap();
    let root_b_dir = tempfile::tempdir().unwrap();

    let (td_a, join_a, cert_a) =
        join_device_to_domain(device_dir.path(), root_a_dir.path(), "device-d").await;
    let (td_b, join_b, cert_b) =
        join_device_to_domain(device_dir.path(), root_b_dir.path(), "device-d").await;

    assert_ne!(td_a, td_b);
    assert_eq!(join_a.applicant_pk, join_b.applicant_pk);
    assert_eq!(
        cert_a.details.device_pk.to_bytes(),
        cert_b.details.device_pk.to_bytes()
    );
    assert_ne!(cert_a.fingerprint(), cert_b.fingerprint());
    assert_ne!(
        cert_a.details.trust_domain_id,
        cert_b.details.trust_domain_id
    );
}

#[tokio::test]
async fn test_multi_domain_revoke_domain_a_does_not_affect_domain_b() {
    let device_dir = tempfile::tempdir().unwrap();
    let root_a_dir = tempfile::tempdir().unwrap();
    let root_b_dir = tempfile::tempdir().unwrap();

    let (td_a, _join_a, cert_a) =
        join_device_to_domain(device_dir.path(), root_a_dir.path(), "device-d").await;
    let (td_b, _join_b, cert_b) =
        join_device_to_domain(device_dir.path(), root_b_dir.path(), "device-d").await;

    revoke_member(root_a_dir.path(), &td_a, &cert_a);

    let pool_a = trust_pool(root_a_dir.path(), &td_a);
    assert_eq!(
        pool_a
            .read()
            .await
            .verify_member_cert(&cert_a, now_unix())
            .unwrap_err(),
        TrustDomainPoolError::Revoked
    );

    let pool_b = trust_pool(root_b_dir.path(), &td_b);
    pool_b
        .read()
        .await
        .verify_member_cert(&cert_b, now_unix())
        .unwrap();
}

#[tokio::test]
async fn test_multi_domain_network_state_pools_remain_disjoint() {
    let device_dir = tempfile::tempdir().unwrap();
    let root_a_dir = tempfile::tempdir().unwrap();
    let root_b_dir = tempfile::tempdir().unwrap();

    let (td_a, _join_a, cert_a) =
        join_device_to_domain(device_dir.path(), root_a_dir.path(), "device-d").await;
    let (td_b, _join_b, cert_b) =
        join_device_to_domain(device_dir.path(), root_b_dir.path(), "device-d").await;

    let pool_a = trust_pool(root_a_dir.path(), &td_a);
    let pool_b = trust_pool(root_b_dir.path(), &td_b);

    pool_a
        .read()
        .await
        .verify_member_cert(&cert_a, now_unix())
        .unwrap();
    pool_b
        .read()
        .await
        .verify_member_cert(&cert_b, now_unix())
        .unwrap();
    assert_eq!(
        pool_a
            .read()
            .await
            .verify_member_cert(&cert_b, now_unix())
            .unwrap_err(),
        TrustDomainPoolError::UnknownDomain
    );
    assert_eq!(
        pool_b
            .read()
            .await
            .verify_member_cert(&cert_a, now_unix())
            .unwrap_err(),
        TrustDomainPoolError::UnknownDomain
    );
}
