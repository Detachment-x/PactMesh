mod test_harness;

use std::time::{SystemTime, UNIX_EPOCH};

use test_harness::*;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

#[tokio::test]
async fn test_three_node_join_approval_writes_member_certs() {
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
    write_member_cert(node_a_dir.path(), &trust_domain_id, &cert_a);
    write_member_cert(node_b_dir.path(), &trust_domain_id, &cert_b);

    assert!(test_harness::network_dir(node_a_dir.path(), &trust_domain_id).join("member_cert.pem").is_file());
    assert!(test_harness::network_dir(node_b_dir.path(), &trust_domain_id).join("member_cert.pem").is_file());
    assert_member_matches_join(&cert_a, &join_a, "node-a");
    assert_member_matches_join(&cert_b, &join_b, "node-b");
}

#[tokio::test]
async fn test_three_node_members_verify_in_shared_trust_pool() {
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

    let pool = trust_pool(root_dir.path(), &trust_domain_id);
    let guard = pool.read().await;
    guard.verify_member_cert(&cert_a, now_unix()).unwrap();
    guard.verify_member_cert(&cert_b, now_unix()).unwrap();
}

#[tokio::test]
async fn test_three_node_bootstrap_and_join_requests_bind_same_network() {
    let root_dir = tempfile::tempdir().unwrap();
    let node_a_dir = tempfile::tempdir().unwrap();
    let node_b_dir = tempfile::tempdir().unwrap();
    let trust_domain_id = create_domain(root_dir.path());
    create_network(root_dir.path(), &trust_domain_id);
    let invite = invite_url(root_dir.path(), &trust_domain_id);
    let bootstrap = read_bootstrap(&invite);

    let join_a = accept_invite(node_a_dir.path(), &invite, "node-a");
    let join_b = accept_invite(node_b_dir.path(), &invite, "node-b");

    assert_eq!(bootstrap.trust_domain_id.to_string(), trust_domain_id);
    assert_eq!(join_a.trust_domain_id, bootstrap.trust_domain_id);
    assert_eq!(join_b.trust_domain_id, bootstrap.trust_domain_id);
    assert_eq!(join_a.network_local_id, bootstrap.network_local_id);
    assert_eq!(join_b.network_local_id, bootstrap.network_local_id);
    assert_ne!(join_a.applicant_pk, join_b.applicant_pk);
}
