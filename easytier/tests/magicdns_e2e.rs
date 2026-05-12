mod test_harness;

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
};

use easytier::{
    dns::{
        hosts_writer::{HostnameIndexEntry, HostsWriter, NetworkKey},
        platform::MockHostsBackend,
    },
    trust::{DeviceFingerprint, MemberCert, NetworkLocalId, TrustDomainId},
};
use test_harness::*;

fn td_from_str(value: &str) -> TrustDomainId {
    let bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, value).unwrap();
    TrustDomainId(bytes.try_into().unwrap())
}

fn network_key(trust_domain_id: &str, network: &str) -> NetworkKey {
    NetworkKey::new(
        td_from_str(trust_domain_id),
        NetworkLocalId::try_from_str(network).unwrap(),
    )
}

fn fingerprint(cert: &MemberCert) -> DeviceFingerprint {
    DeviceFingerprint::new(cert.fingerprint().0)
}

fn index_entry(
    cert: &MemberCert,
    hostname: &str,
    network: &str,
    trust_domain_id: &str,
) -> HostnameIndexEntry {
    HostnameIndexEntry {
        fingerprint: fingerprint(cert),
        hostname: hostname.to_owned(),
        fqdn: format!("{hostname}.{network}.{}.pnw", &trust_domain_id[..8]),
    }
}

fn ipam(
    fp_a: DeviceFingerprint,
    fp_b: DeviceFingerprint,
) -> impl Fn(&DeviceFingerprint) -> Option<IpAddr> {
    move |fingerprint| {
        if *fingerprint == fp_a {
            Some(IpAddr::V4(Ipv4Addr::new(10, 144, 0, 10)))
        } else if *fingerprint == fp_b {
            Some(IpAddr::V4(Ipv4Addr::new(10, 144, 0, 20)))
        } else {
            None
        }
    }
}

async fn setup_two_named_members() -> (tempfile::TempDir, String, MemberCert, MemberCert) {
    let root_dir = tempfile::tempdir().unwrap();
    let node_a_dir = tempfile::tempdir().unwrap();
    let node_b_dir = tempfile::tempdir().unwrap();
    let trust_domain_id = create_domain(root_dir.path());
    create_network(root_dir.path(), &trust_domain_id);
    let invite = invite_url(root_dir.path(), &trust_domain_id);
    let join_a = accept_invite(node_a_dir.path(), &invite, "node-a");
    let join_b = accept_invite(node_b_dir.path(), &invite, "node-b");
    let root = root_instance(root_dir.path(), &trust_domain_id);
    let mut cert_a = approve_join(&root, &join_a).await;
    let mut cert_b = approve_join(&root, &join_b).await;
    cert_a.details.hostname = Some(easytier::trust::HostnameLabel::try_from_str("laptop").unwrap());
    cert_b.details.hostname = Some(easytier::trust::HostnameLabel::try_from_str("server").unwrap());
    rewrite_network_state_with_members(
        root_dir.path(),
        &trust_domain_id,
        &[cert_a.clone(), cert_b.clone()],
    );
    (root_dir, trust_domain_id, cert_a, cert_b)
}

#[tokio::test]
async fn test_magicdns_hosts_contains_peer_fqdns_and_preserves_external_lines() {
    let (_root_dir, trust_domain_id, cert_a, cert_b) = setup_two_named_members().await;
    let backend = MockHostsBackend::new("1.2.3.4 external.example\n");
    let mut indexes = BTreeMap::new();
    indexes.insert(
        network_key(&trust_domain_id, NETWORK_LOCAL_ID),
        vec![
            index_entry(&cert_a, "laptop", NETWORK_LOCAL_ID, &trust_domain_id),
            index_entry(&cert_b, "server", NETWORK_LOCAL_ID, &trust_domain_id),
        ],
    );

    HostsWriter::refresh_with_backend(
        &backend,
        &indexes,
        &ipam(fingerprint(&cert_a), fingerprint(&cert_b)),
        true,
    )
    .unwrap();

    let content = backend.content();
    assert!(content.contains("1.2.3.4 external.example"));
    assert!(content.contains("10.144.0.10 laptop\n"));
    assert!(content.contains(&format!(
        "10.144.0.10 laptop.{NETWORK_LOCAL_ID}.{}.pnw",
        &trust_domain_id[..8]
    )));
    assert!(content.contains("10.144.0.20 server\n"));
    assert!(content.contains(&format!(
        "10.144.0.20 server.{NETWORK_LOCAL_ID}.{}.pnw",
        &trust_domain_id[..8]
    )));
}

#[tokio::test]
async fn test_magicdns_rename_and_revoke_refreshes_hosts_block() {
    let (root_dir, trust_domain_id, cert_a, cert_b) = setup_two_named_members().await;
    let backend = MockHostsBackend::new("");
    let key = network_key(&trust_domain_id, NETWORK_LOCAL_ID);
    let lookup = ipam(fingerprint(&cert_a), fingerprint(&cert_b));

    let mut indexes = BTreeMap::new();
    indexes.insert(
        key.clone(),
        vec![
            index_entry(&cert_a, "laptop", NETWORK_LOCAL_ID, &trust_domain_id),
            index_entry(&cert_b, "server", NETWORK_LOCAL_ID, &trust_domain_id),
        ],
    );
    HostsWriter::refresh_with_backend(&backend, &indexes, &lookup, true).unwrap();
    assert!(backend.content().contains("laptop"));
    assert!(backend.content().contains("server"));

    indexes.insert(
        key.clone(),
        vec![
            index_entry(&cert_a, "macbook", NETWORK_LOCAL_ID, &trust_domain_id),
            index_entry(&cert_b, "server", NETWORK_LOCAL_ID, &trust_domain_id),
        ],
    );
    HostsWriter::refresh_with_backend(&backend, &indexes, &lookup, true).unwrap();
    assert!(backend.content().contains("macbook"));
    assert!(!backend.content().contains("laptop"));

    revoke_member(root_dir.path(), &trust_domain_id, &cert_b);
    indexes.insert(
        key,
        vec![index_entry(
            &cert_a,
            "macbook",
            NETWORK_LOCAL_ID,
            &trust_domain_id,
        )],
    );
    HostsWriter::refresh_with_backend(&backend, &indexes, &lookup, true).unwrap();
    assert!(backend.content().contains("macbook"));
    assert!(!backend.content().contains("server"));
}

#[tokio::test]
async fn test_magicdns_multi_network_disables_short_names() {
    let (_root_dir, trust_domain_id, cert_a, cert_b) = setup_two_named_members().await;
    let backend = MockHostsBackend::new("");
    let mut indexes = BTreeMap::new();
    indexes.insert(
        network_key(&trust_domain_id, NETWORK_LOCAL_ID),
        vec![index_entry(
            &cert_a,
            "laptop",
            NETWORK_LOCAL_ID,
            &trust_domain_id,
        )],
    );
    indexes.insert(
        network_key(&trust_domain_id, "lab-net"),
        vec![index_entry(&cert_b, "server", "lab-net", &trust_domain_id)],
    );

    HostsWriter::refresh_with_backend(
        &backend,
        &indexes,
        &ipam(fingerprint(&cert_a), fingerprint(&cert_b)),
        false,
    )
    .unwrap();

    let content = backend.content();
    assert!(!content.contains("10.144.0.10 laptop\n"));
    assert!(!content.contains("10.144.0.20 server\n"));
    assert!(content.contains(&format!(
        "laptop.{NETWORK_LOCAL_ID}.{}.pnw",
        &trust_domain_id[..8]
    )));
    assert!(content.contains(&format!("server.lab-net.{}.pnw", &trust_domain_id[..8])));
}
