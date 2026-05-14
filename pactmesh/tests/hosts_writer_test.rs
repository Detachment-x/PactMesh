use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
};

use pactmesh::{
    dns::{
        hosts_block::{HostEntry, HostsBlock, render_block},
        hosts_writer::{HostnameIndexEntry, HostsWriter, NetworkKey},
        platform::MockHostsBackend,
    },
    trust::{DeviceFingerprint, NetworkLocalId, TrustDomainId},
};

fn fp(byte: u8) -> DeviceFingerprint {
    DeviceFingerprint::new([byte; 32])
}

fn td(byte: u8) -> TrustDomainId {
    TrustDomainId([byte; 32])
}

fn nlid(name: &str) -> NetworkLocalId {
    NetworkLocalId::try_from_str(name).unwrap()
}

fn key(td_byte: u8, network: &str) -> NetworkKey {
    NetworkKey::new(td(td_byte), nlid(network))
}

fn entry(byte: u8, hostname: &str, network: &str) -> HostnameIndexEntry {
    HostnameIndexEntry {
        fingerprint: fp(byte),
        hostname: hostname.to_owned(),
        fqdn: format!("{hostname}.{network}.{}.pnw", "a".repeat(8)),
    }
}

fn indexes(
    items: Vec<(NetworkKey, Vec<HostnameIndexEntry>)>,
) -> BTreeMap<NetworkKey, Vec<HostnameIndexEntry>> {
    items.into_iter().collect()
}

fn ipam(fingerprint: &DeviceFingerprint) -> Option<IpAddr> {
    match fingerprint.0[0] {
        1 => Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        2 => Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        3 => Some(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 3))),
        _ => None,
    }
}

#[test]
fn test_render_empty_pool_writes_no_blocks() {
    let backend = MockHostsBackend::new("127.0.0.1 localhost\n");
    let report =
        HostsWriter::refresh_with_backend(&backend, &BTreeMap::new(), &ipam, true).unwrap();

    assert_eq!(backend.content(), "127.0.0.1 localhost\n");
    assert_eq!(report.added, 0);
}

#[test]
fn test_render_one_network_with_two_hosts() {
    let backend = MockHostsBackend::new("");
    let map = indexes(vec![(
        key(1, "home"),
        vec![entry(1, "alpha", "home"), entry(2, "beta", "home")],
    )]);

    HostsWriter::refresh_with_backend(&backend, &map, &ipam, false).unwrap();

    let content = backend.content();
    assert!(content.contains("alpha.home.aaaaaaaa.pnw"));
    assert!(content.contains("beta.home.aaaaaaaa.pnw"));
}

#[test]
fn test_render_short_name_enabled_when_only_one_network() {
    let block = HostsBlock {
        trust_domain_id: td(1),
        network_local_id: nlid("home"),
        entries: vec![HostEntry {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            short_name: Some("alpha".to_owned()),
            fqdn: "alpha.home.aaaaaaaa.pnw".to_owned(),
        }],
    };

    let rendered = render_block(&block);
    assert!(rendered.contains("10.0.0.1 alpha\n"));
    assert!(rendered.contains("10.0.0.1 alpha.home.aaaaaaaa.pnw\n"));
}

#[test]
fn test_render_short_name_disabled_when_multi_network() {
    let backend = MockHostsBackend::new("");
    let map = indexes(vec![(key(1, "home"), vec![entry(1, "alpha", "home")])]);

    HostsWriter::refresh_with_backend(&backend, &map, &ipam, false).unwrap();

    let content = backend.content();
    assert!(!content.contains("10.0.0.1 alpha\n"));
    assert!(content.contains("10.0.0.1 alpha.home.aaaaaaaa.pnw\n"));
}

#[test]
fn test_external_lines_preserved() {
    let backend = MockHostsBackend::new("127.0.0.1 localhost\n# custom\n");
    let map = indexes(vec![(key(1, "home"), vec![entry(1, "alpha", "home")])]);

    HostsWriter::refresh_with_backend(&backend, &map, &ipam, false).unwrap();

    let content = backend.content();
    assert!(content.starts_with("127.0.0.1 localhost\n# custom\n"));
}

#[test]
fn test_external_modification_inside_our_block_logged_and_overwritten() {
    let existing = format!(
        "# BEGIN privateNetwork {}:{}\n10.9.9.9 stale\n# END   privateNetwork {}:{}\n",
        td(1),
        nlid("home"),
        td(1),
        nlid("home")
    );
    let backend = MockHostsBackend::new(existing);
    let map = indexes(vec![(key(1, "home"), vec![entry(1, "alpha", "home")])]);

    let report = HostsWriter::refresh_with_backend(&backend, &map, &ipam, true).unwrap();

    assert!(report.external_changes_logged >= 1);
    assert!(!backend.content().contains("stale"));
    assert!(backend.content().contains("alpha"));
}

#[test]
fn test_revoked_cert_hostname_removed_on_refresh() {
    let backend = MockHostsBackend::new("");
    let before = indexes(vec![(
        key(1, "home"),
        vec![entry(1, "alpha", "home"), entry(2, "beta", "home")],
    )]);
    HostsWriter::refresh_with_backend(&backend, &before, &ipam, false).unwrap();

    let after = indexes(vec![(key(1, "home"), vec![entry(1, "alpha", "home")])]);
    HostsWriter::refresh_with_backend(&backend, &after, &ipam, false).unwrap();

    assert!(backend.content().contains("alpha"));
    assert!(!backend.content().contains("beta"));
}

#[test]
fn test_unset_hostname_removes_entry_keeps_others() {
    let backend = MockHostsBackend::new("");
    let before = indexes(vec![(
        key(1, "home"),
        vec![entry(1, "alpha", "home"), entry(2, "beta", "home")],
    )]);
    HostsWriter::refresh_with_backend(&backend, &before, &ipam, true).unwrap();

    let after = indexes(vec![(key(1, "home"), vec![entry(2, "beta", "home")])]);
    HostsWriter::refresh_with_backend(&backend, &after, &ipam, true).unwrap();

    assert!(!backend.content().contains("alpha"));
    assert!(backend.content().contains("beta"));
}

#[test]
fn test_ipam_unknown_skips_entry() {
    let backend = MockHostsBackend::new("");
    let map = indexes(vec![(
        key(1, "home"),
        vec![entry(9, "ghost", "home"), entry(1, "alpha", "home")],
    )]);

    HostsWriter::refresh_with_backend(&backend, &map, &ipam, true).unwrap();

    assert!(!backend.content().contains("ghost"));
    assert!(backend.content().contains("alpha"));
}

#[test]
fn test_atomic_write_preserves_file_perms() {
    let backend = MockHostsBackend::new("");
    let map = indexes(vec![(key(1, "home"), vec![entry(1, "alpha", "home")])]);

    HostsWriter::refresh_with_backend(&backend, &map, &ipam, true).unwrap();

    assert_eq!(backend.write_count(), 1);
}
