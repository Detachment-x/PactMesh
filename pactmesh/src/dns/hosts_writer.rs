use std::{collections::BTreeMap, net::IpAddr};

use thiserror::Error;

use crate::trust::{DeviceFingerprint, NetworkLocalId, TrustDomainId};

use super::{
    hosts_block::{HostEntry, HostsBlock, RawSection, parse_existing, render_block},
    platform::{HostsBackend, SystemHostsBackend},
};

#[derive(Debug, Error)]
pub enum HostsError {
    #[error("hosts io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NetworkKey {
    pub trust_domain_id: TrustDomainId,
    pub network_local_id: NetworkLocalId,
}

impl NetworkKey {
    pub fn new(trust_domain_id: TrustDomainId, network_local_id: NetworkLocalId) -> Self {
        Self {
            trust_domain_id,
            network_local_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostnameIndexEntry {
    pub fingerprint: DeviceFingerprint,
    pub hostname: String,
    pub fqdn: String,
}

pub type HostnameIndex = Vec<HostnameIndexEntry>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefreshReport {
    pub added: usize,
    pub removed: usize,
    pub modified: usize,
    pub external_changes_logged: usize,
}

pub struct HostsWriter;

impl HostsWriter {
    pub fn refresh(
        hostname_index_per_network: &BTreeMap<NetworkKey, HostnameIndex>,
        ipam_lookup: &dyn Fn(&DeviceFingerprint) -> Option<IpAddr>,
        short_names_enabled: bool,
    ) -> Result<RefreshReport, HostsError> {
        let backend = SystemHostsBackend::default();
        Self::refresh_with_backend(
            &backend,
            hostname_index_per_network,
            ipam_lookup,
            short_names_enabled,
        )
    }

    pub fn refresh_with_backend(
        backend: &dyn HostsBackend,
        hostname_index_per_network: &BTreeMap<NetworkKey, HostnameIndex>,
        ipam_lookup: &dyn Fn(&DeviceFingerprint) -> Option<IpAddr>,
        short_names_enabled: bool,
    ) -> Result<RefreshReport, HostsError> {
        let existing = backend.read()?;
        let (sections, spans) = parse_existing(&existing);
        let rendered =
            render_all_blocks(hostname_index_per_network, ipam_lookup, short_names_enabled);

        let mut report = RefreshReport::default();
        for key in rendered.keys() {
            if spans.contains_key(key) {
                report.modified += 1;
            } else {
                report.added += 1;
            }
        }
        for key in spans.keys() {
            if !rendered.contains_key(key) {
                report.removed += 1;
            }
        }
        report.external_changes_logged = spans.len().min(report.modified + report.removed);

        let mut next = String::new();
        for section in sections {
            if let RawSection::External(text) = section {
                next.push_str(&text);
                if !text.ends_with('\n') {
                    next.push('\n');
                }
            }
        }
        if !next.is_empty() && !next.ends_with('\n') {
            next.push('\n');
        }
        for block in rendered.values() {
            if !next.is_empty() && !next.ends_with('\n') {
                next.push('\n');
            }
            next.push_str(block);
        }

        backend.atomic_write(&next)?;
        Ok(report)
    }
}

fn render_all_blocks(
    hostname_index_per_network: &BTreeMap<NetworkKey, HostnameIndex>,
    ipam_lookup: &dyn Fn(&DeviceFingerprint) -> Option<IpAddr>,
    short_names_enabled: bool,
) -> BTreeMap<String, String> {
    let mut blocks = BTreeMap::new();
    for (key, index) in hostname_index_per_network {
        let entries = index
            .iter()
            .filter_map(|entry| {
                let ip = ipam_lookup(&entry.fingerprint)?;
                Some(HostEntry {
                    ip,
                    short_name: short_names_enabled.then(|| entry.hostname.clone()),
                    fqdn: entry.fqdn.clone(),
                })
            })
            .collect::<Vec<_>>();

        if entries.is_empty() {
            continue;
        }

        let block = HostsBlock {
            trust_domain_id: key.trust_domain_id,
            network_local_id: key.network_local_id.clone(),
            entries,
        };
        blocks.insert(block.key().marker(), render_block(&block));
    }
    blocks
}
