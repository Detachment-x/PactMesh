use std::{collections::BTreeMap, net::IpAddr};

use crate::trust::{NetworkLocalId, TrustDomainId};

pub const BEGIN_PREFIX: &str = "# BEGIN privateNetwork ";
pub const END_PREFIX: &str = "# END   privateNetwork ";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlockKey {
    pub trust_domain_id: TrustDomainId,
    pub network_local_id: NetworkLocalId,
}

impl BlockKey {
    pub fn marker(&self) -> String {
        format!("{}:{}", self.trust_domain_id, self.network_local_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEntry {
    pub ip: IpAddr,
    pub short_name: Option<String>,
    pub fqdn: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsBlock {
    pub trust_domain_id: TrustDomainId,
    pub network_local_id: NetworkLocalId,
    pub entries: Vec<HostEntry>,
}

impl HostsBlock {
    pub fn key(&self) -> BlockKey {
        BlockKey {
            trust_domain_id: self.trust_domain_id,
            network_local_id: self.network_local_id.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawSection {
    External(String),
    PrivateNetwork { key: String, content: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSpan {
    pub start_line: usize,
    pub end_line: usize,
    pub content: String,
}

pub fn parse_existing(hosts_text: &str) -> (Vec<RawSection>, BTreeMap<String, BlockSpan>) {
    let lines = hosts_text.lines().map(str::to_owned).collect::<Vec<_>>();
    let mut sections = Vec::new();
    let mut spans = BTreeMap::new();
    let mut external = Vec::new();
    let mut idx = 0usize;

    while idx < lines.len() {
        let line = &lines[idx];
        if let Some(key) = line.strip_prefix(BEGIN_PREFIX) {
            if !external.is_empty() {
                sections.push(RawSection::External(join_lines(&external)));
                external.clear();
            }

            let start_line = idx;
            let mut block_lines = vec![line.clone()];
            idx += 1;
            while idx < lines.len() {
                block_lines.push(lines[idx].clone());
                if lines[idx] == format!("{END_PREFIX}{key}") {
                    break;
                }
                idx += 1;
            }
            let content = join_lines(&block_lines);
            let end_line = idx.min(lines.len().saturating_sub(1));
            let key = key.to_owned();
            spans.insert(
                key.clone(),
                BlockSpan {
                    start_line,
                    end_line,
                    content: content.clone(),
                },
            );
            sections.push(RawSection::PrivateNetwork { key, content });
        } else {
            external.push(line.clone());
        }
        idx += 1;
    }

    if !external.is_empty() {
        sections.push(RawSection::External(join_lines(&external)));
    }

    (sections, spans)
}

pub fn render_block(block: &HostsBlock) -> String {
    let key = block.key().marker();
    let mut out = String::new();
    out.push_str(BEGIN_PREFIX);
    out.push_str(&key);
    out.push('\n');

    let mut entries = block.entries.clone();
    entries.sort_by(|left, right| left.fqdn.cmp(&right.fqdn));
    for entry in entries {
        if let Some(short_name) = entry.short_name {
            out.push_str(&format!("{} {}\n", entry.ip, short_name));
        }
        out.push_str(&format!("{} {}\n", entry.ip, entry.fqdn));
    }

    out.push_str(END_PREFIX);
    out.push_str(&key);
    out.push('\n');
    out
}

fn join_lines(lines: &[String]) -> String {
    if lines.is_empty() {
        return String::new();
    }
    let mut text = lines.join("\n");
    text.push('\n');
    text
}
