//! ACL validation errors (T-036).
//!
//! See `acl-schema-draft.md` §3 / §4.

use thiserror::Error;

/// Validation failures for ACL signing / receiving.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AclError {
    #[error("tag count exceeds limit ({0} > 64)")]
    TooManyTags(usize),
    #[error("rule count exceeds limit ({0} > 256)")]
    TooManyRules(usize),
    #[error("tag name '{0}' violates charset (D9-C: [A-Za-z0-9_.-]{{1,32}})")]
    InvalidTagName(String),
    #[error("tag '{0}' references unknown device fingerprint")]
    TagMemberNotFound(String),
    #[error("rule {0} has empty src or dst (must contain ≥ 1 selector)")]
    EmptySrcOrDst(usize),
    #[error("port spec {0} only valid for tcp/udp")]
    PortsNotApplicable(String),
    #[error("CIDR prefix_len {0} out of range")]
    InvalidPrefixLen(u8),
    #[error("rule references undefined tag '{0}'")]
    UndefinedTag(String),
    #[error("port range invalid: low={0} > high={1}")]
    InvalidPortRange(u16, u16),
    #[error("hostname '{0}' violates LDH charset / length 1..=63 (D14)")]
    InvalidHostname(String),
    #[error("rule references subnet '{0}' which no cert advertises via capabilities.can_proxy_subnet")]
    SubnetOrphan(String),
    #[error("rule references hostname '{0}' which resolves to no live cert in network_state")]
    UnresolvedHostname(String),
    #[error("schema_version {got} exceeds max supported {max_supported}")]
    UnsupportedSchemaVersion { got: u8, max_supported: u8 },
}
