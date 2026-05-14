//! ACL validation rules (T-036).
//!
//! Applies VR1–VR11 from `acl-schema-draft.md` §4.

use super::acl::{
    ACL_SCHEMA_VERSION, AclPolicy, AclRule, Cidr, DeviceFingerprint, MAX_RULES, MAX_TAGS, PortSpec,
    Proto, Selector,
};
use super::acl_error::AclError;

/// Validate a policy before signing (VR1–VR9).
pub fn validate_for_signing(
    policy: &AclPolicy,
    member_cert_index: &[DeviceFingerprint],
    proxy_cidrs: &[Cidr],
) -> Result<(), AclError> {
    validate_common(policy)?;

    for (tag, members) in &policy.tags {
        if members
            .iter()
            .any(|member| !member_cert_index.contains(member))
        {
            return Err(AclError::TagMemberNotFound(tag.as_str().to_owned()));
        }
    }

    for rule in &policy.rules {
        for selector in rule.src.iter().chain(&rule.dst) {
            if let Selector::Subnet(cidr) = selector
                && !proxy_cidrs.contains(cidr)
            {
                return Err(AclError::SubnetOrphan(cidr_string(*cidr)));
            }
        }
    }

    Ok(())
}

/// Validate a received policy locally (VR10–VR11).
pub fn validate_for_receiving(
    policy: &AclPolicy,
    max_supported_version: u8,
) -> Result<(), AclError> {
    if policy.schema_version > max_supported_version {
        return Err(AclError::UnsupportedSchemaVersion {
            got: policy.schema_version,
            max_supported: max_supported_version,
        });
    }
    validate_common(policy)
}

fn validate_common(policy: &AclPolicy) -> Result<(), AclError> {
    if policy.tags.len() > MAX_TAGS {
        return Err(AclError::TooManyTags(policy.tags.len()));
    }
    if policy.rules.len() > MAX_RULES {
        return Err(AclError::TooManyRules(policy.rules.len()));
    }
    if policy.schema_version == 0 {
        return Err(AclError::UnsupportedSchemaVersion {
            got: policy.schema_version,
            max_supported: ACL_SCHEMA_VERSION,
        });
    }

    for tag in policy.tags.keys() {
        if tag.as_str().is_empty() {
            return Err(AclError::InvalidTagName(tag.as_str().to_owned()));
        }
    }

    for (idx, rule) in policy.rules.iter().enumerate() {
        validate_rule(policy, rule, idx)?;
    }

    Ok(())
}

fn validate_rule(policy: &AclPolicy, rule: &AclRule, idx: usize) -> Result<(), AclError> {
    if rule.src.is_empty() || rule.dst.is_empty() {
        return Err(AclError::EmptySrcOrDst(idx));
    }

    if rule.ports.is_some() && !matches!(rule.proto, Proto::Tcp | Proto::Udp) {
        return Err(AclError::PortsNotApplicable(
            proto_name(rule.proto).to_owned(),
        ));
    }

    for port in rule.ports.iter().flatten() {
        if let PortSpec::Range(low, high) = port
            && low > high
        {
            return Err(AclError::InvalidPortRange(*low, *high));
        }
    }

    for selector in rule.src.iter().chain(&rule.dst) {
        match selector {
            Selector::Tag(tag) if !policy.tags.contains_key(tag) => {
                return Err(AclError::UndefinedTag(tag.as_str().to_owned()));
            }
            Selector::Subnet(cidr) => validate_cidr(*cidr)?,
            Selector::Hostname(hostname) if hostname.as_str().is_empty() => {
                return Err(AclError::InvalidHostname(hostname.as_str().to_owned()));
            }
            _ => {}
        }
    }

    Ok(())
}

fn validate_cidr(cidr: Cidr) -> Result<(), AclError> {
    let max = if cidr.addr.is_ipv4() { 32 } else { 128 };
    if cidr.prefix_len > max {
        return Err(AclError::InvalidPrefixLen(cidr.prefix_len));
    }
    Ok(())
}

fn proto_name(proto: Proto) -> &'static str {
    match proto {
        Proto::Wildcard => "*",
        Proto::Icmp => "icmp",
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    }
}

fn cidr_string(cidr: Cidr) -> String {
    format!("{}/{}", cidr.addr, cidr.prefix_len)
}
