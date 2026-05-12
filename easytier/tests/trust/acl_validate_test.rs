//! Tests for `trust::acl_validate` (T-036).

use std::{collections::BTreeMap, net::IpAddr};

use easytier::trust::{
    ACL_SCHEMA_VERSION, AclError, AclPolicy, AclRule, Action, Cidr, DeviceFingerprint, PortSpec,
    Proto, Selector, TagName, TagNameError, validate_for_receiving, validate_for_signing,
};

fn fingerprint(byte: u8) -> DeviceFingerprint {
    DeviceFingerprint::new([byte; 32])
}

fn cidr_v4(a: u8, prefix_len: u8) -> Cidr {
    Cidr::new(IpAddr::from([10, 0, 0, a]), prefix_len)
}

fn tag(name: &str) -> TagName {
    TagName::try_from_str(name).unwrap()
}

fn base_policy() -> AclPolicy {
    let mut tags = BTreeMap::new();
    tags.insert(tag("server"), vec![fingerprint(1), fingerprint(2)]);
    tags.insert(tag("ops"), vec![fingerprint(3)]);

    let rules = vec![AclRule {
        action: Action::Accept,
        src: vec![Selector::Tag(tag("ops"))],
        dst: vec![Selector::Tag(tag("server"))],
        proto: Proto::Tcp,
        ports: Some(vec![PortSpec::Single(22), PortSpec::Range(80, 443)]),
    }];

    AclPolicy {
        tags,
        rules,
        default_action: Action::Accept,
        schema_version: ACL_SCHEMA_VERSION,
    }
}

fn member_index() -> Vec<DeviceFingerprint> {
    vec![fingerprint(1), fingerprint(2), fingerprint(3), fingerprint(4)]
}

fn proxy_cidrs() -> Vec<Cidr> {
    vec![cidr_v4(0, 24), Cidr::new("2001:db8::1".parse().unwrap(), 64)]
}

#[test]
fn test_vr1_too_many_tags() {
    let mut policy = base_policy();
    policy.tags.clear();
    for i in 0..65 {
        policy.tags.insert(tag(&format!("t{i}")), vec![fingerprint(1)]);
    }

    assert_eq!(
        validate_for_signing(&policy, &member_index(), &proxy_cidrs()),
        Err(AclError::TooManyTags(65))
    );
}

#[test]
fn test_vr1_tag_limit_accept() {
    let policy = base_policy();
    assert_eq!(validate_for_signing(&policy, &member_index(), &proxy_cidrs()), Ok(()));
}

#[test]
fn test_vr1_too_many_rules() {
    let mut policy = base_policy();
    policy.rules = (0..257)
        .map(|_| AclRule {
            action: Action::Accept,
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            proto: Proto::Wildcard,
            ports: None,
        })
        .collect();

    assert_eq!(
        validate_for_signing(&policy, &member_index(), &proxy_cidrs()),
        Err(AclError::TooManyRules(257))
    );
}

#[test]
fn test_vr1_rule_limit_accept() {
    let policy = base_policy();
    assert_eq!(validate_for_receiving(&policy, ACL_SCHEMA_VERSION), Ok(()));
}

#[test]
fn test_vr2_tag_name_strict_accept() {
    assert_eq!(TagName::try_from_str("Server.prod_01"), Ok(tag("Server.prod_01")));
}

#[test]
fn test_vr2_tag_name_rejects_colon() {
    assert_eq!(
        TagName::try_from_str("bad:name"),
        Err(TagNameError::Charset(b':'))
    );
}

#[test]
fn test_vr3_phantom_fingerprint() {
    let mut policy = base_policy();
    policy.tags.insert(tag("ghost"), vec![fingerprint(99)]);

    assert_eq!(
        validate_for_signing(&policy, &member_index(), &proxy_cidrs()),
        Err(AclError::TagMemberNotFound("ghost".to_owned()))
    );
}

#[test]
fn test_vr3_known_fingerprint_accept() {
    let policy = base_policy();
    assert_eq!(validate_for_signing(&policy, &member_index(), &proxy_cidrs()), Ok(()));
}

#[test]
fn test_vr4_empty_src_rejected() {
    let mut policy = base_policy();
    policy.rules[0].src.clear();

    assert_eq!(
        validate_for_signing(&policy, &member_index(), &proxy_cidrs()),
        Err(AclError::EmptySrcOrDst(0))
    );
}

#[test]
fn test_vr4_non_empty_src_dst_accept() {
    let policy = base_policy();
    assert_eq!(validate_for_signing(&policy, &member_index(), &proxy_cidrs()), Ok(()));
}

#[test]
fn test_vr5_undefined_tag() {
    let mut policy = base_policy();
    policy.rules[0].dst = vec![Selector::Tag(tag("missing"))];

    assert_eq!(
        validate_for_signing(&policy, &member_index(), &proxy_cidrs()),
        Err(AclError::UndefinedTag("missing".to_owned()))
    );
}

#[test]
fn test_vr5_defined_tag_accept() {
    let policy = base_policy();
    assert_eq!(validate_for_signing(&policy, &member_index(), &proxy_cidrs()), Ok(()));
}

#[test]
fn test_vr6_ports_not_applicable() {
    let mut policy = base_policy();
    policy.rules[0].proto = Proto::Icmp;

    assert_eq!(
        validate_for_signing(&policy, &member_index(), &proxy_cidrs()),
        Err(AclError::PortsNotApplicable("icmp".to_owned()))
    );
}

#[test]
fn test_vr6_tcp_ports_accept() {
    let policy = base_policy();
    assert_eq!(validate_for_signing(&policy, &member_index(), &proxy_cidrs()), Ok(()));
}

#[test]
fn test_vr7_invalid_port_range() {
    let mut policy = base_policy();
    policy.rules[0].ports = Some(vec![PortSpec::Range(100, 10)]);

    assert_eq!(
        validate_for_signing(&policy, &member_index(), &proxy_cidrs()),
        Err(AclError::InvalidPortRange(100, 10))
    );
}

#[test]
fn test_vr7_valid_port_range_accept() {
    let policy = base_policy();
    assert_eq!(validate_for_signing(&policy, &member_index(), &proxy_cidrs()), Ok(()));
}

#[test]
fn test_vr8_invalid_prefix_len() {
    let mut policy = base_policy();
    policy.rules[0].dst = vec![Selector::Subnet(cidr_v4(0, 33))];

    assert_eq!(
        validate_for_signing(&policy, &member_index(), &proxy_cidrs()),
        Err(AclError::InvalidPrefixLen(33))
    );
}

#[test]
fn test_vr8_valid_prefix_len_accept() {
    let mut policy = base_policy();
    policy.rules[0].dst = vec![Selector::Subnet(cidr_v4(0, 24))];

    assert_eq!(validate_for_signing(&policy, &member_index(), &proxy_cidrs()), Ok(()));
}

#[test]
fn test_vr9_subnet_orphan() {
    let mut policy = base_policy();
    policy.rules[0].dst = vec![Selector::Subnet(cidr_v4(5, 24))];

    assert_eq!(
        validate_for_signing(&policy, &member_index(), &proxy_cidrs()),
        Err(AclError::SubnetOrphan("10.0.0.5/24".to_owned()))
    );
}

#[test]
fn test_vr9_subnet_present_accept() {
    let mut policy = base_policy();
    policy.rules[0].dst = vec![Selector::Subnet(cidr_v4(0, 24))];

    assert_eq!(validate_for_signing(&policy, &member_index(), &proxy_cidrs()), Ok(()));
}

#[test]
fn test_vr10_schema_too_new() {
    let mut policy = base_policy();
    policy.schema_version = 2;

    assert_eq!(
        validate_for_receiving(&policy, 1),
        Err(AclError::UnsupportedSchemaVersion {
            got: 2,
            max_supported: 1,
        })
    );
}

#[test]
fn test_vr10_schema_supported_accept() {
    let policy = base_policy();
    assert_eq!(validate_for_receiving(&policy, ACL_SCHEMA_VERSION), Ok(()));
}

#[test]
fn test_vr11_receiving_rechecks_ports() {
    let mut policy = base_policy();
    policy.rules[0].proto = Proto::Wildcard;

    assert_eq!(
        validate_for_receiving(&policy, ACL_SCHEMA_VERSION),
        Err(AclError::PortsNotApplicable("*".to_owned()))
    );
}

#[test]
fn test_vr11_receiving_accepts_valid_policy() {
    let policy = base_policy();
    assert_eq!(validate_for_receiving(&policy, ACL_SCHEMA_VERSION), Ok(()));
}
