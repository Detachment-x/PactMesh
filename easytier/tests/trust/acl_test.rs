//! Tests for `trust::acl` (T-035).

use std::{collections::BTreeMap, net::IpAddr, str::FromStr};

use easytier::trust::acl::{
    ACL_SCHEMA_VERSION, AclPolicy, AclRule, Action, Cidr, DeviceFingerprint, PortSpec, Proto,
    Selector, TagName, TagNameError,
};
use easytier::trust::{HostnameLabel, from_cbor, to_canonical_cbor};
use pnet::ipnetwork::IpNetwork as IpNet;

fn fingerprint(byte: u8) -> DeviceFingerprint {
    DeviceFingerprint::new([byte; 32])
}

fn tag(name: &str) -> TagName {
    TagName::try_from_str(name).unwrap()
}

fn hostname(name: &str) -> HostnameLabel {
    HostnameLabel::try_from_str(name).unwrap()
}

fn cidr(text: &str) -> Cidr {
    match IpNet::from_str(text).unwrap() {
        IpNet::V4(net) => Cidr::new(IpAddr::V4(net.ip()), net.prefix()),
        IpNet::V6(net) => Cidr::new(IpAddr::V6(net.ip()), net.prefix()),
    }
}

fn sample_policy(reverse_members: bool, reverse_tag_inserts: bool) -> AclPolicy {
    let member_sets = [
        ("db", vec![fingerprint(2), fingerprint(1)]),
        ("ops", vec![fingerprint(5), fingerprint(4)]),
        ("qa", vec![fingerprint(8), fingerprint(7)]),
        ("server", vec![fingerprint(3), fingerprint(2), fingerprint(1)]),
        ("vpn", vec![fingerprint(9), fingerprint(6)]),
    ];

    let mut tags = BTreeMap::new();
    let iter: Box<dyn Iterator<Item = &(&'static str, Vec<DeviceFingerprint>)>> = if reverse_tag_inserts {
        Box::new(member_sets.iter().rev())
    } else {
        Box::new(member_sets.iter())
    };
    for (name, members) in iter {
        let mut members = members.clone();
        members.sort_unstable();
        if reverse_members {
            members.reverse();
        }
        tags.insert(tag(name), members);
    }

    let rules = vec![
        AclRule {
            action: Action::Accept,
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Tag(tag("server"))],
            proto: Proto::Tcp,
            ports: Some(vec![PortSpec::Single(22), PortSpec::Single(80), PortSpec::Single(443)]),
        },
        AclRule {
            action: Action::Accept,
            src: vec![Selector::Tag(tag("ops"))],
            dst: vec![Selector::Device(fingerprint(1))],
            proto: Proto::Udp,
            ports: Some(vec![PortSpec::Single(53)]),
        },
        AclRule {
            action: Action::Drop,
            src: vec![Selector::Device(fingerprint(2))],
            dst: vec![Selector::Subnet(cidr("10.10.0.0/24"))],
            proto: Proto::Wildcard,
            ports: None,
        },
        AclRule {
            action: Action::Accept,
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Hostname(hostname("git-01"))],
            proto: Proto::Tcp,
            ports: Some(vec![PortSpec::Single(9418)]),
        },
        AclRule {
            action: Action::Accept,
            src: vec![Selector::Subnet(cidr("2001:db8::/64"))],
            dst: vec![Selector::Tag(tag("vpn"))],
            proto: Proto::Icmp,
            ports: None,
        },
        AclRule {
            action: Action::Drop,
            src: vec![Selector::Tag(tag("qa"))],
            dst: vec![Selector::Tag(tag("db"))],
            proto: Proto::Tcp,
            ports: Some(vec![PortSpec::Range(5432, 5433)]),
        },
        AclRule {
            action: Action::Accept,
            src: vec![Selector::Device(fingerprint(3))],
            dst: vec![Selector::Device(fingerprint(4))],
            proto: Proto::Udp,
            ports: Some(vec![PortSpec::Range(10000, 10010)]),
        },
        AclRule {
            action: Action::Accept,
            src: vec![Selector::Tag(tag("server"))],
            dst: vec![Selector::Wildcard],
            proto: Proto::Wildcard,
            ports: None,
        },
        AclRule {
            action: Action::Drop,
            src: vec![Selector::Hostname(hostname("db-01"))],
            dst: vec![Selector::Tag(tag("ops"))],
            proto: Proto::Tcp,
            ports: Some(vec![PortSpec::Single(5432)]),
        },
        AclRule {
            action: Action::Accept,
            src: vec![Selector::Tag(tag("vpn"))],
            dst: vec![Selector::Subnet(cidr("192.168.10.0/24"))],
            proto: Proto::Wildcard,
            ports: None,
        },
    ];

    AclPolicy {
        tags,
        rules,
        default_action: Action::Accept,
        schema_version: ACL_SCHEMA_VERSION,
    }
}

#[test]
fn test_selector_round_trip_cbor() {
    let selectors = vec![
        Selector::Wildcard,
        Selector::Tag(tag("server.prod")),
        Selector::Device(fingerprint(9)),
        Selector::Subnet(cidr("10.42.0.0/24")),
        Selector::Hostname(hostname("Edge-01")),
    ];

    for selector in selectors {
        let encoded = to_canonical_cbor(&selector);
        let decoded: Selector = from_cbor(&encoded).unwrap();
        assert_eq!(decoded, selector);
        assert_eq!(to_canonical_cbor(&decoded), encoded);
    }
}

#[test]
fn test_tag_name_charset_strict() {
    let valid = TagName::try_from_str("Server.prod_01").unwrap();
    assert_eq!(valid.as_str(), "Server.prod_01");
    assert_eq!(TagName::try_from_str(""), Err(TagNameError::Length(0)));
    assert_eq!(TagName::try_from_str("bad:name"), Err(TagNameError::Charset(b':')));
    assert_eq!(TagName::try_from_str("中文"), Err(TagNameError::Charset(0xe4)));

    let too_long = "a".repeat(33);
    assert_eq!(
        TagName::try_from_str(&too_long),
        Err(TagNameError::Length(33))
    );
}

#[test]
fn test_acl_policy_round_trip_cbor() {
    let policy = sample_policy(false, false);
    let encoded = to_canonical_cbor(&policy);
    let decoded: AclPolicy = from_cbor(&encoded).unwrap();

    assert_eq!(decoded, policy);
    assert_eq!(to_canonical_cbor(&decoded), encoded);
    assert!(decoded.rules.iter().any(|rule| {
        rule.dst
            .iter()
            .any(|selector| matches!(selector, Selector::Hostname(_)))
            || rule.src
                .iter()
                .any(|selector| matches!(selector, Selector::Hostname(_)))
    }));
}

#[test]
fn test_deterministic_encoding() {
    let canonical = sample_policy(false, false);
    let reordered = sample_policy(true, true);

    assert_eq!(to_canonical_cbor(&canonical), to_canonical_cbor(&reordered));
}
