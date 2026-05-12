//! Tests for `trust::acl_match` (T-037).

use std::{collections::BTreeMap, net::IpAddr};

use easytier::trust::{
    ACL_SCHEMA_VERSION, AclPolicy, AclRule, Action, Cidr, DeviceFingerprint, PacketTuple,
    PeerMatchContext, PortSpec, Proto, Selector, TagName, TagsMap, decide, selector_match,
};

fn fingerprint(byte: u8) -> DeviceFingerprint {
    DeviceFingerprint::new([byte; 32])
}

fn tag(name: &str) -> TagName {
    TagName::try_from_str(name).unwrap()
}

fn cidr(addr: [u8; 4], prefix_len: u8) -> Cidr {
    Cidr::new(IpAddr::from(addr), prefix_len)
}

fn tags_map() -> TagsMap {
    let mut tags = BTreeMap::new();
    tags.insert(tag("server"), vec![fingerprint(1), fingerprint(2)]);
    tags.insert(tag("ops"), vec![fingerprint(3)]);
    tags
}

fn proxy_cidrs() -> Vec<(DeviceFingerprint, Cidr)> {
    vec![
        (fingerprint(4), cidr([10, 42, 0, 0], 24)),
        (fingerprint(5), cidr([192, 168, 0, 0], 24)),
    ]
}

fn packet(dst_port: u16, proto: u8) -> PacketTuple {
    PacketTuple {
        src_ip: IpAddr::from([10, 0, 0, 10]),
        dst_ip: IpAddr::from([10, 42, 0, 15]),
        proto,
        src_port: 55555,
        dst_port,
    }
}

fn ctx<'a>(
    peer_fp: &'a DeviceFingerprint,
    tags: &'a TagsMap,
    proxy_cidrs: &'a [(DeviceFingerprint, Cidr)],
) -> PeerMatchContext<'a> {
    PeerMatchContext {
        peer_fp,
        tags,
        proxy_cidrs,
    }
}

#[test]
fn test_selector_wildcard_matches() {
    let tags = tags_map();
    let proxy = proxy_cidrs();

    assert!(selector_match(
        &Selector::Wildcard,
        &fingerprint(9),
        IpAddr::from([10, 0, 0, 9]),
        &tags,
        &proxy,
    ));
}

#[test]
fn test_selector_device_matches_exact_fp() {
    let tags = tags_map();
    let proxy = proxy_cidrs();

    assert!(selector_match(
        &Selector::Device(fingerprint(2)),
        &fingerprint(2),
        IpAddr::from([10, 0, 0, 2]),
        &tags,
        &proxy,
    ));
}

#[test]
fn test_selector_device_rejects_other_fp() {
    let tags = tags_map();
    let proxy = proxy_cidrs();

    assert!(!selector_match(
        &Selector::Device(fingerprint(2)),
        &fingerprint(8),
        IpAddr::from([10, 0, 0, 8]),
        &tags,
        &proxy,
    ));
}

#[test]
fn test_selector_tag_matches_member() {
    let tags = tags_map();
    let proxy = proxy_cidrs();

    assert!(selector_match(
        &Selector::Tag(tag("server")),
        &fingerprint(1),
        IpAddr::from([10, 0, 0, 1]),
        &tags,
        &proxy,
    ));
}

#[test]
fn test_selector_tag_rejects_non_member() {
    let tags = tags_map();
    let proxy = proxy_cidrs();

    assert!(!selector_match(
        &Selector::Tag(tag("ops")),
        &fingerprint(2),
        IpAddr::from([10, 0, 0, 2]),
        &tags,
        &proxy,
    ));
}

#[test]
fn test_selector_subnet_matches_when_ip_in_range_and_advertised() {
    let tags = tags_map();
    let proxy = proxy_cidrs();

    assert!(selector_match(
        &Selector::Subnet(cidr([10, 42, 0, 0], 24)),
        &fingerprint(4),
        IpAddr::from([10, 42, 0, 88]),
        &tags,
        &proxy,
    ));
}

#[test]
fn test_selector_subnet_rejects_ip_out_of_range() {
    let tags = tags_map();
    let proxy = proxy_cidrs();

    assert!(!selector_match(
        &Selector::Subnet(cidr([10, 42, 0, 0], 24)),
        &fingerprint(4),
        IpAddr::from([10, 43, 0, 1]),
        &tags,
        &proxy,
    ));
}

#[test]
fn test_selector_subnet_rejects_unadvertised_cidr() {
    let tags = tags_map();
    let proxy = proxy_cidrs();

    assert!(!selector_match(
        &Selector::Subnet(cidr([10, 99, 0, 0], 24)),
        &fingerprint(7),
        IpAddr::from([10, 99, 0, 9]),
        &tags,
        &proxy,
    ));
}

#[test]
fn test_decide_port_range_matches_dst_port() {
    let tags = tags_map();
    let proxy = proxy_cidrs();
    let src_fp = fingerprint(3);
    let dst_fp = fingerprint(1);
    let policy = AclPolicy {
        tags: tags.clone(),
        rules: vec![AclRule {
            action: Action::Accept,
            src: vec![Selector::Tag(tag("ops"))],
            dst: vec![Selector::Tag(tag("server"))],
            proto: Proto::Tcp,
            ports: Some(vec![PortSpec::Range(80, 90)]),
        }],
        default_action: Action::Drop,
        schema_version: ACL_SCHEMA_VERSION,
    };

    assert_eq!(
        decide(
            &policy,
            &packet(88, 6),
            ctx(&src_fp, &tags, &proxy),
            ctx(&dst_fp, &tags, &proxy)
        ),
        Action::Accept
    );
}

#[test]
fn test_decide_proto_mismatch_falls_back_default() {
    let tags = tags_map();
    let proxy = proxy_cidrs();
    let src_fp = fingerprint(3);
    let dst_fp = fingerprint(1);
    let policy = AclPolicy {
        tags: tags.clone(),
        rules: vec![AclRule {
            action: Action::Accept,
            src: vec![Selector::Tag(tag("ops"))],
            dst: vec![Selector::Tag(tag("server"))],
            proto: Proto::Udp,
            ports: Some(vec![PortSpec::Single(53)]),
        }],
        default_action: Action::Drop,
        schema_version: ACL_SCHEMA_VERSION,
    };

    assert_eq!(
        decide(
            &policy,
            &packet(53, 6),
            ctx(&src_fp, &tags, &proxy),
            ctx(&dst_fp, &tags, &proxy)
        ),
        Action::Drop
    );
}

#[test]
fn test_decide_default_drop_when_no_rule_matches() {
    let tags = tags_map();
    let proxy = proxy_cidrs();
    let src_fp = fingerprint(8);
    let dst_fp = fingerprint(9);
    let policy = AclPolicy {
        tags: tags.clone(),
        rules: vec![AclRule {
            action: Action::Accept,
            src: vec![Selector::Tag(tag("ops"))],
            dst: vec![Selector::Tag(tag("server"))],
            proto: Proto::Tcp,
            ports: Some(vec![PortSpec::Single(22)]),
        }],
        default_action: Action::Drop,
        schema_version: ACL_SCHEMA_VERSION,
    };

    assert_eq!(
        decide(
            &policy,
            &packet(22, 6),
            ctx(&src_fp, &tags, &proxy),
            ctx(&dst_fp, &tags, &proxy)
        ),
        Action::Drop
    );
}

#[test]
fn test_decide_default_accept_when_no_rule_matches() {
    let tags = tags_map();
    let proxy = proxy_cidrs();
    let src_fp = fingerprint(8);
    let dst_fp = fingerprint(9);
    let policy = AclPolicy {
        tags: tags.clone(),
        rules: vec![AclRule {
            action: Action::Drop,
            src: vec![Selector::Tag(tag("ops"))],
            dst: vec![Selector::Tag(tag("server"))],
            proto: Proto::Tcp,
            ports: Some(vec![PortSpec::Single(22)]),
        }],
        default_action: Action::Accept,
        schema_version: ACL_SCHEMA_VERSION,
    };

    assert_eq!(
        decide(
            &policy,
            &packet(22, 6),
            ctx(&src_fp, &tags, &proxy),
            ctx(&dst_fp, &tags, &proxy)
        ),
        Action::Accept
    );
}

#[test]
fn test_decide_first_match_order_sensitive() {
    let tags = tags_map();
    let proxy = proxy_cidrs();
    let src_fp = fingerprint(3);
    let dst_fp = fingerprint(1);
    let packet = packet(22, 6);

    let accept_then_drop = AclPolicy {
        tags: tags.clone(),
        rules: vec![
            AclRule {
                action: Action::Accept,
                src: vec![Selector::Tag(tag("ops"))],
                dst: vec![Selector::Tag(tag("server"))],
                proto: Proto::Tcp,
                ports: Some(vec![PortSpec::Single(22)]),
            },
            AclRule {
                action: Action::Drop,
                src: vec![Selector::Wildcard],
                dst: vec![Selector::Wildcard],
                proto: Proto::Wildcard,
                ports: None,
            },
        ],
        default_action: Action::Drop,
        schema_version: ACL_SCHEMA_VERSION,
    };
    let drop_then_accept = AclPolicy {
        tags: tags.clone(),
        rules: vec![
            AclRule {
                action: Action::Drop,
                src: vec![Selector::Wildcard],
                dst: vec![Selector::Wildcard],
                proto: Proto::Wildcard,
                ports: None,
            },
            AclRule {
                action: Action::Accept,
                src: vec![Selector::Tag(tag("ops"))],
                dst: vec![Selector::Tag(tag("server"))],
                proto: Proto::Tcp,
                ports: Some(vec![PortSpec::Single(22)]),
            },
        ],
        default_action: Action::Accept,
        schema_version: ACL_SCHEMA_VERSION,
    };

    assert_eq!(
        decide(
            &accept_then_drop,
            &packet,
            ctx(&src_fp, &tags, &proxy),
            ctx(&dst_fp, &tags, &proxy)
        ),
        Action::Accept
    );
    assert_eq!(
        decide(
            &drop_then_accept,
            &packet,
            ctx(&src_fp, &tags, &proxy),
            ctx(&dst_fp, &tags, &proxy)
        ),
        Action::Drop
    );
}
