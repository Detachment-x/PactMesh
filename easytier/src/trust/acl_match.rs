//! ACL selector matching and first-match policy decisions (T-037).
//!
//! Applies `network_state.payload.acl` to one packet 5-tuple.

use std::{collections::BTreeMap, net::IpAddr};

use pnet::ipnetwork::IpNetwork as IpNet;

use super::acl::{AclPolicy, Action, Cidr, DeviceFingerprint, PortSpec, Proto, Selector, TagName};

/// In-memory view of `acl.tags` used during packet evaluation.
pub type TagsMap = BTreeMap<TagName, Vec<DeviceFingerprint>>;

/// Packet 5-tuple used by stateless ACL evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketTuple {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub proto: u8,
    pub src_port: u16,
    pub dst_port: u16,
}

/// Per-endpoint context needed by `decide`.
#[derive(Debug, Clone, Copy)]
pub struct PeerMatchContext<'a> {
    pub peer_fp: &'a DeviceFingerprint,
    pub tags: &'a TagsMap,
    pub proxy_cidrs: &'a [(DeviceFingerprint, Cidr)],
}

/// Match one selector against one peer fingerprint + IP tuple.
pub fn selector_match(
    sel: &Selector,
    peer_fp: &DeviceFingerprint,
    peer_ip: IpAddr,
    tags: &TagsMap,
    proxy_cidrs: &[(DeviceFingerprint, Cidr)],
) -> bool {
    match sel {
        Selector::Wildcard => true,
        Selector::Tag(tag) => tags
            .get(tag)
            .is_some_and(|members| members.contains(peer_fp)),
        Selector::Device(expected) => expected == peer_fp,
        Selector::Subnet(cidr) => {
            cidr_contains(*cidr, peer_ip)
                && proxy_cidrs
                    .iter()
                    .any(|(_, advertised)| advertised == cidr)
        }
        // T-039 adds hostname-index resolution; before that, hostname selectors never match.
        Selector::Hostname(_) => false,
    }
}

/// Evaluate `policy` against one packet using first-match semantics.
pub fn decide(
    policy: &AclPolicy,
    packet: &PacketTuple,
    src_ctx: PeerMatchContext<'_>,
    dst_ctx: PeerMatchContext<'_>,
) -> Action {
    for rule in &policy.rules {
        let match_src = rule.src.iter().any(|selector| {
            selector_match(
                selector,
                src_ctx.peer_fp,
                packet.src_ip,
                src_ctx.tags,
                src_ctx.proxy_cidrs,
            )
        });
        let match_dst = rule.dst.iter().any(|selector| {
            selector_match(
                selector,
                dst_ctx.peer_fp,
                packet.dst_ip,
                dst_ctx.tags,
                dst_ctx.proxy_cidrs,
            )
        });
        let match_proto = proto_matches(rule.proto, packet.proto);
        let match_port = rule
            .ports
            .as_ref()
            .is_none_or(|ports| ports.iter().any(|port| port_matches(*port, packet.dst_port)));

        if match_src && match_dst && match_proto && match_port {
            return rule.action;
        }
    }

    policy.default_action
}

fn proto_matches(rule_proto: Proto, packet_proto: u8) -> bool {
    match rule_proto {
        Proto::Wildcard => true,
        Proto::Icmp => packet_proto == 1,
        Proto::Tcp => packet_proto == 6,
        Proto::Udp => packet_proto == 17,
    }
}

fn port_matches(spec: PortSpec, dst_port: u16) -> bool {
    match spec {
        PortSpec::Single(port) => port == dst_port,
        PortSpec::Range(low, high) => (low..=high).contains(&dst_port),
    }
}

fn cidr_contains(cidr: Cidr, ip: IpAddr) -> bool {
    IpNet::new(cidr.addr, cidr.prefix_len)
        .is_ok_and(|network| network.contains(ip))
}
