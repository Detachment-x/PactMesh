use std::{collections::BTreeMap, str::FromStr};

use ed25519_dalek::VerifyingKey;
use pactmesh::trust::{
    ACL_SCHEMA_VERSION, AclPolicy, Action, Capabilities, DeviceFingerprint, DeviceRole,
    DeviceStatus, MemberCertIndexEntry, NetworkLocalId, NetworkStatePayload, SignKey, TagName,
    TrustDomainRoot, UnsignedMemberCert, UnsignedNetworkState, encode_device_id, to_canonical_cbor,
    view_for_member,
};
use pnet::ipnetwork::IpNetwork as IpNet;

fn member_cert(root: &TrustDomainRoot, network_id: &str) -> pactmesh::trust::MemberCert {
    let sk = SignKey::generate();
    let device_pk = VerifyingKey::from_bytes(&sk.verify_key().0).unwrap();
    UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str(network_id).unwrap(),
        device_pk,
        device_label: "node-a".to_owned(),
        not_before: 10,
        expires_at: 1000,
        capabilities: Capabilities {
            can_be_exit_node: false,
            can_relay_data: true,
            can_relay_control: false,
            can_proxy_subnet: vec![IpNet::from_str("10.1.0.0/24").unwrap()],
        },
        network_state_version_ref: 1,
        hostname: None,
    }
    .sign(root)
}

fn signed_state(
    root: &TrustDomainRoot,
    network_id: &str,
    entry: MemberCertIndexEntry,
) -> pactmesh::trust::SignedNetworkState {
    signed_state_with_tags(root, network_id, entry, BTreeMap::new())
}

fn signed_state_with_tags(
    root: &TrustDomainRoot,
    network_id: &str,
    entry: MemberCertIndexEntry,
    tags: BTreeMap<TagName, Vec<DeviceFingerprint>>,
) -> pactmesh::trust::SignedNetworkState {
    let acl = AclPolicy {
        tags,
        rules: Vec::new(),
        default_action: Action::Accept,
        schema_version: ACL_SCHEMA_VERSION,
    };
    UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str(network_id).unwrap(),
        version: 1,
        payload: NetworkStatePayload {
            member_cert_index: vec![entry],
            revoked_certs: Vec::new(),
            disabled_certs: Vec::new(),
            acl: to_canonical_cbor(&acl),
            routes: Vec::new(),
            peer_hints: Vec::new(),
            ip_assignments: Vec::new(),
            capability_grants: Vec::new(),
            hostname_bindings: Vec::new(),
        },
    }
    .sign(root)
}

#[test]
fn test_device_view_separates_role_from_capabilities() {
    let root = TrustDomainRoot::generate();
    let network_id = "office-net";
    let cert = member_cert(&root, network_id);
    let entry = MemberCertIndexEntry {
        fingerprint: cert.fingerprint(),
        device_label: cert.details.device_label.clone(),
        issued_at: cert.details.not_before,
        expires_at: cert.details.expires_at,
    };
    let state = signed_state(&root, network_id, entry.clone());

    let view = view_for_member(&entry, Some(&cert), &state, network_id, None, false, 20);

    assert_eq!(view.role, DeviceRole::Member);
    assert!(view.capabilities.relay_data);
    assert_eq!(view.capabilities.proxy_subnets, vec!["10.1.0.0/24"]);
    assert_eq!(view.status, DeviceStatus::Active);
}

#[test]
fn test_device_view_root_is_local_governance_identity_only() {
    let root = TrustDomainRoot::generate();
    let network_id = "office-net";
    let cert = member_cert(&root, network_id);
    let entry = MemberCertIndexEntry {
        fingerprint: cert.fingerprint(),
        device_label: cert.details.device_label.clone(),
        issued_at: cert.details.not_before,
        expires_at: cert.details.expires_at,
    };
    let state = signed_state(&root, network_id, entry.clone());
    let local_id = encode_device_id(cert.details.device_pk.as_bytes());

    let view = view_for_member(
        &entry,
        Some(&cert),
        &state,
        network_id,
        Some(&local_id),
        true,
        20,
    );

    assert_eq!(view.role, DeviceRole::Root);
    assert!(view.capabilities.relay_data);
}

#[test]
fn test_device_view_expired_is_status_not_role() {
    let root = TrustDomainRoot::generate();
    let network_id = "office-net";
    let cert = member_cert(&root, network_id);
    let entry = MemberCertIndexEntry {
        fingerprint: cert.fingerprint(),
        device_label: cert.details.device_label.clone(),
        issued_at: cert.details.not_before,
        expires_at: 10,
    };
    let state = signed_state(&root, network_id, entry.clone());

    let view = view_for_member(&entry, Some(&cert), &state, network_id, None, false, 20);

    assert_eq!(view.role, DeviceRole::Member);
    assert_eq!(view.status, DeviceStatus::Expired);
}

#[test]
fn test_device_view_tags_are_human_grouping_not_role_or_capability() {
    let root = TrustDomainRoot::generate();
    let network_id = "office-net";
    let cert = member_cert(&root, network_id);
    let entry = MemberCertIndexEntry {
        fingerprint: cert.fingerprint(),
        device_label: cert.details.device_label.clone(),
        issued_at: cert.details.not_before,
        expires_at: cert.details.expires_at,
    };
    let mut tags = BTreeMap::new();
    tags.insert(
        TagName::try_from_str("ops").unwrap(),
        vec![DeviceFingerprint(cert.fingerprint().0)],
    );
    let state = signed_state_with_tags(&root, network_id, entry.clone(), tags);

    let view = view_for_member(&entry, Some(&cert), &state, network_id, None, false, 20);

    assert_eq!(view.tags, vec!["ops"]);
    assert_eq!(view.role, DeviceRole::Member);
    assert!(view.capabilities.relay_data);
}
