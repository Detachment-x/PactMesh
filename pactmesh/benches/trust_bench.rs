use std::{net::IpAddr, str::FromStr};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ed25519_dalek::SigningKey;
use pactmesh::trust::{
    ACL_SCHEMA_VERSION, AclPolicy, AclRule, Action, Capabilities, Cidr, DeviceFingerprint,
    MemberCert, NetworkLocalId, NetworkStatePayload, PacketTuple, PeerMatchContext, PortSpec,
    Proto, RevocationReason, RevokedCert, Selector, TagName, TagsMap, TrustDomainPool,
    TrustDomainRoot, UnsignedMemberCert, UnsignedNetworkState, to_canonical_cbor,
};
use pnet::ipnetwork::IpNetwork as IpNet;
use rand::rngs::OsRng;

fn sample_cert(root: &TrustDomainRoot, index: u64) -> MemberCert {
    UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str("office-net").unwrap(),
        device_pk: SigningKey::generate(&mut OsRng).verifying_key(),
        device_label: format!("device-{index}"),
        not_before: 1_715_000_000,
        expires_at: 1_816_000_000,
        capabilities: Capabilities {
            can_relay_data: true,
            can_relay_control: index % 2 == 0,
            can_proxy_subnet: vec![IpNet::from_str("10.0.0.0/24").unwrap()],
        },
        network_state_version_ref: 1,
        hostname: None,
    }
    .sign(root)
}

fn sample_pool(root: &TrustDomainRoot, certs: &[MemberCert]) -> TrustDomainPool {
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    let revoked_certs = certs
        .iter()
        .take(100)
        .map(|cert| RevokedCert {
            cert_fingerprint: cert.fingerprint(),
            revoked_at: 1_715_000_001,
            reason_code: RevocationReason::Removed,
            reason_note: None,
        })
        .collect();
    let state = UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str("office-net").unwrap(),
        version: 1,
        payload: NetworkStatePayload {
            member_cert_index: Vec::new(),
            revoked_certs,
            disabled_certs: Vec::new(),
            acl: Vec::new(),
            routes: Vec::new(),
        },
    }
    .sign(root);
    pool.apply_network_state(state).unwrap();
    pool
}

fn tag(name: &str) -> TagName {
    TagName::try_from_str(name).unwrap()
}

fn fingerprint(byte: u8) -> DeviceFingerprint {
    DeviceFingerprint::new([byte; 32])
}

fn bench_handshake_full_noise_with_cert(c: &mut Criterion) {
    let root = TrustDomainRoot::generate();
    let cert = sample_cert(&root, 1);
    c.bench_function("bench_handshake_full_noise_with_cert", |b| {
        b.iter(|| {
            let wire = to_canonical_cbor(&cert);
            let decoded: MemberCert = pactmesh::trust::from_cbor(&wire).unwrap();
            decoded.verify(&root.public_key()).unwrap();
        })
    });
}

fn bench_member_cert_verify_signature_only(c: &mut Criterion) {
    let root = TrustDomainRoot::generate();
    let cert = sample_cert(&root, 2);
    c.bench_function("bench_member_cert_verify_signature_only", |b| {
        b.iter(|| cert.verify(&root.public_key()).unwrap())
    });
}

fn bench_trust_domain_pool_lookup(c: &mut Criterion) {
    let root = TrustDomainRoot::generate();
    let certs = (0..1000)
        .map(|idx| sample_cert(&root, idx))
        .collect::<Vec<_>>();
    let pool = sample_pool(&root, &certs);
    let active = &certs[500];
    c.bench_function("bench_trust_domain_pool_lookup", |b| {
        b.iter(|| pool.verify_member_cert(active, 1_716_000_000).unwrap())
    });
}

fn bench_acl_decide_first_match_in_256_rules(c: &mut Criterion) {
    let mut tags = TagsMap::new();
    tags.insert(tag("client"), vec![fingerprint(1)]);
    tags.insert(tag("server"), vec![fingerprint(2)]);
    let mut rules = Vec::new();
    for idx in 0..255u16 {
        rules.push(AclRule {
            action: Action::Drop,
            src: vec![Selector::Device(fingerprint(200))],
            dst: vec![Selector::Wildcard],
            proto: Proto::Tcp,
            ports: Some(vec![PortSpec::Single(idx)]),
        });
    }
    rules.push(AclRule {
        action: Action::Accept,
        src: vec![Selector::Tag(tag("client"))],
        dst: vec![Selector::Tag(tag("server"))],
        proto: Proto::Tcp,
        ports: Some(vec![PortSpec::Single(443)]),
    });
    let policy = AclPolicy {
        tags: tags.clone(),
        rules,
        default_action: Action::Drop,
        schema_version: ACL_SCHEMA_VERSION,
    };
    let packet = PacketTuple {
        src_ip: IpAddr::from([10, 0, 0, 1]),
        dst_ip: IpAddr::from([10, 0, 0, 2]),
        proto: 6,
        src_port: 50000,
        dst_port: 443,
    };
    let empty_proxy: Vec<(DeviceFingerprint, Cidr)> = Vec::new();
    let src = fingerprint(1);
    let dst = fingerprint(2);
    let src_ctx = PeerMatchContext {
        peer_fp: &src,
        tags: &tags,
        proxy_cidrs: &empty_proxy,
    };
    let dst_ctx = PeerMatchContext {
        peer_fp: &dst,
        tags: &tags,
        proxy_cidrs: &empty_proxy,
    };
    c.bench_function("bench_acl_decide_first_match_in_256_rules", |b| {
        b.iter(|| pactmesh::trust::decide(&policy, &packet, src_ctx, dst_ctx))
    });
}

fn bench_cbor_encode_member_cert(c: &mut Criterion) {
    let root = TrustDomainRoot::generate();
    let cert = sample_cert(&root, 3);
    let mut group = c.benchmark_group("bench_cbor_encode_member_cert");
    group.bench_with_input(
        BenchmarkId::from_parameter("member_cert"),
        &cert,
        |b, cert| b.iter(|| to_canonical_cbor(cert)),
    );
    group.finish();
}

criterion_group!(
    benches,
    bench_handshake_full_noise_with_cert,
    bench_member_cert_verify_signature_only,
    bench_trust_domain_pool_lookup,
    bench_acl_decide_first_match_in_256_rules,
    bench_cbor_encode_member_cert
);
criterion_main!(benches);
