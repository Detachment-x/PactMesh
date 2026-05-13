use easytier::{
    connector::manual::recovery_candidate_urls_for_diagnostics,
    trust::{
        NetworkLocalId, NetworkStatePayload, PeerHint, TrustDomainPool, TrustDomainRoot,
        UnsignedNetworkState, apply_lan_recovered_network_state,
    },
};

const NETWORK: &str = "office-net";
const NOW: u64 = 1_700_000_000;

fn network_id() -> NetworkLocalId {
    NetworkLocalId::try_from_str(NETWORK).unwrap()
}

fn peer_hint(url: &str) -> PeerHint {
    PeerHint {
        url: url.to_owned(),
        label: Some("new-public-peer".to_owned()),
        capabilities: vec!["public-reachable".to_owned()],
        updated_at: NOW,
        expires_at: Some(NOW + 3600),
    }
}

fn signed_state(
    root: &TrustDomainRoot,
    version: u64,
    hints: Vec<PeerHint>,
) -> easytier::trust::SignedNetworkState {
    UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: network_id(),
        version,
        payload: NetworkStatePayload {
            member_cert_index: Vec::new(),
            revoked_certs: Vec::new(),
            disabled_certs: Vec::new(),
            acl: Vec::new(),
            routes: Vec::new(),
            peer_hints: hints,
        },
    }
    .sign(root)
}

fn cache_path(dir: &tempfile::TempDir, trust_domain_id: &str) -> std::path::PathBuf {
    dir.path()
        .join("privateNetwork/peer-cache")
        .join(trust_domain_id)
        .join(format!("{NETWORK}.json"))
}

#[test]
fn test_signed_hint_restart_recovery_prefers_new_public_peer() {
    let root = TrustDomainRoot::generate();
    let state = signed_state(
        &root,
        2,
        vec![
            peer_hint("tcp://203.0.113.20:11010"),
            peer_hint("tcp://203.0.113.20:11010"),
            PeerHint {
                url: "tcp://203.0.113.10:11010".to_owned(),
                label: Some("old-dead-peer".to_owned()),
                capabilities: Vec::new(),
                updated_at: NOW - 3600,
                expires_at: Some(NOW - 1),
            },
        ],
    );

    let candidates = recovery_candidate_urls_for_diagnostics(
        Some(&state),
        None,
        &root.id().to_string(),
        NETWORK,
        NOW,
    );

    assert_eq!(
        candidates
            .signed_peer_hints
            .iter()
            .map(url::Url::to_string)
            .collect::<Vec<_>>(),
        vec!["tcp://203.0.113.20:11010"]
    );
    assert!(candidates.local_peer_cache.is_empty());
}

#[test]
fn test_local_cache_recovery_uses_last_successful_peer_when_state_has_no_hint() {
    let root = TrustDomainRoot::generate();
    let dir = tempfile::tempdir().unwrap();
    let path = cache_path(&dir, &root.id().to_string());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        format!(
            r#"{{
  "schema_version": 1,
  "entries": [
    {{
      "url": "tcp://203.0.113.30:11010",
      "peer_id": 7,
      "trust_domain_id": "{}",
      "network_local_id": "office-net",
      "last_success": {},
      "failures": 0
    }},
    {{
      "url": "tcp://203.0.113.40:11010",
      "peer_id": 8,
      "trust_domain_id": "{}",
      "network_local_id": "office-net",
      "last_success": {},
      "failures": 3
    }}
  ]
}}"#,
            root.id(),
            NOW - 60,
            root.id(),
            NOW - 60
        ),
    )
    .unwrap();

    let candidates = recovery_candidate_urls_for_diagnostics(
        None,
        Some(&path),
        &root.id().to_string(),
        NETWORK,
        NOW,
    );

    assert!(candidates.signed_peer_hints.is_empty());
    assert_eq!(
        candidates
            .local_peer_cache
            .iter()
            .map(url::Url::to_string)
            .collect::<Vec<_>>(),
        vec!["tcp://203.0.113.30:11010"]
    );
}

#[test]
fn test_lan_updated_peer_recovery_applies_signed_state_then_exposes_hint() {
    let root = TrustDomainRoot::generate();
    let mut pool = TrustDomainPool::new();
    pool.add_root(root.public_key().into());
    pool.apply_network_state(signed_state(&root, 1, Vec::new()))
        .unwrap();

    let recovered = signed_state(&root, 2, vec![peer_hint("tcp://203.0.113.50:11010")]);
    apply_lan_recovered_network_state(&mut pool, &root.id(), &network_id(), recovered).unwrap();

    let state = pool.network_state(&root.id(), &network_id()).unwrap();
    let candidates = recovery_candidate_urls_for_diagnostics(
        Some(state),
        None,
        &root.id().to_string(),
        NETWORK,
        NOW,
    );

    assert_eq!(
        candidates
            .signed_peer_hints
            .iter()
            .map(url::Url::to_string)
            .collect::<Vec<_>>(),
        vec!["tcp://203.0.113.50:11010"]
    );
}

#[test]
fn test_dead_old_ip_without_recovery_source_reports_non_trust_boundary() {
    let root = TrustDomainRoot::generate();
    let state = signed_state(&root, 1, Vec::new());
    let candidates = recovery_candidate_urls_for_diagnostics(
        Some(&state),
        None,
        &root.id().to_string(),
        NETWORK,
        NOW,
    );

    let reason = candidates.empty_reason().unwrap();
    assert!(reason.contains("no recovery candidates"));
    assert!(!reason.to_ascii_lowercase().contains("trust"));
}
