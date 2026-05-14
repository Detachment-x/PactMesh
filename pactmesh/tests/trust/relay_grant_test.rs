use pactmesh::trust::{RelayCapabilities, RelayGrantEntry, RelayGrantTable, TrustDomainId};

fn tdid(byte: u8) -> TrustDomainId {
    TrustDomainId([byte; 32])
}

fn caps(can_relay_data: bool, can_assist_holepunch: bool) -> RelayCapabilities {
    RelayCapabilities {
        can_relay_data,
        can_assist_holepunch,
    }
}

#[test]
fn test_permits_hit_returns_capabilities() {
    let expected = caps(true, false);
    let table = RelayGrantTable::from_entries(vec![RelayGrantEntry {
        foreign_root_pk: tdid(1),
        capabilities: expected.clone(),
        expires_at: 1_800_000_000,
    }]);

    assert_eq!(table.permits(&tdid(1), 1_700_000_000), Some(&expected));
}

#[test]
fn test_permits_miss_for_unknown_root() {
    let table = RelayGrantTable::from_entries(vec![RelayGrantEntry {
        foreign_root_pk: tdid(1),
        capabilities: caps(true, false),
        expires_at: 1_800_000_000,
    }]);

    assert_eq!(table.permits(&tdid(2), 1_700_000_000), None);
}

#[test]
fn test_permits_expired_returns_none() {
    let table = RelayGrantTable::from_entries(vec![RelayGrantEntry {
        foreign_root_pk: tdid(1),
        capabilities: caps(true, false),
        expires_at: 1_700_000_000,
    }]);

    assert_eq!(table.permits(&tdid(1), 1_700_000_000), None);
    assert_eq!(table.permits(&tdid(1), 1_700_000_001), None);
}

#[test]
fn test_permits_capabilities_relay_only_vs_holepunch_only() {
    let relay_only = caps(true, false);
    let holepunch_only = caps(false, true);
    let table = RelayGrantTable::from_entries(vec![
        RelayGrantEntry {
            foreign_root_pk: tdid(1),
            capabilities: relay_only.clone(),
            expires_at: 1_800_000_000,
        },
        RelayGrantEntry {
            foreign_root_pk: tdid(2),
            capabilities: holepunch_only.clone(),
            expires_at: 1_800_000_000,
        },
    ]);

    assert_eq!(table.permits(&tdid(1), 1_700_000_000), Some(&relay_only));
    assert_eq!(
        table.permits(&tdid(2), 1_700_000_000),
        Some(&holepunch_only)
    );
}
