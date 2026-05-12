use easytier::common::config::{ConfigLoader, TomlConfigLoader};
use easytier::trust::TrustDomainId;

fn tdid_hex(byte: u8) -> String {
    let mut out = String::with_capacity(64);
    for _ in 0..32 {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("writing to string cannot fail");
    }
    out
}

#[test]
fn test_toml_parses_relay_serving_section() {
    let config = TomlConfigLoader::new_from_str(&format!(
        r#"
[trust_domain]
domain_dir = "/tmp/domain"
network_local_id = "office-net"
sk_self_password_env = "SK_PASS"

[[trust_domain.relay_serving]]
foreign_root_pk_hex = "{}"
can_relay_data = true
can_assist_holepunch = false
expires_at = 1800000000

[[trust_domain.relay_serving]]
foreign_root_pk_hex = "{}"
can_relay_data = false
can_assist_holepunch = true
expires_at = 1800000001
"#,
        tdid_hex(1),
        tdid_hex(2)
    ))
    .unwrap();

    let trust_domain = config.get_trust_domain().unwrap();

    assert_eq!(trust_domain.relay_serving.len(), 2);
    assert_eq!(trust_domain.relay_serving[0].foreign_root_pk_hex, tdid_hex(1));
    assert_eq!(trust_domain.relay_serving[1].foreign_root_pk_hex, tdid_hex(2));
}

#[test]
fn test_get_relay_grant_table_returns_configured_entries() {
    let config = TomlConfigLoader::new_from_str(&format!(
        r#"
[trust_domain]
domain_dir = "/tmp/domain"
network_local_id = "office-net"
sk_self_password_env = "SK_PASS"

[[trust_domain.relay_serving]]
foreign_root_pk_hex = "{}"
can_relay_data = true
can_assist_holepunch = false
expires_at = 1800000000
"#,
        tdid_hex(7)
    ))
    .unwrap();

    let table = config.get_relay_grant_table();
    let capabilities = table.permits(&TrustDomainId([7; 32]), 1700000000).unwrap();

    assert!(capabilities.can_relay_data);
    assert!(!capabilities.can_assist_holepunch);
}

#[test]
fn test_default_config_relay_grant_table_is_empty() {
    let config = TomlConfigLoader::new_from_str("").unwrap();

    assert!(config.get_relay_grant_table().permits(&TrustDomainId([9; 32]), 1700000000).is_none());
}
