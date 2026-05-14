//! Integration test crate root for the trust layer.
//!
//! Each submodule under `tests/trust/` is wired in via `#[path]` so
//! `cargo test --test trust` runs them as one binary. M0 keeps every
//! function `#[ignore = "pending T-XXX"]` so the harness compiles
//! while the implementation tasks (M2 §1–§7 + §3.5) are pending.

#[path = "trust/acl_match_test.rs"]
mod acl_match_test;
#[path = "trust/acl_test.rs"]
mod acl_test;
#[path = "trust/acl_validate_test.rs"]
mod acl_validate_test;
#[path = "trust/bootstrap_self_test.rs"]
mod bootstrap_self_test;
#[path = "trust/bootstrap_test.rs"]
mod bootstrap_test;
#[path = "trust/borrowed_relay_resolver_test.rs"]
mod borrowed_relay_resolver_test;
#[path = "trust/cache_test.rs"]
mod cache_test;
#[path = "trust/cbor_test.rs"]
mod cbor_test;
#[path = "trust/config_sync_test.rs"]
mod config_sync_test;
#[path = "trust/device_view_test.rs"]
mod device_view_test;
#[path = "trust/hostname_test.rs"]
mod hostname_test;
#[path = "trust/identity_test.rs"]
mod identity_test;
#[path = "trust/join_forward_test.rs"]
mod join_forward_test;
#[path = "trust/join_test.rs"]
mod join_test;
#[path = "trust/member_cert_test.rs"]
mod member_cert_test;
#[path = "trust/network_state_receiver_test.rs"]
mod network_state_receiver_test;
#[path = "trust/network_state_test.rs"]
mod network_state_test;
#[path = "trust/pool_test.rs"]
mod pool_test;
#[path = "trust/relay_grant_test.rs"]
mod relay_grant_test;
#[path = "trust/revocation_test.rs"]
mod revocation_test;
#[path = "trust/services_wired_test.rs"]
mod services_wired_test;
#[path = "trust/trust_domain_meta_test.rs"]
mod trust_domain_meta_test;
#[path = "trust/trust_pool_foreign_test.rs"]
mod trust_pool_foreign_test;
#[path = "trust/types_test.rs"]
mod types_test;
