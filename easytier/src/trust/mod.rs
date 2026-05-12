//! Trust layer for the privateNetwork fork.
//!
//! Implements the self-managed trust domain, signed `network_state`,
//! `trust_domain_meta`, member certificates, revocation, cross-domain
//! relay borrow, and the in-memory `TrustDomainPool` cache.
//!
//! See `trust-and-config-design.md` for the full design (§4 keys, §6
//! wire formats, §7 verification, §10 revocation, §11.9 relay session,
//! §18 MagicDNS) and `acl-schema-draft.md` for ACL CBOR layout.
//!
//! All on-the-wire types are encoded with CBOR Deterministic Encoding
//! (RFC 8949 §4.2) via `minicbor` 0.25 derive.

pub mod acl;
pub mod acl_error;
pub mod acl_validate;
pub mod acl_match;
pub mod cache;
pub mod cbor;
pub mod config_sync_client;
pub mod config_sync_service;
pub mod hostname;
pub mod identity;
pub mod join;
pub mod join_dedup;
pub mod join_forward_service;
pub mod member_cert;
pub mod network_bootstrap;
pub mod network_state;
pub mod pending_cert_queue;
pub mod pool;
pub mod relay_borrow;
pub mod revocation;
pub mod trust_domain_meta;
pub mod types;
pub mod wire;

pub use acl_error::AclError;
pub use acl_match::{PacketTuple, PeerMatchContext, TagsMap, decide, selector_match};
pub use acl_validate::{validate_for_receiving, validate_for_signing};
pub use acl::{
    ACL_SCHEMA_VERSION, MAX_RULES, MAX_SELECTORS_PER_RULE, MAX_TAG_MEMBERS,
    MAX_TAG_NAME_LEN, MAX_TAGS, AclPolicy, AclRule, Action, Cidr, DeviceFingerprint, PortSpec,
    Proto, Selector, TagName, TagNameError,
};
pub use cache::CachedMemberCert;
pub use cbor::{from_cbor, to_canonical_cbor, unwrap_armored, wrap_armored};
pub use hostname::{HostnameError, HostnameLabel};
pub use identity::{SignKey, TrustDomainRoot, VerifyKey};
pub use join::JoinRequest;
pub use member_cert::{Capabilities, MemberCert, UnsignedMemberCert};
pub use network_state::{
    MemberCertIndexEntry, NetworkStatePayload, SignedNetworkState, UnsignedNetworkState,
};
pub use network_bootstrap::NetworkBootstrap;
pub use pool::TrustDomainPool;
pub use relay_borrow::{
    BorrowedRelayProof, BorrowedRelayResolver, RelayCandidate, RelayGrantEntry, RelayGrantTable,
};
pub use revocation::{DisabledCert, RevocationReason, RevokedCert};
pub use trust_domain_meta::{
    ActiveRelay, RelayCapabilities, SignedTrustDomainMeta, UnsignedTrustDomainMeta,
};
pub use types::{
    MemberCertFingerprint, NetworkLocalId, NetworkLocalIdError, TrustDomainId, TrustError,
};
pub use wire::{
    WireError, join_request_from_envelope, join_request_to_envelope, member_cert_from_envelope,
    member_cert_to_envelope, signed_network_state_from_envelope,
    signed_network_state_to_envelope, trust_domain_meta_from_envelope,
    trust_domain_meta_to_envelope,
};
