//! Effective (runtime) capability / hostname resolution.
//!
//! A member cert carries a device's *identity* and an initial capability +
//! hostname grant. Post-issue edits live in `network_state` (`capability_grants`
//! / `hostname_bindings`, keyed by cert fingerprint) so they take effect without
//! reissuing the cert — see `trust-and-config-design.md` and the v0.5.0 unified
//! model. This module is the single source of the priority rule:
//!
//! > if `network_state` has an entry for the cert fingerprint → it wins;
//! > otherwise → fall back to the cert body.
//!
//! For hostnames the *absence* of a binding falls back to the cert, while a
//! binding whose `hostname` is `None` explicitly clears it.

use super::hostname::HostnameLabel;
use super::member_cert::{Capabilities, MemberCert};
use super::network_state::SignedNetworkState;
use super::types::MemberCertFingerprint;

/// Effective capabilities for `cert` under the current `state`.
pub fn effective_capabilities(cert: &MemberCert, state: &SignedNetworkState) -> Capabilities {
    effective_capabilities_by_fingerprint(&cert.fingerprint(), &cert.details.capabilities, state)
}

/// Effective capabilities given a precomputed fingerprint + cert-body fallback.
///
/// Hot-path callers (e.g. peer identity refresh) hold the fingerprint and a
/// baseline snapshot without the full cert; this avoids re-hashing the cert.
pub fn effective_capabilities_by_fingerprint(
    fingerprint: &MemberCertFingerprint,
    cert_fallback: &Capabilities,
    state: &SignedNetworkState,
) -> Capabilities {
    state
        .details
        .payload
        .capability_grants
        .iter()
        .find(|grant| grant.cert_fingerprint == *fingerprint)
        .map(|grant| grant.capabilities.clone())
        .unwrap_or_else(|| cert_fallback.clone())
}

/// Effective hostname for `cert` under the current `state`.
pub fn effective_hostname(cert: &MemberCert, state: &SignedNetworkState) -> Option<HostnameLabel> {
    effective_hostname_by_fingerprint(&cert.fingerprint(), cert.details.hostname.as_ref(), state)
}

/// Effective hostname given a precomputed fingerprint + cert-body fallback.
///
/// A present binding wins (including `None`, which clears the hostname); an
/// absent binding falls back to the cert body.
pub fn effective_hostname_by_fingerprint(
    fingerprint: &MemberCertFingerprint,
    cert_fallback: Option<&HostnameLabel>,
    state: &SignedNetworkState,
) -> Option<HostnameLabel> {
    match state
        .details
        .payload
        .hostname_bindings
        .iter()
        .find(|binding| binding.cert_fingerprint == *fingerprint)
    {
        Some(binding) => binding.hostname.clone(),
        None => cert_fallback.cloned(),
    }
}

/// Effective device label for `cert` under the current `state`.
pub fn effective_label(cert: &MemberCert, state: &SignedNetworkState) -> String {
    effective_label_by_fingerprint(&cert.fingerprint(), &cert.details.device_label, state)
}

/// Effective device label given a precomputed fingerprint + cert-body fallback.
///
/// A present binding wins; an absent binding falls back to the cert body. Unlike
/// hostname the label is a required non-empty string, so there is no "clear"
/// state — removing a binding simply reverts to the cert label.
pub fn effective_label_by_fingerprint(
    fingerprint: &MemberCertFingerprint,
    cert_fallback: &str,
    state: &SignedNetworkState,
) -> String {
    state
        .details
        .payload
        .label_bindings
        .iter()
        .find(|binding| binding.cert_fingerprint == *fingerprint)
        .map(|binding| binding.label.clone())
        .unwrap_or_else(|| cert_fallback.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::{
        CapabilityGrant, HostnameBinding, NetworkLocalId, NetworkStatePayload, SignKey,
        SignedNetworkState, TrustDomainRoot, UnsignedMemberCert, UnsignedNetworkState,
    };
    use ed25519_dalek::VerifyingKey;
    use pnet::ipnetwork::IpNetwork as IpNet;

    fn caps(relay: bool, exit: bool, subnet: &str) -> Capabilities {
        Capabilities {
            can_relay_data: relay,
            can_relay_control: relay,
            can_proxy_subnet: vec![subnet.parse::<IpNet>().unwrap()],
            can_be_exit_node: exit,
        }
    }

    fn cert_with(root: &TrustDomainRoot, hostname: Option<&str>) -> MemberCert {
        let sk = SignKey::generate();
        let device_pk = VerifyingKey::from_bytes(&sk.verify_key().0).unwrap();
        UnsignedMemberCert {
            trust_domain_id: root.id(),
            network_local_id: NetworkLocalId::try_from_str("office-net").unwrap(),
            device_pk,
            device_label: "device".to_owned(),
            not_before: 1_715_000_000,
            expires_at: 4_102_444_800,
            capabilities: caps(true, false, "10.0.0.0/24"),
            network_state_version_ref: 1,
            hostname: hostname.map(|h| HostnameLabel::try_from_str(h).unwrap()),
        }
        .sign(root)
    }

    fn state_with(
        root: &TrustDomainRoot,
        grants: Vec<CapabilityGrant>,
        bindings: Vec<HostnameBinding>,
    ) -> SignedNetworkState {
        UnsignedNetworkState {
            trust_domain_id: root.id(),
            network_local_id: NetworkLocalId::try_from_str("office-net").unwrap(),
            version: 1,
            payload: NetworkStatePayload {
                member_cert_index: Vec::new(),
                revoked_certs: Vec::new(),
                disabled_certs: Vec::new(),
                acl: Vec::new(),
                routes: Vec::new(),
                peer_hints: Vec::new(),
                ip_assignments: Vec::new(),
                capability_grants: grants,
                hostname_bindings: bindings,
                label_bindings: Vec::new(),
            },
        }
        .sign(root)
    }

    #[test]
    fn capabilities_fall_back_to_cert_when_no_grant() {
        let root = TrustDomainRoot::generate();
        let cert = cert_with(&root, None);
        let state = state_with(&root, Vec::new(), Vec::new());
        assert_eq!(
            effective_capabilities(&cert, &state),
            cert.details.capabilities
        );
    }

    #[test]
    fn capabilities_grant_overrides_cert() {
        let root = TrustDomainRoot::generate();
        let cert = cert_with(&root, None);
        let granted = caps(false, true, "192.168.0.0/16");
        let state = state_with(
            &root,
            vec![CapabilityGrant {
                cert_fingerprint: cert.fingerprint(),
                capabilities: granted.clone(),
                granted_at: 100,
            }],
            Vec::new(),
        );
        assert_eq!(effective_capabilities(&cert, &state), granted);
    }

    #[test]
    fn grant_for_other_fingerprint_is_ignored() {
        let root = TrustDomainRoot::generate();
        let cert = cert_with(&root, None);
        let other = cert_with(&root, None);
        let state = state_with(
            &root,
            vec![CapabilityGrant {
                cert_fingerprint: other.fingerprint(),
                capabilities: caps(false, true, "192.168.0.0/16"),
                granted_at: 100,
            }],
            Vec::new(),
        );
        assert_eq!(
            effective_capabilities(&cert, &state),
            cert.details.capabilities
        );
    }

    #[test]
    fn hostname_absent_binding_falls_back_to_cert() {
        let root = TrustDomainRoot::generate();
        let cert = cert_with(&root, Some("alpha"));
        let state = state_with(&root, Vec::new(), Vec::new());
        assert_eq!(
            effective_hostname(&cert, &state).map(|h| h.as_str().to_owned()),
            Some("alpha".to_owned())
        );
    }

    #[test]
    fn hostname_binding_some_overrides_cert() {
        let root = TrustDomainRoot::generate();
        let cert = cert_with(&root, Some("alpha"));
        let state = state_with(
            &root,
            Vec::new(),
            vec![HostnameBinding {
                cert_fingerprint: cert.fingerprint(),
                hostname: Some(HostnameLabel::try_from_str("beta").unwrap()),
                bound_at: 100,
            }],
        );
        assert_eq!(
            effective_hostname(&cert, &state).map(|h| h.as_str().to_owned()),
            Some("beta".to_owned())
        );
    }

    #[test]
    fn hostname_binding_none_clears_cert_hostname() {
        let root = TrustDomainRoot::generate();
        let cert = cert_with(&root, Some("alpha"));
        let state = state_with(
            &root,
            Vec::new(),
            vec![HostnameBinding {
                cert_fingerprint: cert.fingerprint(),
                hostname: None,
                bound_at: 100,
            }],
        );
        assert_eq!(effective_hostname(&cert, &state), None);
    }
}
