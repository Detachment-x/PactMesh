//! `network_state` wire type, signing helpers, and PEM armor.
//!
//! See `trust-and-config-design.md` §6.1 (layout) and §7.1 (verification).
//! ACL and routes are kept as opaque blobs in M0 (`acl: AclPlaceholder`,
//! `routes: RoutesPlaceholder`); they will be typed once T-035..T-041 land.

use ed25519_dalek::{Signature, Verifier};
use thiserror::Error;

use super::cbor::{ArmorError, from_cbor, to_canonical_cbor, unwrap_armored, wrap_armored};
use super::identity::{TrustDomainRoot, VerifyKey};
use super::member_cert::SignatureBytes32;
use super::revocation::{DisabledCert, RevokedCert};
use super::types::{MemberCertFingerprint, NetworkLocalId, TrustDomainId};

const NETWORK_STATE_PEM_LABEL: &str = "PNW-NETWORK-STATE";

/// Audit-only entry in `payload.member_cert_index`. Not used for join authentication.
#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq)]
pub struct MemberCertIndexEntry {
    #[n(0)]
    pub fingerprint: MemberCertFingerprint,
    #[n(1)]
    pub device_label: String,
    #[n(2)]
    pub issued_at: u64,
    #[n(3)]
    pub expires_at: u64,
}

/// Opaque ACL bytes (filled by T-035 / T-036).
pub type AclPlaceholder = Vec<u8>;

/// Opaque routes bytes (filled when route configuration is typed in M3).
pub type RoutesPlaceholder = Vec<u8>;

/// `network_state.payload`. Member-cert index, revoke / disable lists, ACL bundle, routes.
#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq)]
pub struct NetworkStatePayload {
    #[n(0)]
    pub member_cert_index: Vec<MemberCertIndexEntry>,
    #[n(1)]
    pub revoked_certs: Vec<RevokedCert>,
    #[n(2)]
    pub disabled_certs: Vec<DisabledCert>,
    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    pub acl: AclPlaceholder,
    #[n(4)]
    #[cbor(with = "minicbor::bytes")]
    pub routes: RoutesPlaceholder,
}

/// Header + payload before signing.
#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq)]
pub struct UnsignedNetworkState {
    #[n(0)]
    pub trust_domain_id: TrustDomainId,
    #[n(1)]
    pub network_local_id: NetworkLocalId,
    #[n(2)]
    pub version: u64,
    #[n(3)]
    pub payload: NetworkStatePayload,
}

impl UnsignedNetworkState {
    /// Canonical CBOR bytes used as the signing input.
    pub fn marshal_for_signing(&self) -> Vec<u8> {
        to_canonical_cbor(self)
    }

    /// Sign and produce a `SignedNetworkState`.
    pub fn sign(self, root: &TrustDomainRoot) -> SignedNetworkState {
        let signing_bytes = self.marshal_for_signing();
        let signature = root.sign(&signing_bytes).into();

        SignedNetworkState {
            details: self,
            signature,
        }
    }
}

/// Signed network state. Distributed by any node; verified locally per §7.1.
#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq)]
pub struct SignedNetworkState {
    #[n(0)]
    pub details: UnsignedNetworkState,
    #[n(1)]
    pub signature: SignatureBytes32,
}

impl SignedNetworkState {
    /// Verify signature against `root_pk`. Does NOT check version monotonicity
    /// (caller's responsibility — typically `TrustDomainPool::apply_network_state`).
    pub fn verify(&self, root_pk: &VerifyKey) -> Result<(), NetworkStateVerifyError> {
        let expected_domain = TrustDomainId::from_root_pubkey(
            &ed25519_dalek::VerifyingKey::from_bytes(&root_pk.0)
                .expect("stored public key must be valid"),
        );
        if self.details.trust_domain_id != expected_domain {
            return Err(NetworkStateVerifyError::DomainMismatch);
        }

        let sig_bytes: [u8; 64] = self
            .signature
            .0
            .as_slice()
            .try_into()
            .map_err(|_| NetworkStateVerifyError::BadSignature)?;
        let signature = Signature::from_bytes(&sig_bytes);
        ed25519_dalek::VerifyingKey::from_bytes(&root_pk.0)
            .expect("stored public key must be valid")
            .verify(&self.details.marshal_for_signing(), &signature)
            .map_err(|_| NetworkStateVerifyError::BadSignature)
    }

    /// PEM armor with label `"PNW-NETWORK-STATE"`.
    pub fn to_pem(&self) -> String {
        wrap_armored(NETWORK_STATE_PEM_LABEL, &to_canonical_cbor(self))
    }

    /// Inverse of `to_pem`.
    pub fn from_pem(text: &str) -> Result<Self, NetworkStateParseError> {
        let payload = unwrap_armored(text, NETWORK_STATE_PEM_LABEL)?;
        from_cbor(&payload).map_err(|err| NetworkStateParseError::Cbor(err.to_string()))
    }
}

/// `SignedNetworkState::verify` failure modes.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum NetworkStateVerifyError {
    #[error("signature mismatch")]
    BadSignature,
    #[error("trust_domain_id does not match root pubkey")]
    DomainMismatch,
}

/// PEM parsing failure modes.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum NetworkStateParseError {
    #[error("armor: {0}")]
    Armor(#[from] ArmorError),
    #[error("cbor decode: {0}")]
    Cbor(String),
}
