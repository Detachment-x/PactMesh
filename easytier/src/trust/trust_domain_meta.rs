//! `trust_domain_meta` wire type. Lists relays this trust domain trusts.
//!
//! See `trust-and-config-design.md` §3.5 / §6.5 / §11.9. Relay trust is
//! unilateral: this trust domain's root signs the list; each relay node
//! decides locally which trust domains it serves (out-of-band coordination).

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use minicbor::{Decoder, Encoder};
use thiserror::Error;

use super::cbor::to_canonical_cbor;
use super::identity::{TrustDomainRoot, VerifyKey};
use super::member_cert::SignatureBytes32;
use super::types::TrustDomainId;

mod verify_key_cbor {
    use super::*;

    pub fn encode<Ctx, W: minicbor::encode::Write>(
        value: &VerifyingKey,
        encoder: &mut Encoder<W>,
        _ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.bytes(value.as_bytes())?;
        Ok(())
    }

    pub fn decode<'b, Ctx>(
        decoder: &mut Decoder<'b>,
        _ctx: &mut Ctx,
    ) -> Result<VerifyingKey, minicbor::decode::Error> {
        let bytes = decoder.bytes()?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| minicbor::decode::Error::message("device_pk must be 32 bytes"))?;
        VerifyingKey::from_bytes(&bytes)
            .map_err(|err| minicbor::decode::Error::message(err.to_string()))
    }
}

/// Per-relay capability flags signed into the metadata.
#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq)]
pub struct RelayCapabilities {
    #[n(0)]
    pub can_relay_data: bool,
    #[n(1)]
    pub can_assist_holepunch: bool,
}

mod outbound_grant_vec_cbor {
    use super::*;

    pub fn encode<Ctx, W: minicbor::encode::Write>(
        value: &[OutboundGrant],
        encoder: &mut Encoder<W>,
        ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        minicbor::Encode::encode(value, encoder, ctx)
    }

    pub fn decode<'b, Ctx>(
        decoder: &mut Decoder<'b>,
        ctx: &mut Ctx,
    ) -> Result<Vec<OutboundGrant>, minicbor::decode::Error> {
        minicbor::Decode::decode(decoder, ctx)
    }

    pub fn nil() -> Option<Vec<OutboundGrant>> {
        Some(Vec::new())
    }

    pub fn is_nil(value: &[OutboundGrant]) -> bool {
        value.is_empty()
    }
}

/// One relay entry in the trust-domain-level relay list.
#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq)]
pub struct ActiveRelay {
    #[n(0)]
    #[cbor(with = "verify_key_cbor")]
    pub device_pk: VerifyingKey,
    #[n(1)]
    pub device_label: String,
    #[n(2)]
    pub capabilities: RelayCapabilities,
    /// Recommended ≤ 90 days; revocation is implicit via short expiry + re-signing.
    #[n(3)]
    pub expires_at: u64,
}

/// One outbound cross-domain relay borrow grant signed into trust-domain meta.
#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq)]
pub struct OutboundGrant {
    #[n(0)]
    #[cbor(with = "verify_key_cbor")]
    pub foreign_root_pk: VerifyingKey,
    #[n(1)]
    pub foreign_trust_domain_id: TrustDomainId,
    #[n(2)]
    pub capabilities: RelayCapabilities,
    #[n(3)]
    pub expires_at: u64,
}

/// Header + payload before signing.
#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq)]
pub struct UnsignedTrustDomainMeta {
    #[n(0)]
    pub trust_domain_id: TrustDomainId,
    #[n(1)]
    pub version: u64,
    #[n(2)]
    pub active_relays: Vec<ActiveRelay>,
    #[n(3)]
    #[cbor(with = "outbound_grant_vec_cbor", has_nil)]
    pub outbound_grants: Vec<OutboundGrant>,
}

impl UnsignedTrustDomainMeta {
    /// Canonical CBOR bytes for signing.
    pub fn marshal_for_signing(&self) -> Vec<u8> {
        to_canonical_cbor(self)
    }

    /// Sign with `SK_root` and produce a `SignedTrustDomainMeta`.
    pub fn sign(self, root: &TrustDomainRoot) -> SignedTrustDomainMeta {
        let signing_bytes = self.marshal_for_signing();
        let signature = root.sign(&signing_bytes).into();

        SignedTrustDomainMeta {
            details: self,
            signature,
        }
    }
}

/// Signed `trust_domain_meta`.
#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq)]
pub struct SignedTrustDomainMeta {
    #[n(0)]
    pub details: UnsignedTrustDomainMeta,
    #[n(1)]
    pub signature: SignatureBytes32,
}

impl SignedTrustDomainMeta {
    /// Verify signature against `root_pk`. Version monotonicity is the caller's job.
    pub fn verify(&self, root_pk: &VerifyKey) -> Result<(), TrustDomainMetaVerifyError> {
        let verifying_key =
            VerifyingKey::from_bytes(&root_pk.0).expect("stored public key must be valid");
        let expected_domain = TrustDomainId::from_root_pubkey(&verifying_key);
        if self.details.trust_domain_id != expected_domain {
            return Err(TrustDomainMetaVerifyError::DomainMismatch);
        }

        let sig_bytes: [u8; 64] = self
            .signature
            .0
            .as_slice()
            .try_into()
            .map_err(|_| TrustDomainMetaVerifyError::BadSignature)?;
        let signature = Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(&self.details.marshal_for_signing(), &signature)
            .map_err(|_| TrustDomainMetaVerifyError::BadSignature)
    }
}

/// `verify` failure modes.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum TrustDomainMetaVerifyError {
    #[error("signature mismatch")]
    BadSignature,
    #[error("trust_domain_id does not match root pubkey")]
    DomainMismatch,
}
