//! `join_request` wire type and applicant-side self-signing.
//!
//! See `trust-and-config-design.md` §6.3 / §9.

use rand::RngCore;
use rand::rngs::OsRng;
use thiserror::Error;

use super::cbor::to_canonical_cbor;
use super::identity::{SignKey, SignatureBytes, VerifyKey, verify_signature};
use super::member_cert::SignatureBytes32;
use super::types::{NetworkLocalId, TrustDomainId};

/// Self-signed application from a new device asking the trust-domain root for a cert.
///
/// `applicant_signature` is over fields 0..6 with `applicant_sk`. Verifying
/// it (T-070) tells the root that whoever holds the private key matching
/// `applicant_pk` actually composed this request — preventing on-path
/// substitution by transit nodes.
#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    #[n(0)]
    pub trust_domain_id: TrustDomainId,
    #[n(1)]
    pub network_local_id: NetworkLocalId,
    #[n(2)]
    #[cbor(with = "verify_key_cbor")]
    pub applicant_pk: VerifyKey,
    #[n(3)]
    pub device_label: String,
    #[n(4)]
    pub hint: String,
    #[n(5)]
    #[cbor(with = "minicbor::bytes")]
    pub nonce: Vec<u8>,
    #[n(6)]
    pub applicant_signature: SignatureBytes32,
}

#[derive(minicbor::Encode)]
struct UnsignedJoinRequest<'a> {
    #[n(0)]
    trust_domain_id: &'a TrustDomainId,
    #[n(1)]
    network_local_id: &'a NetworkLocalId,
    #[n(2)]
    #[cbor(with = "verify_key_cbor")]
    applicant_pk: &'a VerifyKey,
    #[n(3)]
    device_label: &'a str,
    #[n(4)]
    hint: &'a str,
    #[n(5)]
    #[cbor(with = "minicbor::bytes")]
    nonce: &'a [u8],
}

mod verify_key_cbor {
    use super::*;

    pub fn encode<Ctx, W: minicbor::encode::Write>(
        value: &VerifyKey,
        encoder: &mut minicbor::Encoder<W>,
        _ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.bytes(&value.0)?;
        Ok(())
    }

    pub fn decode<'b, Ctx>(
        decoder: &mut minicbor::Decoder<'b>,
        _ctx: &mut Ctx,
    ) -> Result<VerifyKey, minicbor::decode::Error> {
        let bytes = decoder.bytes()?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| minicbor::decode::Error::message("applicant_pk must be 32 bytes"))?;
        Ok(VerifyKey(bytes))
    }
}

impl JoinRequest {
    fn marshal_for_signing(&self) -> Vec<u8> {
        to_canonical_cbor(&UnsignedJoinRequest {
            trust_domain_id: &self.trust_domain_id,
            network_local_id: &self.network_local_id,
            applicant_pk: &self.applicant_pk,
            device_label: &self.device_label,
            hint: &self.hint,
            nonce: &self.nonce,
        })
    }

    /// Build a request and sign it locally with the applicant's private key.
    pub fn new_signed(
        trust_domain_id: TrustDomainId,
        network_local_id: NetworkLocalId,
        applicant_sk: &SignKey,
        device_label: String,
        hint: String,
    ) -> Self {
        let mut nonce = vec![0u8; 16];
        OsRng.fill_bytes(&mut nonce);

        let mut request = Self {
            trust_domain_id,
            network_local_id,
            applicant_pk: applicant_sk.verify_key(),
            device_label,
            hint,
            nonce,
            applicant_signature: SignatureBytes32(Vec::new()),
        };
        request.applicant_signature = applicant_sk.sign(&request.marshal_for_signing()).into();
        request
    }

    /// Verify the embedded `applicant_signature` against `applicant_pk`.
    pub fn verify_self_signature(&self) -> Result<(), JoinVerifyError> {
        let sig_bytes: [u8; 64] = self
            .applicant_signature
            .0
            .as_slice()
            .try_into()
            .map_err(|_| JoinVerifyError::BadSignature)?;
        verify_signature(
            &self.applicant_pk,
            &self.marshal_for_signing(),
            &SignatureBytes(sig_bytes),
        )
        .map_err(|_| JoinVerifyError::BadSignature)
    }
}

/// `verify_self_signature` failure modes.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum JoinVerifyError {
    #[error("applicant signature mismatch")]
    BadSignature,
    #[error("malformed applicant pubkey")]
    BadPubkey,
}
