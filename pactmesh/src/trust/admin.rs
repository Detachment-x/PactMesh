//! Root-signed management grants for non-root admin devices.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use minicbor::{Decoder, Encoder};
use thiserror::Error;

use super::cbor::{from_cbor, to_canonical_cbor, unwrap_armored, wrap_armored};
use super::identity::{SignKey, TrustDomainRoot, VerifyKey};
use super::member_cert::SignatureBytes32;
use super::types::TrustDomainId;

const ADMIN_GRANT_PEM_LABEL: &str = "PNW-ADMIN-GRANT";

#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq)]
pub struct AdminCapabilities {
    #[n(0)]
    pub approve_join: bool,
    #[n(1)]
    pub revoke_member: bool,
    #[n(2)]
    pub disable_member: bool,
    #[n(3)]
    pub edit_acl: bool,
    #[n(4)]
    pub rotate_admins: bool,
}

impl AdminCapabilities {
    pub fn all() -> Self {
        Self {
            approve_join: true,
            revoke_member: true,
            disable_member: true,
            edit_acl: true,
            rotate_admins: true,
        }
    }

    pub fn approve_only() -> Self {
        Self {
            approve_join: true,
            revoke_member: false,
            disable_member: false,
            edit_acl: false,
            rotate_admins: false,
        }
    }
}

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
            .map_err(|_| minicbor::decode::Error::message("admin_device_pk must be 32 bytes"))?;
        VerifyingKey::from_bytes(&bytes)
            .map_err(|err| minicbor::decode::Error::message(err.to_string()))
    }
}

#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq)]
pub struct UnsignedAdminGrant {
    #[n(0)]
    pub trust_domain_id: TrustDomainId,
    #[n(1)]
    #[cbor(with = "verify_key_cbor")]
    pub admin_device_pk: VerifyingKey,
    #[n(2)]
    pub admin_label: String,
    #[n(3)]
    pub not_before: u64,
    #[n(4)]
    pub expires_at: u64,
    #[n(5)]
    pub capabilities: AdminCapabilities,
}

impl UnsignedAdminGrant {
    pub fn marshal_for_signing(&self) -> Vec<u8> {
        to_canonical_cbor(self)
    }

    pub fn sign(self, root: &TrustDomainRoot) -> AdminGrant {
        let signature = root.sign(&self.marshal_for_signing()).into();
        AdminGrant {
            details: self,
            signature,
        }
    }
}

#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq)]
pub struct AdminGrant {
    #[n(0)]
    pub details: UnsignedAdminGrant,
    #[n(1)]
    pub signature: SignatureBytes32,
}

impl AdminGrant {
    pub fn verify(&self, root_pk: &VerifyKey, now: u64) -> Result<(), AdminGrantVerifyError> {
        let root_pk =
            VerifyingKey::from_bytes(&root_pk.0).expect("stored public key must be valid");
        if self.details.trust_domain_id != TrustDomainId::from_root_pubkey(&root_pk) {
            return Err(AdminGrantVerifyError::DomainMismatch);
        }
        if self.details.not_before >= self.details.expires_at {
            return Err(AdminGrantVerifyError::BadTimeWindow);
        }
        if now < self.details.not_before || now >= self.details.expires_at {
            return Err(AdminGrantVerifyError::NotCurrentlyValid);
        }
        let sig_bytes: [u8; 64] = self
            .signature
            .0
            .as_slice()
            .try_into()
            .map_err(|_| AdminGrantVerifyError::BadSignature)?;
        let signature = Signature::from_bytes(&sig_bytes);
        root_pk
            .verify(&self.details.marshal_for_signing(), &signature)
            .map_err(|_| AdminGrantVerifyError::BadSignature)
    }

    pub fn verify_admin_signature(
        &self,
        message: &[u8],
        signature: &SignatureBytes32,
    ) -> Result<(), AdminGrantVerifyError> {
        let sig_bytes: [u8; 64] = signature
            .0
            .as_slice()
            .try_into()
            .map_err(|_| AdminGrantVerifyError::BadAdminSignature)?;
        let sig = Signature::from_bytes(&sig_bytes);
        self.details
            .admin_device_pk
            .verify(message, &sig)
            .map_err(|_| AdminGrantVerifyError::BadAdminSignature)
    }

    pub fn to_pem(&self) -> String {
        wrap_armored(ADMIN_GRANT_PEM_LABEL, &to_canonical_cbor(self))
    }

    pub fn from_pem(text: &str) -> Result<Self, AdminGrantParseError> {
        let payload = unwrap_armored(text, ADMIN_GRANT_PEM_LABEL)?;
        from_cbor(&payload).map_err(|err| AdminGrantParseError::Cbor(err.to_string()))
    }
}

pub fn sign_admin_operation(admin_sk: &SignKey, message: &[u8]) -> SignatureBytes32 {
    admin_sk.sign(message).into()
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AdminGrantVerifyError {
    #[error("signature mismatch")]
    BadSignature,
    #[error("admin operation signature mismatch")]
    BadAdminSignature,
    #[error("trust_domain_id does not match root pubkey")]
    DomainMismatch,
    #[error("invalid time window")]
    BadTimeWindow,
    #[error("admin grant is not currently valid")]
    NotCurrentlyValid,
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AdminGrantParseError {
    #[error("armor: {0}")]
    Armor(#[from] super::cbor::ArmorError),
    #[error("cbor decode: {0}")]
    Cbor(String),
}
