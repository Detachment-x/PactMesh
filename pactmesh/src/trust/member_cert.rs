//! `member_cert` wire type, signing helpers, and PEM armor.
//!
//! See `trust-and-config-design.md` §6.2 (final layout; `hostname` is added by
//! T-034) and §7.3 (verification logic).

use std::net::IpAddr;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use minicbor::{Decoder, Encoder};
use pnet::ipnetwork::IpNetwork as IpNet;
use thiserror::Error;

use super::cbor::{ArmorError, from_cbor, to_canonical_cbor, unwrap_armored, wrap_armored};
use super::hostname::HostnameLabel;
use super::identity::{SignatureBytes, TrustDomainRoot};
use super::types::{MemberCertFingerprint, NetworkLocalId, TrustDomainId};

const MEMBER_CERT_PEM_LABEL: &str = "PNW-MEMBER-CERT";

/// Authorization caps the trust-domain root grants when signing a cert.
///
/// Devices can locally narrow these (turn off relay / proxy temporarily) but
/// cannot exceed them.
#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    #[n(0)]
    pub can_relay_data: bool,
    #[n(1)]
    pub can_relay_control: bool,
    #[n(2)]
    #[cbor(with = "cidr_vec_cbor")]
    pub can_proxy_subnet: Vec<IpNet>,
}

impl Capabilities {
    /// True iff `self` is everywhere-narrower-or-equal compared to `other`.
    pub fn is_subset_of(&self, other: &Capabilities) -> bool {
        (!self.can_relay_data || other.can_relay_data)
            && (!self.can_relay_control || other.can_relay_control)
            && self.can_proxy_subnet.iter().all(|candidate| {
                other
                    .can_proxy_subnet
                    .iter()
                    .any(|allowed| cidr_is_subset_of(*candidate, *allowed))
            })
    }
}

fn cidr_is_subset_of(candidate: IpNet, allowed: IpNet) -> bool {
    match (candidate, allowed) {
        (IpNet::V4(candidate), IpNet::V4(allowed)) => {
            allowed.contains(candidate.network()) && allowed.contains(candidate.broadcast())
        }
        (IpNet::V6(candidate), IpNet::V6(allowed)) => {
            allowed.contains(candidate.network()) && allowed.contains(candidate.broadcast())
        }
        _ => false,
    }
}

mod cidr_vec_cbor {
    use super::*;

    pub fn encode<Ctx, W: minicbor::encode::Write>(
        value: &[IpNet],
        encoder: &mut Encoder<W>,
        _ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(value.len() as u64)?;
        for cidr in value {
            let bytes = match cidr {
                IpNet::V4(net) => {
                    let mut out = Vec::with_capacity(6);
                    out.push(4);
                    out.extend_from_slice(&net.ip().octets());
                    out.push(net.prefix());
                    out
                }
                IpNet::V6(net) => {
                    let mut out = Vec::with_capacity(18);
                    out.push(6);
                    out.extend_from_slice(&net.ip().octets());
                    out.push(net.prefix());
                    out
                }
            };
            encoder.bytes(&bytes)?;
        }
        Ok(())
    }

    pub fn decode<'b, Ctx>(
        decoder: &mut Decoder<'b>,
        _ctx: &mut Ctx,
    ) -> Result<Vec<IpNet>, minicbor::decode::Error> {
        let len = decoder
            .array()?
            .ok_or_else(|| minicbor::decode::Error::message("indefinite array is not supported"))?;
        let mut out = Vec::with_capacity(len as usize);
        for _ in 0..len {
            let bytes = decoder.bytes()?;
            let cidr = match bytes {
                [4, a, b, c, d, prefix] => {
                    let ip = IpAddr::from([*a, *b, *c, *d]);
                    IpNet::new(ip, *prefix)
                        .map_err(|err| minicbor::decode::Error::message(err.to_string()))?
                }
                [6, rest @ ..] if rest.len() == 17 => {
                    let ip =
                        IpAddr::from(<[u8; 16]>::try_from(&rest[..16]).expect("length checked"));
                    IpNet::new(ip, rest[16])
                        .map_err(|err| minicbor::decode::Error::message(err.to_string()))?
                }
                _ => {
                    return Err(minicbor::decode::Error::message(
                        "invalid CIDR helper bytes",
                    ));
                }
            };
            out.push(cidr);
        }
        Ok(out)
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
            .map_err(|_| minicbor::decode::Error::message("device_pk must be 32 bytes"))?;
        VerifyingKey::from_bytes(&bytes)
            .map_err(|err| minicbor::decode::Error::message(err.to_string()))
    }
}

/// Cert payload signed by `SK_root`.
///
/// Field indices keep the original T-031 order and append `hostname` last for
/// backward compatibility with older certs that ended at field 7.
#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq)]
pub struct UnsignedMemberCert {
    #[n(0)]
    pub trust_domain_id: TrustDomainId,
    #[n(1)]
    pub network_local_id: NetworkLocalId,
    #[n(2)]
    #[cbor(with = "verify_key_cbor")]
    pub device_pk: VerifyingKey,
    #[n(3)]
    pub device_label: String,
    #[n(4)]
    pub not_before: u64,
    #[n(5)]
    pub expires_at: u64,
    #[n(6)]
    pub capabilities: Capabilities,
    #[n(7)]
    pub network_state_version_ref: u64,
    #[n(8)]
    pub hostname: Option<HostnameLabel>,
}

impl UnsignedMemberCert {
    /// Canonical CBOR encoding of the unsigned payload (input to `Sign`).
    pub fn marshal_for_signing(&self) -> Vec<u8> {
        to_canonical_cbor(self)
    }

    /// Sign with `SK_root` and produce a `MemberCert`.
    pub fn sign(self, root: &TrustDomainRoot) -> MemberCert {
        let signing_bytes = self.marshal_for_signing();
        let signature = root.sign(&signing_bytes).into();

        MemberCert {
            details: self,
            signature,
        }
    }
}

/// Signed member certificate (payload + signature).
#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq)]
pub struct MemberCert {
    #[n(0)]
    pub details: UnsignedMemberCert,
    #[n(1)]
    pub signature: SignatureBytes32,
}

/// Wire-format wrapper for a 64-byte ed25519 signature.
#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq)]
pub struct SignatureBytes32(
    #[n(0)]
    #[cbor(with = "minicbor::bytes")]
    pub Vec<u8>,
);

impl From<SignatureBytes> for SignatureBytes32 {
    fn from(s: SignatureBytes) -> Self {
        Self(s.0.to_vec())
    }
}

impl MemberCert {
    /// SHA-256 fingerprint over canonical CBOR bytes.
    pub fn fingerprint(&self) -> MemberCertFingerprint {
        MemberCertFingerprint::from_cert_bytes(&to_canonical_cbor(self))
    }

    /// Verify signature + field invariants (`trust_domain_id` matches `root_pk`,
    /// `not_before < expires_at`, etc.).
    pub fn verify(&self, root_pk: &VerifyingKey) -> Result<(), VerifyError> {
        if self.details.trust_domain_id != TrustDomainId::from_root_pubkey(root_pk) {
            return Err(VerifyError::DomainMismatch);
        }
        if self.details.not_before >= self.details.expires_at {
            return Err(VerifyError::BadTimeWindow {
                nb: self.details.not_before,
                ea: self.details.expires_at,
            });
        }

        let sig_bytes: [u8; 64] = self
            .signature
            .0
            .as_slice()
            .try_into()
            .map_err(|_| VerifyError::BadSignature)?;
        let signature = Signature::from_bytes(&sig_bytes);
        root_pk
            .verify(&self.details.marshal_for_signing(), &signature)
            .map_err(|_| VerifyError::BadSignature)
    }

    /// PEM-armored serialization with label `"PNW-MEMBER-CERT"`.
    pub fn to_pem(&self) -> String {
        wrap_armored(MEMBER_CERT_PEM_LABEL, &to_canonical_cbor(self))
    }

    /// Inverse of `to_pem`; rejects label mismatch.
    pub fn from_pem(text: &str) -> Result<Self, ParseError> {
        let payload = unwrap_armored(text, MEMBER_CERT_PEM_LABEL)?;
        from_cbor(&payload).map_err(|err| ParseError::Cbor(err.to_string()))
    }
}

/// Verification failure modes.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    #[error("signature mismatch")]
    BadSignature,
    #[error("trust_domain_id does not match root pubkey")]
    DomainMismatch,
    #[error("invalid time window: not_before {nb} >= expires_at {ea}")]
    BadTimeWindow { nb: u64, ea: u64 },
    #[error("certificate has expired (now {now} >= expires_at {ea})")]
    Expired { now: u64, ea: u64 },
    #[error("network_state_version_ref {got} > local {have}")]
    FutureVersionRef { have: u64, got: u64 },
}

/// PEM parsing failure modes.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    #[error("armor: {0}")]
    Armor(#[from] ArmorError),
    #[error("cbor decode: {0}")]
    Cbor(String),
}
