//! Protobuf envelope helpers for trust-layer CBOR payloads.

use thiserror::Error;

use crate::proto::peer_rpc::{MemberCertEnvelope, NetworkStateEnvelope};

use crate::proto::peer_rpc::{JoinRequestEnvelope, TrustDomainMetaEnvelope};

use super::{
    JoinRequest, MemberCert, SignedNetworkState, SignedTrustDomainMeta, from_cbor,
    to_canonical_cbor,
};

/// Error while converting trust CBOR payloads to or from protobuf envelopes.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    #[error("envelope cbor payload is empty")]
    EnvelopeEmpty,
    #[error("cbor decode failed: {0}")]
    CborDecodeFailed(String),
    #[error("schema version unsupported: {0}")]
    SchemaVersionUnsupported(u64),
}

fn reject_empty(cbor: &[u8]) -> Result<(), WireError> {
    if cbor.is_empty() {
        return Err(WireError::EnvelopeEmpty);
    }
    Ok(())
}

/// Wrap a `MemberCert` as a protobuf envelope carrying canonical CBOR bytes.
pub fn member_cert_to_envelope(cert: &MemberCert) -> MemberCertEnvelope {
    MemberCertEnvelope {
        cbor: to_canonical_cbor(cert),
    }
}

/// Decode a `MemberCert` from a protobuf envelope without verifying its signature.
pub fn member_cert_from_envelope(env: &MemberCertEnvelope) -> Result<MemberCert, WireError> {
    reject_empty(&env.cbor)?;
    from_cbor(&env.cbor).map_err(|err| WireError::CborDecodeFailed(err.to_string()))
}

/// Wrap a signed network state as a protobuf envelope carrying canonical CBOR bytes.
pub fn signed_network_state_to_envelope(state: &SignedNetworkState) -> NetworkStateEnvelope {
    NetworkStateEnvelope {
        cbor: to_canonical_cbor(state),
    }
}

/// Decode a signed network state from a protobuf envelope without verifying its signature.
pub fn signed_network_state_from_envelope(
    env: &NetworkStateEnvelope,
) -> Result<SignedNetworkState, WireError> {
    reject_empty(&env.cbor)?;
    from_cbor(&env.cbor).map_err(|err| WireError::CborDecodeFailed(err.to_string()))
}

/// Wrap signed trust-domain metadata as a protobuf envelope carrying canonical CBOR bytes.
pub fn trust_domain_meta_to_envelope(meta: &SignedTrustDomainMeta) -> TrustDomainMetaEnvelope {
    TrustDomainMetaEnvelope {
        cbor: to_canonical_cbor(meta),
    }
}

/// Decode signed trust-domain metadata from a protobuf envelope without verifying its signature.
pub fn trust_domain_meta_from_envelope(
    env: &TrustDomainMetaEnvelope,
) -> Result<SignedTrustDomainMeta, WireError> {
    reject_empty(&env.cbor)?;
    from_cbor(&env.cbor).map_err(|err| WireError::CborDecodeFailed(err.to_string()))
}

/// Wrap a join request as a protobuf envelope carrying canonical CBOR bytes.
pub fn join_request_to_envelope(join: &JoinRequest) -> JoinRequestEnvelope {
    JoinRequestEnvelope {
        cbor: to_canonical_cbor(join),
    }
}

/// Decode a join request from a protobuf envelope without authorizing it.
pub fn join_request_from_envelope(env: &JoinRequestEnvelope) -> Result<JoinRequest, WireError> {
    reject_empty(&env.cbor)?;
    from_cbor(&env.cbor).map_err(|err| WireError::CborDecodeFailed(err.to_string()))
}
