use std::io::Read;
use std::iter;
use std::path::Path;

use age::secrecy::SecretString;
use age::{Decryptor, scrypt};
use ed25519_dalek::VerifyingKey;
use thiserror::Error;

use crate::trust::{
    MemberCert, MemberCertFingerprint, NetworkLocalId, SignKey, TrustDomainId, unwrap_armored,
};

pub(crate) const PK_ROOT_PEM_LABEL: &str = "PNW-PK-ROOT";

#[derive(Debug, Clone)]
pub struct TrustDomainContext {
    pub trust_domain_id: TrustDomainId,
    pub network_local_id: NetworkLocalId,
    pub member_cert: MemberCert,
    pub sk_self: SignKey,
}

impl TrustDomainContext {
    pub fn new(
        trust_domain_id: TrustDomainId,
        network_local_id: NetworkLocalId,
        member_cert: MemberCert,
        sk_self: SignKey,
    ) -> Self {
        Self {
            trust_domain_id,
            network_local_id,
            member_cert,
            sk_self,
        }
    }

    pub fn fingerprint(&self) -> MemberCertFingerprint {
        self.member_cert.fingerprint()
    }

    pub fn load_from_dir(
        domain_dir: &Path,
        network_local_id: &str,
        sk_self_password: &str,
    ) -> Result<Self, LoadError> {
        let network_local_id = NetworkLocalId::try_from_str(network_local_id)
            .map_err(|_| LoadError::NetworkLocalIdInvalid)?;
        let root_pk = load_root_public_key(&domain_dir.join("pk_root.pem"))?;
        let trust_domain_id = TrustDomainId::from_root_pubkey(&root_pk);
        let network_dir = domain_dir.join("networks").join(network_local_id.as_str());

        let member_cert_pem = std::fs::read_to_string(network_dir.join("member_cert.pem"))?;
        let member_cert = MemberCert::from_pem(&member_cert_pem)
            .map_err(|err| LoadError::InvalidPem(err.to_string()))?;
        if member_cert.details.network_local_id != network_local_id {
            return Err(LoadError::InvalidPem(
                "member_cert network_local_id mismatch".to_owned(),
            ));
        }
        if member_cert.details.trust_domain_id != trust_domain_id {
            return Err(LoadError::TrustDomainIdMismatch);
        }
        member_cert
            .verify(&root_pk)
            .map_err(|err| LoadError::InvalidPem(err.to_string()))?;

        let sk_self = load_sk_self_for_network(domain_dir, &network_dir, sk_self_password)?;
        if sk_self.verify_key().0 != member_cert.details.device_pk.to_bytes() {
            return Err(LoadError::InvalidPem(
                "sk_self does not match member_cert device_pk".to_owned(),
            ));
        }

        Ok(Self::new(
            trust_domain_id,
            network_local_id,
            member_cert,
            sk_self,
        ))
    }
}

pub(crate) fn load_root_public_key(path: &Path) -> Result<VerifyingKey, LoadError> {
    let pem = std::fs::read_to_string(path)?;
    let payload = unwrap_armored(&pem, PK_ROOT_PEM_LABEL)
        .map_err(|err| LoadError::InvalidPem(err.to_string()))?;
    let bytes: [u8; 32] = payload.as_slice().try_into().map_err(|_| {
        LoadError::InvalidPem("pk_root.pem must contain exactly 32 bytes".to_owned())
    })?;
    VerifyingKey::from_bytes(&bytes).map_err(|err| LoadError::InvalidPem(err.to_string()))
}

fn load_sk_self_for_network(
    domain_dir: &Path,
    network_dir: &Path,
    password: &str,
) -> Result<SignKey, LoadError> {
    let network_key = network_dir.join("sk_self.age");
    if network_key.exists() {
        return load_sk_self(&network_key, password);
    }

    let device_id_path = network_dir.join("device_id");
    let device_id = std::fs::read_to_string(&device_id_path)?;
    let device_id = device_id.trim();
    if device_id.is_empty() {
        return Err(LoadError::InvalidPem("device_id is empty".to_owned()));
    }
    let private_network_dir = domain_dir
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| LoadError::InvalidPem("domain_dir is not under trust-domains".to_owned()))?;
    load_sk_self(
        &private_network_dir
            .join("devices")
            .join(device_id)
            .join("sk_self.age"),
        password,
    )
}

fn load_sk_self(path: &Path, password: &str) -> Result<SignKey, LoadError> {
    let blob = std::fs::read(path)?;
    let decryptor = Decryptor::new(&blob[..]).map_err(|_| LoadError::SkSelfDecryptFailed)?;
    let identity = scrypt::Identity::new(SecretString::from(password.to_owned()));
    let mut reader = decryptor
        .decrypt(iter::once(&identity as &dyn age::Identity))
        .map_err(|_| LoadError::SkSelfDecryptFailed)?;

    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|_| LoadError::SkSelfDecryptFailed)?;
    let bytes: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| LoadError::SkSelfDecryptFailed)?;
    Ok(SignKey::from_bytes(bytes))
}

#[derive(Error, Debug)]
pub enum LoadError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid pem: {0}")]
    InvalidPem(String),
    #[error("failed to decrypt sk_self.age")]
    SkSelfDecryptFailed,
    #[error("network_local_id is invalid")]
    NetworkLocalIdInvalid,
    #[error("trust_domain_id does not match pk_root.pem")]
    TrustDomainIdMismatch,
}
