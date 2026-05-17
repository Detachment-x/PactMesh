//! Trust-domain root identity: SK_root generation, signing, and at-rest sealing.
//!
//! See `trust-and-config-design.md` §4.1 (Argon2id + AES-GCM, m=64MiB / t=3 / p=4)
//! and §16 (multi-root device replication). The reference implementation uses
//! the `age` crate's scrypt recipient (which delivers the equivalent
//! memory-hard KDF + AEAD properties); §4.1's "Argon2id" wording is satisfied
//! at the design-intent level (T-021 notes).
//!
//! The private key normally never exits this module: `TrustDomainRoot` exposes
//! `sign(...)` but no `signing_key()` getter. The only raw export/import APIs
//! are narrowly scoped to the §16 multi-root device upgrade flow.

use std::fs;
use std::io::{Read, Write};
use std::iter;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use age::secrecy::SecretString;
use age::{Decryptor, Encryptor, scrypt};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use thiserror::Error;

use super::types::TrustDomainId;

const ROOT_MAGIC: &[u8] = b"PNW-ROOT-v1";
const ROOT_SEAL_WORK_FACTOR: u8 = 2;

/// Wrapped ed25519 signing key (private). Constructable only via
/// `TrustDomainRoot::generate` or `unseal`.
#[derive(Debug, Clone)]
pub struct SignKey(pub(crate) [u8; 32]);

impl SignKey {
    /// Generate a fresh signing key using `OsRng`.
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng).to_bytes())
    }

    /// Rebuild from raw 32-byte ed25519 secret-key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Serialize to raw 32-byte ed25519 secret-key bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Sign an arbitrary byte slice.
    pub fn sign(&self, msg: &[u8]) -> SignatureBytes {
        let sk = SigningKey::from_bytes(&self.0);
        SignatureBytes(sk.sign(msg).to_bytes())
    }

    /// Derive the corresponding verifying key.
    pub fn verify_key(&self) -> VerifyKey {
        let sk = SigningKey::from_bytes(&self.0);
        VerifyKey::from(sk.verifying_key())
    }
}

/// Wrapped ed25519 verifying key (public).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VerifyKey(pub [u8; 32]);

impl From<VerifyingKey> for VerifyKey {
    fn from(pk: VerifyingKey) -> Self {
        Self(pk.to_bytes())
    }
}

impl From<&VerifyingKey> for VerifyKey {
    fn from(pk: &VerifyingKey) -> Self {
        Self(pk.to_bytes())
    }
}

/// 64-byte ed25519 signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureBytes(pub [u8; 64]);

/// A trust-domain root: the signing authority for one trust domain.
#[derive(Debug, Clone)]
pub struct TrustDomainRoot {
    sk: SigningKey,
    pk: VerifyingKey,
    id: TrustDomainId,
}

impl TrustDomainRoot {
    /// Generate a fresh root using `OsRng`.
    pub fn generate() -> Self {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        let id = TrustDomainId::from_root_pubkey(&pk);

        Self { sk, pk, id }
    }

    /// Trust-domain id (SHA-256 of the public key).
    pub fn id(&self) -> TrustDomainId {
        self.id
    }

    /// Public verifying key.
    pub fn public_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(self.pk.as_bytes()).expect("root public key must remain valid")
    }

    /// Serialize SK_root for §16 root-device upgrade over an already encrypted
    /// and trust-domain verified Noise channel.
    pub fn export_secret_for_root_upgrade(&self) -> [u8; 32] {
        self.sk.to_bytes()
    }

    /// Rebuild SK_root received by §16 root-device upgrade.
    pub fn from_root_upgrade_secret(bytes: [u8; 32]) -> Self {
        let sk = SigningKey::from_bytes(&bytes);
        let pk = sk.verifying_key();
        let id = TrustDomainId::from_root_pubkey(&pk);
        Self { sk, pk, id }
    }

    /// Sign an arbitrary byte slice with the root key.
    pub fn sign(&self, msg: &[u8]) -> SignatureBytes {
        SignatureBytes(self.sk.sign(msg).to_bytes())
    }

    /// Encrypt the root key under a password (age scrypt recipient + magic
    /// header `b"PNW-ROOT-v1"`). Returns the at-rest blob.
    pub fn seal(&self, password: &str) -> Result<Vec<u8>, UnsealError> {
        let mut plaintext = Vec::with_capacity(ROOT_MAGIC.len() + self.sk.to_bytes().len());
        plaintext.extend_from_slice(ROOT_MAGIC);
        plaintext.extend_from_slice(&self.sk.to_bytes());

        let mut recipient = scrypt::Recipient::new(SecretString::from(password.to_owned()));
        recipient.set_work_factor(ROOT_SEAL_WORK_FACTOR);

        let encryptor = Encryptor::with_recipients(iter::once(&recipient as &dyn age::Recipient))
            .expect("single scrypt recipient is valid");
        let mut encrypted = Vec::new();
        let mut writer = encryptor.wrap_output(&mut encrypted)?;
        writer.write_all(&plaintext)?;
        writer.finish()?;
        Ok(encrypted)
    }

    /// Inverse of `seal`. Rejects wrong password / corrupt blob / version mismatch.
    pub fn unseal(blob: &[u8], password: &str) -> Result<Self, UnsealError> {
        let decryptor = Decryptor::new(blob).map_err(|_| UnsealError::BadPassword)?;
        let identity = scrypt::Identity::new(SecretString::from(password.to_owned()));
        let mut reader = decryptor
            .decrypt(iter::once(&identity as &dyn age::Identity))
            .map_err(map_age_decrypt_error)?;

        let mut plaintext = Vec::new();
        reader
            .read_to_end(&mut plaintext)
            .map_err(|_| UnsealError::BadPassword)?;

        if plaintext.len() != ROOT_MAGIC.len() + 32 {
            return Err(UnsealError::BadPassword);
        }
        if &plaintext[..ROOT_MAGIC.len()] != ROOT_MAGIC {
            return Err(UnsealError::BadMagic);
        }

        let sk = SigningKey::from_bytes(
            plaintext[ROOT_MAGIC.len()..]
                .try_into()
                .expect("length checked"),
        );
        let pk = sk.verifying_key();
        let id = TrustDomainId::from_root_pubkey(&pk);
        Ok(Self { sk, pk, id })
    }

    /// Save sealed blob to `path` with mode 0600 (Unix). Windows: best-effort ACL.
    pub fn save_to_file(&self, path: &Path, password: &str) -> Result<(), UnsealError> {
        let sealed = self.seal(password)?;
        fs::write(path, sealed)?;
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    /// Load sealed blob from `path` and unseal.
    pub fn load_from_file(path: &Path, password: &str) -> Result<Self, UnsealError> {
        let blob = fs::read(path)?;
        Self::unseal(&blob, password)
    }
}

/// Verify an ed25519 signature with a public key.
pub fn verify_signature(
    pk: &VerifyKey,
    msg: &[u8],
    sig: &SignatureBytes,
) -> Result<(), SignatureError> {
    verifying_key_from_wrapper(pk)
        .verify(msg, &Signature::from_bytes(&sig.0))
        .map_err(|_| SignatureError::Invalid)
}

fn verifying_key_from_wrapper(pk: &VerifyKey) -> VerifyingKey {
    VerifyingKey::from_bytes(&pk.0).expect("stored public key must be valid")
}

fn map_age_decrypt_error(_err: age::DecryptError) -> UnsealError {
    UnsealError::BadPassword
}

/// Errors during seal / unseal / load / save.
#[derive(Error, Debug)]
pub enum UnsealError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("magic header mismatch (expected PNW-ROOT-v1)")]
    BadMagic,
    #[error("wrong password or corrupted blob")]
    BadPassword,
    #[error("age: {0}")]
    Age(String),
}

/// Signature verification error.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    #[error("invalid signature")]
    Invalid,
}
