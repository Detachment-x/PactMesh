use std::path::Path;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::VerifyingKey;
use qrcode::QrCode;
use thiserror::Error;
use url::Url;

use crate::common::trust_context::{PK_ROOT_PEM_LABEL, load_root_public_key};

use super::{NetworkLocalId, TrustDomainId, from_cbor, to_canonical_cbor, unwrap_armored, wrap_armored};

const BOOTSTRAP_PEM_LABEL: &str = "PNW-NETWORK-BOOTSTRAP";
const BOOTSTRAP_URL_SCHEME: &str = "privatenetwork";
const BOOTSTRAP_URL_HOST: &str = "join";
const MAX_URL_LEN: usize = 2000;

#[derive(minicbor::Encode, minicbor::Decode, Debug, Clone, PartialEq, Eq)]
pub struct NetworkBootstrap {
    #[n(0)]
    pub trust_domain_id: TrustDomainId,
    #[n(1)]
    #[cbor(with = "minicbor_verifying_key")]
    pub pk_root: VerifyingKey,
    #[n(2)]
    pub network_local_id: NetworkLocalId,
    #[n(3)]
    #[cbor(with = "url_vec_cbor")]
    pub bootstrap_seeds: Vec<Url>,
    #[n(4)]
    pub trust_domain_label: Option<String>,
    #[n(5)]
    pub network_name: Option<String>,
    #[n(6)]
    pub description: Option<String>,
}

impl NetworkBootstrap {
    pub fn verify_self_consistency(&self) -> Result<(), BootstrapError> {
        let expected = TrustDomainId::from_root_pubkey(&self.pk_root);
        if self.trust_domain_id != expected {
            return Err(BootstrapError::TrustDomainIdMismatch {
                expected,
                found: self.trust_domain_id,
            });
        }
        Ok(())
    }

    pub fn to_pem(&self) -> String {
        wrap_armored(BOOTSTRAP_PEM_LABEL, &to_canonical_cbor(self))
    }

    pub fn from_pem(text: &str) -> Result<Self, BootstrapError> {
        let payload = unwrap_armored(text, BOOTSTRAP_PEM_LABEL)
            .map_err(|err| BootstrapError::Pem(err.to_string()))?;
        let bootstrap: Self = from_cbor(&payload).map_err(|err| BootstrapError::Cbor(err.to_string()))?;
        bootstrap.verify_self_consistency()?;
        Ok(bootstrap)
    }

    pub fn to_url(&self) -> Result<Url, BootstrapError> {
        self.verify_self_consistency()?;

        let mut url = Url::parse(&format!("{BOOTSTRAP_URL_SCHEME}://{BOOTSTRAP_URL_HOST}"))
            .expect("hard-coded bootstrap base URL must be valid");
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("td", &URL_SAFE_NO_PAD.encode(self.trust_domain_id.0));
            pairs.append_pair("pk", &URL_SAFE_NO_PAD.encode(self.pk_root.as_bytes()));
            pairs.append_pair("n", self.network_local_id.as_str());
            if !self.bootstrap_seeds.is_empty() {
                let seeds = to_canonical_cbor(&UrlSeedList {
                    items: &self.bootstrap_seeds,
                });
                pairs.append_pair("ep", &URL_SAFE_NO_PAD.encode(seeds));
            }
            if let Some(label) = self.trust_domain_label.as_ref() {
                pairs.append_pair("label", label);
            }
            if let Some(network_name) = self.network_name.as_ref() {
                pairs.append_pair("name", network_name);
            }
            if let Some(description) = self.description.as_ref() {
                pairs.append_pair("desc", description);
            }
        }

        if url.as_str().len() >= MAX_URL_LEN {
            return Err(BootstrapError::TooLongForQr(url.as_str().len()));
        }
        Ok(url)
    }

    pub fn from_url(url: &Url) -> Result<Self, BootstrapError> {
        if url.scheme() != BOOTSTRAP_URL_SCHEME || url.host_str() != Some(BOOTSTRAP_URL_HOST) {
            return Err(BootstrapError::InvalidUrl("unsupported bootstrap URL".to_owned()));
        }

        let mut td = None;
        let mut pk = None;
        let mut network_local_id = None;
        let mut bootstrap_seeds = Vec::new();
        let mut trust_domain_label = None;
        let mut network_name = None;
        let mut description = None;

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "td" => td = Some(parse_trust_domain_id(&value)?),
                "pk" => pk = Some(parse_verifying_key(&value)?),
                "n" => {
                    network_local_id = Some(
                        NetworkLocalId::try_from_str(&value)
                            .map_err(|err| BootstrapError::InvalidNetworkLocalId(err.to_string()))?,
                    )
                }
                "ep" => bootstrap_seeds = parse_seed_list(&value)?,
                "label" => trust_domain_label = Some(value.into_owned()),
                "name" => network_name = Some(value.into_owned()),
                "desc" => description = Some(value.into_owned()),
                _ => {}
            }
        }

        let bootstrap = Self {
            trust_domain_id: td.ok_or_else(|| BootstrapError::InvalidUrl("missing td".to_owned()))?,
            pk_root: pk.ok_or_else(|| BootstrapError::InvalidUrl("missing pk".to_owned()))?,
            network_local_id: network_local_id
                .ok_or_else(|| BootstrapError::InvalidUrl("missing n".to_owned()))?,
            bootstrap_seeds,
            trust_domain_label,
            network_name,
            description,
        };
        bootstrap.verify_self_consistency()?;
        Ok(bootstrap)
    }

    pub fn export_from_domain_dir(
        domain_dir: &Path,
        network_local_id: NetworkLocalId,
        bootstrap_seeds: Vec<Url>,
        trust_domain_label: Option<String>,
        network_name: Option<String>,
        description: Option<String>,
    ) -> Result<Self, BootstrapError> {
        let pk_root = load_root_public_key(&domain_dir.join("pk_root.pem"))
            .map_err(|err| BootstrapError::Io(format!("failed to read pk_root.pem: {err}")))?;
        Ok(Self {
            trust_domain_id: TrustDomainId::from_root_pubkey(&pk_root),
            pk_root,
            network_local_id,
            bootstrap_seeds,
            trust_domain_label,
            network_name,
            description,
        })
    }

    pub fn import_into_domain_dir(&self, domain_dir: &Path) -> Result<(), BootstrapError> {
        self.verify_self_consistency()?;
        std::fs::create_dir_all(domain_dir).map_err(|err| BootstrapError::Io(err.to_string()))?;
        let pk_root_path = domain_dir.join("pk_root.pem");
        if pk_root_path.exists() {
            let existing = load_root_public_key(&pk_root_path)
                .map_err(|err| BootstrapError::Io(format!("failed to read existing pk_root.pem: {err}")))?;
            if existing.as_bytes() != self.pk_root.as_bytes() {
                return Err(BootstrapError::PkRootAlreadyExistsAndMismatches);
            }
            return Ok(());
        }

        std::fs::write(&pk_root_path, wrap_armored(PK_ROOT_PEM_LABEL, self.pk_root.as_bytes()))
            .map_err(|err| BootstrapError::Io(err.to_string()))
    }
}

pub fn bootstrap_to_qr_svg(bootstrap: &NetworkBootstrap) -> Result<String, BootstrapError> {
    let url = bootstrap.to_url()?;
    let code = QrCode::new(url.as_str().as_bytes())
        .map_err(|err| BootstrapError::Qr(err.to_string()))?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(256, 256)
        .dark_color(qrcode::render::svg::Color("#111111"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build())
}

#[derive(minicbor::Encode)]
struct UrlSeedList<'a> {
    #[n(0)]
    #[cbor(with = "url_slice_cbor")]
    items: &'a [Url],
}

#[derive(minicbor::Decode)]
struct UrlSeedListOwned {
    #[n(0)]
    #[cbor(with = "url_vec_cbor")]
    items: Vec<Url>,
}

mod minicbor_verifying_key {
    use super::*;

    pub fn encode<Ctx, W: minicbor::encode::Write>(
        value: &VerifyingKey,
        encoder: &mut minicbor::Encoder<W>,
        _ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.bytes(value.as_bytes())?;
        Ok(())
    }

    pub fn decode<'b, Ctx>(
        decoder: &mut minicbor::Decoder<'b>,
        _ctx: &mut Ctx,
    ) -> Result<VerifyingKey, minicbor::decode::Error> {
        let bytes = decoder.bytes()?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| minicbor::decode::Error::message("pk_root must be 32 bytes"))?;
        VerifyingKey::from_bytes(&bytes)
            .map_err(|err| minicbor::decode::Error::message(err.to_string()))
    }
}

mod url_slice_cbor {
    use super::*;

    pub fn encode<Ctx, W: minicbor::encode::Write>(
        value: &[Url],
        encoder: &mut minicbor::Encoder<W>,
        _ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(value.len() as u64)?;
        for url in value {
            encoder.str(url.as_str())?;
        }
        Ok(())
    }
}

mod url_vec_cbor {
    use super::*;

    pub fn encode<Ctx, W: minicbor::encode::Write>(
        value: &[Url],
        encoder: &mut minicbor::Encoder<W>,
        ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        super::url_slice_cbor::encode(value, encoder, ctx)
    }

    pub fn decode<'b, Ctx>(
        decoder: &mut minicbor::Decoder<'b>,
        _ctx: &mut Ctx,
    ) -> Result<Vec<Url>, minicbor::decode::Error> {
        let len = decoder
            .array()?
            .ok_or_else(|| minicbor::decode::Error::message("indefinite array is not supported"))?;
        let mut urls = Vec::with_capacity(len as usize);
        for _ in 0..len {
            let raw = decoder.str()?;
            let url = Url::parse(raw)
                .map_err(|err| minicbor::decode::Error::message(err.to_string()))?;
            urls.push(url);
        }
        Ok(urls)
    }
}

fn parse_trust_domain_id(encoded: &str) -> Result<TrustDomainId, BootstrapError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|err| BootstrapError::InvalidUrl(format!("invalid td: {err}")))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| BootstrapError::InvalidUrl("td must be 32 bytes".to_owned()))?;
    Ok(TrustDomainId(bytes))
}

fn parse_verifying_key(encoded: &str) -> Result<VerifyingKey, BootstrapError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|err| BootstrapError::InvalidUrl(format!("invalid pk: {err}")))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| BootstrapError::InvalidUrl("pk must be 32 bytes".to_owned()))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|err| BootstrapError::InvalidUrl(format!("invalid pk: {err}")))
}

fn parse_seed_list(encoded: &str) -> Result<Vec<Url>, BootstrapError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|err| BootstrapError::InvalidUrl(format!("invalid ep: {err}")))?;
    let urls: UrlSeedListOwned = from_cbor(&bytes).map_err(|err| BootstrapError::Cbor(err.to_string()))?;
    Ok(urls.items)
}

#[derive(Error, Debug)]
pub enum BootstrapError {
    #[error("CBOR: {0}")]
    Cbor(String),
    #[error("PEM: {0}")]
    Pem(String),
    #[error("I/O: {0}")]
    Io(String),
    #[error("invalid bootstrap URL: {0}")]
    InvalidUrl(String),
    #[error("invalid network_local_id: {0}")]
    InvalidNetworkLocalId(String),
    #[error("trust_domain_id mismatch: expected {expected}, found {found}")]
    TrustDomainIdMismatch {
        expected: TrustDomainId,
        found: TrustDomainId,
    },
    #[error("bootstrap URL too long for QR: {0} chars")]
    TooLongForQr(usize),
    #[error("QR render failed: {0}")]
    Qr(String),
    #[error("pk_root.pem already exists and does not match the imported bootstrap")]
    PkRootAlreadyExistsAndMismatches,
}
