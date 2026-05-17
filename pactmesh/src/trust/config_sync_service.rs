use std::{
    collections::{HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::anyhow;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use crate::{
    common::trust_context::load_root_public_key,
    peers::peer_rpc::PeerRpcManager,
    proto::{
        peer_rpc::{
            ConfigResourceSelector, ConfigSyncRpc, ConfigSyncRpcServer, FetchConfigRequest,
            FetchConfigResponse, PendingCertKey, QueryConfigVersionRequest,
            QueryConfigVersionResponse, ResourceVersion, UpgradeToRootDeviceRequest,
            UpgradeToRootDeviceResponse, config_resource_selector,
        },
        rpc_types::{
            self,
            controller::{BaseController, Controller},
        },
    },
    trust::{
        MemberCert, NetworkLocalId, SignedNetworkState, SignedTrustDomainMeta, TrustDomainId,
        TrustDomainPool, TrustDomainRoot, from_cbor, to_canonical_cbor,
    },
};

const FETCH_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const FETCH_RATE_LIMIT_MAX_CALLS: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PendingCertCacheKey {
    pub trust_domain_id: TrustDomainId,
    pub network_local_id: NetworkLocalId,
    pub applicant_pk: [u8; 32],
}

#[derive(Debug, Clone, Default)]
pub struct PendingCertCache {
    entries: HashMap<PendingCertCacheKey, MemberCert>,
}

impl PendingCertCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, cert: MemberCert) {
        let key = PendingCertCacheKey {
            trust_domain_id: cert.details.trust_domain_id,
            network_local_id: cert.details.network_local_id.clone(),
            applicant_pk: cert.details.device_pk.to_bytes(),
        };
        self.entries.insert(key, cert);
    }

    pub fn get(
        &self,
        trust_domain_id: &TrustDomainId,
        network_local_id: &NetworkLocalId,
        applicant_pk: &[u8; 32],
    ) -> Option<MemberCert> {
        self.entries
            .get(&PendingCertCacheKey {
                trust_domain_id: *trust_domain_id,
                network_local_id: network_local_id.clone(),
                applicant_pk: *applicant_pk,
            })
            .cloned()
    }

    fn version_and_digest(
        &self,
        trust_domain_id: &TrustDomainId,
        network_local_id: &NetworkLocalId,
        applicant_pk: &[u8; 32],
    ) -> (u64, Vec<u8>) {
        self.get(trust_domain_id, network_local_id, applicant_pk)
            .map(|cert| {
                let payload_cbor = to_canonical_cbor(&cert);
                (1, sha256_bytes(&payload_cbor))
            })
            .unwrap_or_default()
    }
}

#[derive(Clone)]
pub struct ConfigSyncService {
    pub trust_pool: Arc<RwLock<TrustDomainPool>>,
    pub network_name: String,
    trust_domain_dir: Option<PathBuf>,
    pending_cert_cache: Arc<Mutex<PendingCertCache>>,
    rate_limits: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
}

impl ConfigSyncService {
    pub fn new(trust_pool: Arc<RwLock<TrustDomainPool>>, network_name: String) -> Self {
        Self {
            trust_pool,
            network_name,
            trust_domain_dir: None,
            pending_cert_cache: Arc::new(Mutex::new(PendingCertCache::new())),
            rate_limits: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_trust_domain_dir(mut self, trust_domain_dir: impl Into<PathBuf>) -> Self {
        self.trust_domain_dir = Some(trust_domain_dir.into());
        self
    }

    pub fn pending_cert_cache(&self) -> Arc<Mutex<PendingCertCache>> {
        self.pending_cert_cache.clone()
    }

    pub fn register(&self, peer_rpc_mgr: &PeerRpcManager) {
        peer_rpc_mgr
            .rpc_server()
            .registry()
            .register(ConfigSyncRpcServer::new(self.clone()), &self.network_name);
    }

    fn parse_trust_domain_id(bytes: &[u8]) -> rpc_types::error::Result<TrustDomainId> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            rpc_types::error::Error::MalformatRpcPacket(
                "trust_domain_id must be exactly 32 bytes".to_owned(),
            )
        })?;
        Ok(TrustDomainId(bytes))
    }

    fn parse_network_local_id(network_local_id: &str) -> rpc_types::error::Result<NetworkLocalId> {
        NetworkLocalId::try_from_str(network_local_id).map_err(|err| {
            rpc_types::error::Error::MalformatRpcPacket(format!(
                "invalid network_local_id '{network_local_id}': {err}"
            ))
        })
    }

    fn parse_applicant_pk(bytes: &[u8]) -> rpc_types::error::Result<[u8; 32]> {
        bytes.try_into().map_err(|_| {
            rpc_types::error::Error::MalformatRpcPacket(
                "applicant_pk must be exactly 32 bytes".to_owned(),
            )
        })
    }

    fn fetch_rate_limit_key(ctrl: &BaseController, caller_member_cert_bytes: &[u8]) -> String {
        if !caller_member_cert_bytes.is_empty() {
            return format!(
                "cert:{:?}",
                Sha256::digest(caller_member_cert_bytes).as_slice()
            );
        }

        if let Some(info) = ctrl.get_tunnel_info()
            && let Some(remote_addr) = info.remote_addr.as_ref()
        {
            return format!("anon:{}", remote_addr.url);
        }

        "anon:unknown".to_owned()
    }

    fn enforce_fetch_rate_limit(
        &self,
        ctrl: &BaseController,
        caller_member_cert_bytes: &[u8],
    ) -> rpc_types::error::Result<()> {
        let now = Instant::now();
        let key = Self::fetch_rate_limit_key(ctrl, caller_member_cert_bytes);
        let mut guard = self.rate_limits.lock().unwrap();
        let queue = guard.entry(key).or_default();

        while queue
            .front()
            .is_some_and(|instant| now.duration_since(*instant) >= FETCH_RATE_LIMIT_WINDOW)
        {
            queue.pop_front();
        }

        if queue.len() >= FETCH_RATE_LIMIT_MAX_CALLS {
            return Err(rpc_types::error::Error::ExecutionError(anyhow!(
                "fetch rate limit exceeded"
            )));
        }

        queue.push_back(now);
        Ok(())
    }

    fn verify_caller_member_cert(
        pool: &TrustDomainPool,
        caller_member_cert_bytes: &[u8],
        expected_td: TrustDomainId,
        now: u64,
    ) -> rpc_types::error::Result<()> {
        if caller_member_cert_bytes.is_empty() {
            return Err(rpc_types::error::Error::ExecutionError(anyhow!(
                "caller member cert required"
            )));
        }

        let caller_cert: MemberCert = from_cbor(caller_member_cert_bytes).map_err(|err| {
            rpc_types::error::Error::ExecutionError(anyhow!(
                "caller member cert decode failed: {err}"
            ))
        })?;

        pool.verify_member_cert(&caller_cert, now).map_err(|err| {
            rpc_types::error::Error::ExecutionError(anyhow!(
                "caller member cert verify failed: {err}"
            ))
        })?;

        if caller_cert.details.trust_domain_id != expected_td {
            return Err(rpc_types::error::Error::ExecutionError(anyhow!(
                "caller member cert verify failed: trust domain mismatch"
            )));
        }

        Ok(())
    }

    fn resource_version(
        selector: ConfigResourceSelector,
        version: u64,
        content_digest: Vec<u8>,
    ) -> ResourceVersion {
        ResourceVersion {
            selector: Some(selector),
            version,
            content_digest,
        }
    }

    async fn query_one(
        &self,
        selector: ConfigResourceSelector,
    ) -> rpc_types::error::Result<ResourceVersion> {
        match selector.selector.as_ref() {
            Some(config_resource_selector::Selector::NetworkState(key)) => {
                let trust_domain_id = Self::parse_trust_domain_id(&key.trust_domain_id)?;
                let network_local_id = Self::parse_network_local_id(&key.network_local_id)?;
                let pool = self.trust_pool.read().await;
                let (version, digest) = pool
                    .network_state(&trust_domain_id, &network_local_id)
                    .map(|state| {
                        let payload_cbor = to_canonical_cbor(state);
                        (state.details.version, sha256_bytes(&payload_cbor))
                    })
                    .unwrap_or_default();
                Ok(Self::resource_version(selector, version, digest))
            }
            Some(config_resource_selector::Selector::TrustDomainMetaId(trust_domain_meta_id)) => {
                let trust_domain_id = Self::parse_trust_domain_id(trust_domain_meta_id)?;
                let pool = self.trust_pool.read().await;
                let (version, digest) = pool
                    .trust_domain_meta(&trust_domain_id)
                    .map(|meta| {
                        let payload_cbor = to_canonical_cbor(meta);
                        (meta.details.version, sha256_bytes(&payload_cbor))
                    })
                    .unwrap_or_default();
                Ok(Self::resource_version(selector, version, digest))
            }
            Some(config_resource_selector::Selector::PendingCertFor(key)) => {
                let trust_domain_id = Self::parse_trust_domain_id(&key.trust_domain_id)?;
                let network_local_id = Self::parse_network_local_id(&key.network_local_id)?;
                let applicant_pk = Self::parse_applicant_pk(&key.applicant_pk)?;
                let guard = self.pending_cert_cache.lock().unwrap();
                let (version, digest) =
                    guard.version_and_digest(&trust_domain_id, &network_local_id, &applicant_pk);
                Ok(Self::resource_version(selector, version, digest))
            }
            None => Err(rpc_types::error::Error::MalformatRpcPacket(
                "selector is required".to_owned(),
            )),
        }
    }

    async fn fetch_network_state(
        &self,
        key: &crate::proto::peer_rpc::NetworkStateKey,
        caller_member_cert_bytes: &[u8],
    ) -> rpc_types::error::Result<FetchConfigResponse> {
        let trust_domain_id = Self::parse_trust_domain_id(&key.trust_domain_id)?;
        let network_local_id = Self::parse_network_local_id(&key.network_local_id)?;
        let pool = self.trust_pool.read().await;
        Self::verify_caller_member_cert(
            &pool,
            caller_member_cert_bytes,
            trust_domain_id,
            now_unix(),
        )?;
        let state = pool
            .network_state(&trust_domain_id, &network_local_id)
            .ok_or_else(|| {
                rpc_types::error::Error::ExecutionError(anyhow!("network_state not found"))
            })?;

        Ok(FetchConfigResponse {
            payload_cbor: to_canonical_cbor(state),
            version: state.details.version,
        })
    }

    async fn fetch_trust_domain_meta(
        &self,
        trust_domain_meta_id: &[u8],
        caller_member_cert_bytes: &[u8],
    ) -> rpc_types::error::Result<FetchConfigResponse> {
        let trust_domain_id = Self::parse_trust_domain_id(trust_domain_meta_id)?;
        let pool = self.trust_pool.read().await;
        Self::verify_caller_member_cert(
            &pool,
            caller_member_cert_bytes,
            trust_domain_id,
            now_unix(),
        )?;
        let meta = pool.trust_domain_meta(&trust_domain_id).ok_or_else(|| {
            rpc_types::error::Error::ExecutionError(anyhow!("trust_domain_meta not found"))
        })?;

        Ok(FetchConfigResponse {
            payload_cbor: to_canonical_cbor(meta),
            version: meta.details.version,
        })
    }

    fn fetch_pending_cert(
        &self,
        key: &PendingCertKey,
    ) -> rpc_types::error::Result<FetchConfigResponse> {
        let trust_domain_id = Self::parse_trust_domain_id(&key.trust_domain_id)?;
        let network_local_id = Self::parse_network_local_id(&key.network_local_id)?;
        let applicant_pk = Self::parse_applicant_pk(&key.applicant_pk)?;
        let cert = self
            .pending_cert_cache
            .lock()
            .unwrap()
            .get(&trust_domain_id, &network_local_id, &applicant_pk)
            .ok_or_else(|| {
                rpc_types::error::Error::ExecutionError(anyhow!("pending cert not found"))
            })?;

        Ok(FetchConfigResponse {
            payload_cbor: to_canonical_cbor(&cert),
            version: 1,
        })
    }

    fn ensure_peer_tunnel(ctrl: &BaseController) -> rpc_types::error::Result<()> {
        if ctrl.get_tunnel_info().is_none() {
            return Err(rpc_types::error::Error::ExecutionError(anyhow!(
                "root upgrade requires an established peer tunnel"
            )));
        }

        Ok(())
    }

    fn install_root_from_upgrade(
        domain_dir: &Path,
        trust_domain_id: TrustDomainId,
        sk_root_payload: &[u8],
        passphrase: &str,
    ) -> anyhow::Result<TrustDomainRoot> {
        let bytes: [u8; 32] = sk_root_payload
            .try_into()
            .map_err(|_| anyhow!("sk_root_payload must be exactly 32 bytes"))?;
        let root = TrustDomainRoot::from_root_upgrade_secret(bytes);
        if root.id() != trust_domain_id {
            anyhow::bail!("sk_root_payload does not match trust_domain_id");
        }

        let expected_pk = load_root_public_key(&domain_dir.join("pk_root.pem"))
            .map_err(|err| anyhow!("failed to load pk_root.pem: {err}"))?;
        let payload_pk = root.public_key();
        if payload_pk.as_bytes() != expected_pk.as_bytes() {
            anyhow::bail!("sk_root_payload does not match cached pk_root.pem");
        }

        let path = domain_dir.join("sk_root.age");
        if path.exists() {
            anyhow::bail!("sk_root.age already exists; refusing to overwrite root key");
        }
        root.save_to_file(&path, passphrase)
            .map_err(|err| anyhow!("failed to save {}: {err}", path.display()))?;
        Ok(root)
    }
}

#[async_trait::async_trait]
impl ConfigSyncRpc for ConfigSyncService {
    type Controller = BaseController;

    async fn query_config_version(
        &self,
        _ctrl: Self::Controller,
        input: QueryConfigVersionRequest,
    ) -> rpc_types::error::Result<QueryConfigVersionResponse> {
        let mut versions = Vec::with_capacity(input.resources.len());
        for selector in input.resources {
            versions.push(self.query_one(selector).await?);
        }

        Ok(QueryConfigVersionResponse { versions })
    }

    async fn fetch_config(
        &self,
        ctrl: Self::Controller,
        input: FetchConfigRequest,
    ) -> rpc_types::error::Result<FetchConfigResponse> {
        self.enforce_fetch_rate_limit(&ctrl, &input.caller_member_cert_bytes)?;

        let selector = input.selector.ok_or_else(|| {
            rpc_types::error::Error::MalformatRpcPacket("selector is required".to_owned())
        })?;

        match selector.selector.as_ref() {
            Some(config_resource_selector::Selector::NetworkState(key)) => {
                self.fetch_network_state(key, &input.caller_member_cert_bytes)
                    .await
            }
            Some(config_resource_selector::Selector::TrustDomainMetaId(trust_domain_meta_id)) => {
                self.fetch_trust_domain_meta(trust_domain_meta_id, &input.caller_member_cert_bytes)
                    .await
            }
            Some(config_resource_selector::Selector::PendingCertFor(key)) => {
                self.fetch_pending_cert(key)
            }
            None => Err(rpc_types::error::Error::MalformatRpcPacket(
                "selector is required".to_owned(),
            )),
        }
    }

    async fn upgrade_to_root_device(
        &self,
        ctrl: Self::Controller,
        input: UpgradeToRootDeviceRequest,
    ) -> rpc_types::error::Result<UpgradeToRootDeviceResponse> {
        Self::ensure_peer_tunnel(&ctrl)?;

        let trust_domain_id = Self::parse_trust_domain_id(&input.trust_domain_id)?;
        let domain_dir = self.trust_domain_dir.as_ref().ok_or_else(|| {
            rpc_types::error::Error::ExecutionError(anyhow!(
                "root upgrade target has no configured trust-domain dir"
            ))
        })?;
        let passphrase = std::env::var("PNW_ROOT_UPGRADE_PASSPHRASE").map_err(|_| {
            rpc_types::error::Error::ExecutionError(anyhow!(
                "PNW_ROOT_UPGRADE_PASSPHRASE is required on the target device to save sk_root.age"
            ))
        })?;

        let root = Self::install_root_from_upgrade(
            domain_dir,
            trust_domain_id,
            &input.sk_root_payload,
            passphrase.trim_end_matches(['\r', '\n']),
        )
        .map_err(|err| rpc_types::error::Error::ExecutionError(anyhow!(err)))?;

        {
            let mut pool = self.trust_pool.write().await;
            let pk = VerifyingKey::from_bytes(root.public_key().as_bytes()).map_err(|err| {
                rpc_types::error::Error::ExecutionError(anyhow!(
                    "installed root public key is invalid: {err}"
                ))
            })?;
            pool.add_root(pk.into());
        }

        Ok(UpgradeToRootDeviceResponse {
            ack: true,
            device_pk_of_b: Vec::new(),
        })
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

fn sha256_bytes(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

#[allow(dead_code)]
fn _assert_wire_types(_: (&SignedNetworkState, &SignedTrustDomainMeta)) {}
