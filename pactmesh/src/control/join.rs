//! Accepting an invite: reuse or mint the device identity, sign a `JoinRequest`,
//! hand it to the inviting seed's admission endpoint, and wait for a network
//! administrator to approve it.
//!
//! Both the CLI (`trust accept-invite`) and the console (`POST /api/network/join`)
//! need this. The console used to get it by forking its own executable, which
//! Android cannot do — so the flow lives here and callers simply await it.
//! Nothing below talks to the local daemon: a join only ever speaks to the remote
//! seed, on the admission port (seed port + 1).

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::Engine as _;
use ed25519_dalek::VerifyingKey;
use url::Url;

use crate::common::config_dir::pnw_trust_domains_dir;
use crate::common::trust_context::{SK_SELF_AGE_FILE, SK_SELF_RAW_FILE, write_raw_sk_self};
use crate::proto::api::config::{
    FetchPendingMemberCertRequest, SubmitJoinRequestRequest, TrustJoinManageRpc,
    TrustJoinManageRpcClientFactory,
};
use crate::proto::rpc_impl::standalone::StandAloneClient;
use crate::proto::rpc_types::controller::BaseController;
use crate::trust::{
    JoinRequest, MemberCert, SignKey, SignedNetworkState, from_cbor,
    network_bootstrap::NetworkBootstrap, to_canonical_cbor, unwrap_armored, wrap_armored,
};
use crate::tunnel::tcp::TcpTunnelConnector;

/// Where a join has got to. Reported as it happens so the CLI can print and the
/// console can persist it — a join outlives any single request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinProgress {
    Submitting,
    AwaitingApproval,
    Approved,
}

pub type ProgressFn = Arc<dyn Fn(JoinProgress) + Send + Sync>;

#[derive(Clone)]
pub struct AcceptInviteOptions {
    /// A `privatenetwork://` invite URL, or a path to a bootstrap PEM file.
    pub source: String,
    /// Defaults to the host name.
    pub device_label: Option<String>,
    pub hint: String,
    /// Encrypts `sk_self.age`. Without one the device key stays raw on disk,
    /// which is what unattended auto-start needs.
    pub passphrase: Option<String>,
    /// Submit and wait. When false the request is only prepared on disk, to be
    /// carried to a network administrator by hand.
    pub online: bool,
    pub wait_secs: u64,
    pub poll_secs: u64,
    pub on_progress: Option<ProgressFn>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinOutcome {
    /// Approved: `member_cert.pem` and `network_state.cbor.pem` are on disk.
    Approved,
    /// The signed request is on disk; nothing was sent.
    PreparedOffline,
}

#[derive(Debug, Clone)]
pub struct AcceptInviteResult {
    pub outcome: JoinOutcome,
    pub trust_domain_id: String,
    pub network_local_id: String,
    pub network_dir: PathBuf,
    pub device_dir: PathBuf,
    /// `pending_join_request.cbor.pem`.
    pub join_request_path: PathBuf,
    /// `member_cert.pem`, once approved.
    pub member_cert_path: Option<PathBuf>,
}

/// Parse an invite from a `privatenetwork://` URL or a bootstrap PEM file.
pub fn parse_bootstrap_source(source: &str) -> Result<NetworkBootstrap> {
    if source.starts_with("privatenetwork://") {
        let url = Url::parse(source)?;
        return Ok(NetworkBootstrap::from_url(&url)?);
    }
    let text = std::fs::read_to_string(source)
        .with_context(|| format!("failed to read bootstrap file {source}"))?;
    Ok(NetworkBootstrap::from_pem(&text)?)
}

pub async fn accept_invite(options: AcceptInviteOptions) -> Result<AcceptInviteResult> {
    if options.online && options.poll_secs == 0 {
        anyhow::bail!("poll_secs must be greater than 0");
    }

    let bootstrap = parse_bootstrap_source(&options.source)?;
    bootstrap.verify_self_consistency()?;

    let trust_domain_id = bootstrap.trust_domain_id.to_string();
    let network_local_id = bootstrap.network_local_id.to_string();
    let domain_dir = pnw_trust_domains_dir()?.join(&trust_domain_id);
    ensure_bootstrap_root(&domain_dir, &bootstrap)?;

    let (sk_self, device_id, device_dir, key_file) =
        load_or_create_global_device_identity(options.passphrase.as_deref())?;

    let network_dir = domain_dir.join("networks").join(&network_local_id);
    std::fs::create_dir_all(&network_dir)
        .with_context(|| format!("failed to create {}", network_dir.display()))?;
    write_file(&network_dir.join("device_id"), format!("{device_id}\n"))?;
    std::fs::copy(device_dir.join(key_file), network_dir.join(key_file)).with_context(|| {
        format!(
            "failed to write {}",
            network_dir.join(key_file).display()
        )
    })?;
    write_file(
        &network_dir.join("network_bootstrap.cbor.pem"),
        bootstrap.to_pem(),
    )?;

    let jr = JoinRequest::new_signed(
        bootstrap.trust_domain_id,
        bootstrap.network_local_id.clone(),
        &sk_self,
        options
            .device_label
            .clone()
            .unwrap_or_else(|| gethostname::gethostname().to_string_lossy().to_string()),
        options.hint.clone(),
    );
    let join_request_path = network_dir.join("pending_join_request.cbor.pem");
    write_file(
        &join_request_path,
        wrap_armored("PNW-JOIN-REQUEST", &to_canonical_cbor(&jr)),
    )?;

    let mut result = AcceptInviteResult {
        outcome: JoinOutcome::PreparedOffline,
        trust_domain_id,
        network_local_id,
        network_dir: network_dir.clone(),
        device_dir,
        join_request_path,
        member_cert_path: None,
    };

    if options.online {
        let cert_path = submit_and_await_approval(&bootstrap, &network_dir, &jr, &options).await?;
        result.outcome = JoinOutcome::Approved;
        result.member_cert_path = Some(cert_path);
    }
    Ok(result)
}

fn write_file(path: &Path, contents: impl AsRef<[u8]>) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("failed to write {}", path.display()))
}

fn ensure_bootstrap_root(domain_dir: &Path, bootstrap: &NetworkBootstrap) -> Result<()> {
    std::fs::create_dir_all(domain_dir)
        .with_context(|| format!("failed to create {}", domain_dir.display()))?;
    let pk_root_path = domain_dir.join("pk_root.pem");
    if pk_root_path.exists() {
        let existing_pem = std::fs::read_to_string(&pk_root_path)
            .with_context(|| format!("failed to read {}", pk_root_path.display()))?;
        let existing_bytes = unwrap_armored(&existing_pem, "PNW-PK-ROOT")
            .with_context(|| format!("failed to parse {}", pk_root_path.display()))?;
        let existing_bytes: [u8; 32] = existing_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("pk_root.pem must contain 32 bytes"))?;
        let existing = VerifyingKey::from_bytes(&existing_bytes)
            .map_err(|err| anyhow::anyhow!("invalid pk_root.pem: {err}"))?;
        if existing.as_bytes() != bootstrap.pk_root.as_bytes() {
            anyhow::bail!("existing pk_root.pem does not match invite");
        }
        return Ok(());
    }
    write_file(
        &pk_root_path,
        wrap_armored("PNW-PK-ROOT", bootstrap.pk_root.as_bytes()),
    )
}

/// Reuse the machine-wide device key if there is one, otherwise mint it. A
/// passphrase is required to open an existing `sk_self.age`, and selects the age
/// form when creating one.
pub fn load_or_create_global_device_identity(
    passphrase: Option<&str>,
) -> Result<(SignKey, String, PathBuf, &'static str)> {
    let device_dir = crate::common::config_dir::pnw_config_dir()?.join("devices/default");
    let age_path = device_dir.join(SK_SELF_AGE_FILE);
    if age_path.exists() {
        let passphrase = passphrase.ok_or_else(|| {
            anyhow::anyhow!(
                "PNW_DEVICE_PASSPHRASE or --passphrase-file is required for existing sk_self.age"
            )
        })?;
        let sk_self = load_device_sign_key(&age_path, passphrase)?;
        let device_pk = sk_self.verify_key();
        let pk_path = device_dir.join("pk_self.pem");
        if pk_path.exists() {
            let pem = std::fs::read_to_string(&pk_path)
                .with_context(|| format!("failed to read {}", pk_path.display()))?;
            let stored = unwrap_armored(&pem, "PNW-PK-SELF")
                .with_context(|| format!("failed to parse {}", pk_path.display()))?;
            if stored.as_slice() != device_pk.0 {
                anyhow::bail!("global device pk_self.pem does not match sk_self.age");
            }
        }
        return Ok((sk_self, encode_device_id(&device_pk.0), device_dir, SK_SELF_AGE_FILE));
    }

    let raw_path = device_dir.join(SK_SELF_RAW_FILE);
    if raw_path.exists() {
        let bytes = std::fs::read(&raw_path)
            .with_context(|| format!("failed to read {}", raw_path.display()))?;
        let bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("sk_self.raw must contain exactly 32 bytes"))?;
        let sk_self = SignKey::from_bytes(bytes);
        let device_id = encode_device_id(&sk_self.verify_key().0);
        return Ok((sk_self, device_id, device_dir, SK_SELF_RAW_FILE));
    }

    std::fs::create_dir_all(&device_dir)
        .with_context(|| format!("failed to create {}", device_dir.display()))?;
    let sk_self = SignKey::generate();
    let device_pk = sk_self.verify_key();
    let key_file = if let Some(passphrase) = passphrase {
        write_file(&age_path, seal_device_sign_key(&sk_self, passphrase)?)?;
        SK_SELF_AGE_FILE
    } else {
        write_raw_sk_self(&raw_path, &sk_self)
            .with_context(|| format!("failed to write {}", raw_path.display()))?;
        SK_SELF_RAW_FILE
    };
    write_file(
        &device_dir.join("pk_self.pem"),
        wrap_armored("PNW-PK-SELF", &device_pk.0),
    )?;
    Ok((sk_self, encode_device_id(&device_pk.0), device_dir, key_file))
}

fn encode_device_id(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn load_device_sign_key(path: &Path, passphrase: &str) -> Result<SignKey> {
    let blob = std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let decryptor =
        age::Decryptor::new(&blob[..]).context("failed to parse device key age file")?;
    let identity =
        age::scrypt::Identity::new(age::secrecy::SecretString::from(passphrase.to_owned()));
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .context("failed to decrypt device key")?;
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;
    let bytes: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("device key plaintext must be 32 bytes"))?;
    Ok(SignKey::from_bytes(bytes))
}

fn seal_device_sign_key(sk_self: &SignKey, passphrase: &str) -> Result<Vec<u8>> {
    let mut recipient =
        age::scrypt::Recipient::new(age::secrecy::SecretString::from(passphrase.to_owned()));
    recipient.set_work_factor(2);
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .context("failed to create device-key encryptor")?;
    let mut encrypted = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted)?;
    writer.write_all(&sk_self.to_bytes())?;
    writer.finish()?;
    Ok(encrypted)
}

/// The admission endpoint sits one port above the seed's.
fn derive_join_admission_url(seed: &Url) -> Option<Url> {
    if seed.scheme() != "tcp" {
        return None;
    }
    let mut admission = seed.clone();
    admission.set_port(Some(seed.port()?.checked_add(1)?)).ok()?;
    Some(admission)
}

async fn connect_join_admission_client(
    bootstrap: &NetworkBootstrap,
) -> Result<StandAloneClient<TcpTunnelConnector>> {
    let mut last_error = None;
    for seed in &bootstrap.bootstrap_seeds {
        let Some(admission_url) = derive_join_admission_url(seed) else {
            continue;
        };
        let mut client = StandAloneClient::new(TcpTunnelConnector::new(admission_url.clone()));
        match client
            .scoped_client::<TrustJoinManageRpcClientFactory<BaseController>>(String::new())
            .await
        {
            Ok(_) => return Ok(client),
            Err(err) => last_error = Some(format!("{admission_url}: {err}")),
        }
    }
    anyhow::bail!(
        "failed to connect to join admission endpoint from invite peer hints{}",
        last_error.map(|err| format!(": {err}")).unwrap_or_default()
    )
}

async fn submit_and_await_approval(
    bootstrap: &NetworkBootstrap,
    network_dir: &Path,
    jr: &JoinRequest,
    options: &AcceptInviteOptions,
) -> Result<PathBuf> {
    let report = |p: JoinProgress| {
        if let Some(f) = options.on_progress.as_ref() {
            f(p);
        }
    };

    let mut admission_rpc = connect_join_admission_client(bootstrap).await?;
    report(JoinProgress::Submitting);
    admission_rpc
        .scoped_client::<TrustJoinManageRpcClientFactory<BaseController>>(String::new())
        .await?
        .submit_join_request(
            BaseController::default(),
            SubmitJoinRequestRequest {
                instance: None,
                join_request_cbor: to_canonical_cbor(jr),
                ttl: 6,
            },
        )
        .await
        .context("failed to submit join request to daemon")?;

    report(JoinProgress::AwaitingApproval);
    let deadline = Instant::now() + Duration::from_secs(options.wait_secs);
    loop {
        let response = admission_rpc
            .scoped_client::<TrustJoinManageRpcClientFactory<BaseController>>(String::new())
            .await?
            .fetch_pending_member_cert(
                BaseController::default(),
                FetchPendingMemberCertRequest {
                    instance: None,
                    trust_domain_id: jr.trust_domain_id.0.to_vec(),
                    network_local_id: jr.network_local_id.as_str().to_owned(),
                    applicant_pk: jr.applicant_pk.0.to_vec(),
                },
            )
            .await
            .context("failed to fetch pending member cert from daemon")?;

        if response.found {
            let cert: MemberCert = from_cbor(&response.member_cert_cbor)
                .context("daemon returned invalid member cert CBOR")?;
            if response.network_state_cbor.is_empty() {
                anyhow::bail!("daemon returned member cert without network_state");
            }
            let state: SignedNetworkState = from_cbor(&response.network_state_cbor)
                .context("daemon returned invalid network_state CBOR")?;
            if state.details.trust_domain_id != jr.trust_domain_id {
                anyhow::bail!("daemon returned network_state for a different trust domain");
            }
            if state.details.network_local_id != jr.network_local_id {
                anyhow::bail!("daemon returned network_state for a different network");
            }
            let cert_path = network_dir.join("member_cert.pem");
            write_file(&cert_path, cert.to_pem())?;
            write_file(
                &network_dir.join("network_state.cbor.pem"),
                state.to_pem(),
            )?;
            report(JoinProgress::Approved);
            return Ok(cert_path);
        }

        if Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for approval");
        }
        tokio::time::sleep(Duration::from_secs(options.poll_secs)).await;
    }
}
