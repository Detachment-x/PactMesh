//! TUI 异步动作：需要本地解锁 sk_root + 写盘的逻辑。
//!
//! v0 PR-4 仅实现 `approve_join`。`:reject` 复用 state::reject_join_request，
//! `:revoke`/`:reconnect`/`:restart-connector`/`:export-bundle` 在 mod.rs 给
//! flash hint，不在此实现（避免重复 CLI 大段代码或拍脑袋取参数）。

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use tokio::sync::Mutex;

use crate::common::config_dir::pnw_trust_domains_dir;
use crate::proto::api::config::{
    ApproveJoinRequestRequest, TrustJoinManageRpc, TrustJoinManageRpcClientFactory,
};
use crate::proto::api::instance::InstanceIdentifier;
use crate::proto::rpc_impl::standalone::StandAloneClient;
use crate::proto::rpc_types::controller::BaseController;
use crate::trust::{
    Capabilities, MemberCert, MemberCertIndexEntry, NetworkLocalId, SignedNetworkState,
    TrustDomainRoot, UnsignedMemberCert, from_cbor, to_canonical_cbor,
};
use crate::tui::state::JoinRow;
use crate::tunnel::tcp::TcpTunnelConnector;

const ONE_YEAR_SECS: u64 = 365 * 24 * 60 * 60;

pub struct ApproveOutcome {
    pub short_fp: String,
    pub network_state_version: u64,
    pub device_label: String,
}

pub async fn approve_join(
    rpc: &std::sync::Arc<Mutex<StandAloneClient<TcpTunnelConnector>>>,
    instance: &InstanceIdentifier,
    row: &JoinRow,
    passphrase: &str,
) -> Result<ApproveOutcome> {
    let domain_dir = pnw_trust_domains_dir()?.join(&row.trust_domain_id_b64);
    if !domain_dir.is_dir() {
        anyhow::bail!("trust domain dir not found: {}", domain_dir.display());
    }
    let sk_root_path = domain_dir.join("sk_root.age");
    let root = TrustDomainRoot::load_from_file(&sk_root_path, passphrase)
        .with_context(|| format!("failed to unlock {}", sk_root_path.display()))?;
    if root.id().0.as_slice() != row.trust_domain_id.as_slice() {
        anyhow::bail!("sk_root.age does not match selected trust_domain_id");
    }

    let network_dir = domain_dir.join("networks").join(&row.network_local_id);
    let state_path = network_dir.join("network_state.cbor.pem");
    let original_pem = std::fs::read_to_string(&state_path)
        .with_context(|| format!("failed to read {}", state_path.display()))?;
    let mut state = SignedNetworkState::from_pem(&original_pem)
        .with_context(|| format!("failed to parse {}", state_path.display()))?;

    let applicant_pk_bytes: [u8; 32] = row
        .applicant_pk
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("applicant_pk must be 32 bytes"))?;
    let now = now_unix_secs();
    let cert = UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str(&row.network_local_id)
            .map_err(|err| anyhow::anyhow!("invalid network_local_id: {err}"))?,
        device_pk: VerifyingKey::from_bytes(&applicant_pk_bytes)
            .context("applicant_pk is not a valid ed25519 key")?,
        device_label: row.device_label.clone(),
        not_before: now.saturating_sub(1),
        expires_at: now.saturating_add(ONE_YEAR_SECS),
        capabilities: Capabilities {
            can_relay_data: false,
            can_relay_control: false,
            can_proxy_subnet: Vec::new(),
        },
        network_state_version_ref: state.details.version,
        hostname: None,
    }
    .sign(&root);

    let client = {
        let mut g = rpc.lock().await;
        g.scoped_client::<TrustJoinManageRpcClientFactory<BaseController>>(String::new())
            .await
            .context("creating trust join manage rpc client")?
    };
    let response = client
        .approve_join_request(
            BaseController::default(),
            ApproveJoinRequestRequest {
                instance: Some(instance.clone()),
                trust_domain_id: row.trust_domain_id.clone(),
                network_local_id: row.network_local_id.clone(),
                applicant_pk: row.applicant_pk.clone(),
                member_cert_cbor: Some(to_canonical_cbor(&cert)),
            },
        )
        .await
        .context("daemon refused to approve join request")?;

    let issued: MemberCert = from_cbor(&response.member_cert_cbor)
        .context("daemon returned invalid member cert CBOR")?;
    let fingerprint = issued.fingerprint();
    let device_label = issued.details.device_label.clone();

    let already = state
        .details
        .payload
        .member_cert_index
        .iter()
        .any(|e| e.fingerprint == fingerprint);
    let new_version = if already {
        state.details.version
    } else {
        state
            .details
            .payload
            .member_cert_index
            .push(MemberCertIndexEntry {
                fingerprint,
                device_label: device_label.clone(),
                issued_at: issued.details.not_before,
                expires_at: issued.details.expires_at,
            });
        write_signed_state(&network_dir, &state, original_pem, &root)?
    };

    let cert_dir = network_dir.join("member_certs");
    std::fs::create_dir_all(&cert_dir)
        .with_context(|| format!("failed to create {}", cert_dir.display()))?;
    std::fs::write(cert_dir.join(format!("{fingerprint}.pem")), issued.to_pem())
        .with_context(|| format!("failed to write {fingerprint}.pem"))?;

    let short_fp: String = fingerprint.to_string().chars().take(8).collect();
    Ok(ApproveOutcome {
        short_fp,
        network_state_version: new_version,
        device_label,
    })
}

fn write_signed_state(
    network_dir: &Path,
    state: &SignedNetworkState,
    original_pem: String,
    root: &TrustDomainRoot,
) -> Result<u64> {
    let mut next = state.details.clone();
    let next_version = next.version.saturating_add(1);
    next.version = next_version;
    let next = next.sign(root);
    let backup = network_dir.join(format!("network_state.v{}.cbor.pem", state.details.version));
    std::fs::write(&backup, original_pem)
        .with_context(|| format!("failed to write {}", backup.display()))?;
    std::fs::write(network_dir.join("network_state.cbor.pem"), next.to_pem())
        .with_context(|| "failed to write network_state.cbor.pem")?;
    Ok(next_version)
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
