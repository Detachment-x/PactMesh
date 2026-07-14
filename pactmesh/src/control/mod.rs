//! 共享治理编排核心：本地解锁 sk_root → 改 network_state → 签名 → 备份落盘。
//!
//! CLI `handle_trust_*`、TUI `tui::actions`、Web `controller` 三处共用此信封，
//! 避免重复实现"加载 root → 改状态 → 版本+1 → 签名 → 落盘"。各调用方只提供
//! 针对 `payload` 的具体变更闭包，并自行处理打印 / RPC 通知 / 响应。

pub mod embedded;
pub mod join;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::common::config_dir::pnw_trust_domains_dir;
use crate::trust::{
    from_cbor, to_canonical_cbor, validate_for_signing, view_for_member, wrap_armored, AclPolicy,
    Action, BootstrapError, Cidr, DeviceFingerprint, DeviceView, HostnameLabel, MemberCert,
    MemberCertFingerprint, MemberCertIndexEntry, NetworkBootstrap, NetworkLocalId,
    NetworkStatePayload, SignedNetworkState, TrustDomainRoot, UnsignedNetworkState,
    ACL_SCHEMA_VERSION,
};
use url::Url;

/// 低层提交：版本+1 → 运行 `mutate` → 签名 → 备份旧态(`.v<prev>`) → 落盘，返回新版本号。
///
/// 供已自行完成"读状态 / 解锁 / 校验"的调用方（如需保留特定预检/取口令顺序的
/// CLI handler）直接复用同一份签名落盘逻辑，避免重复实现版本递增与备份命名。
pub fn commit_signed(
    network_dir: &Path,
    state_path: &Path,
    original_pem: &str,
    original_state: &SignedNetworkState,
    root: &TrustDomainRoot,
    mutate: impl FnOnce(&mut UnsignedNetworkState, &TrustDomainRoot) -> Result<()>,
) -> Result<u64> {
    let prev_version = original_state.details.version;
    let mut next = original_state.details.clone();
    next.version = next.version.saturating_add(1);
    mutate(&mut next, root)?;
    let signed = next.sign(root);
    write_state_with_backup(network_dir, state_path, prev_version, original_pem, &signed)
}

/// 共享落盘尾部：备份旧态(`.v<prev>`) → 写入已签名的新态，返回新版本号。
///
/// 唯一的"备份命名 + 双写"实现：`commit_signed`（→ controller 端点 / `SigningSession`）
/// 与 CLI `handle_trust_*`（经 binary `write_pre_signed_network_state` 包装）共用，
/// 避免在 lib 与 binary 各写一份签名落盘逻辑。
pub fn write_state_with_backup(
    network_dir: &Path,
    state_path: &Path,
    previous_version: u64,
    original_pem: &str,
    next_state: &SignedNetworkState,
) -> Result<u64> {
    let backup = network_dir.join(format!("network_state.v{previous_version}.cbor.pem"));
    std::fs::write(&backup, original_pem)
        .with_context(|| format!("failed to write {}", backup.display()))?;
    std::fs::write(state_path, next_state.to_pem())
        .with_context(|| format!("failed to write {}", state_path.display()))?;
    Ok(next_state.details.version)
}

/// 一次签名会话：已解锁 root + 已读取的当前网络状态，等待提交一次变更。
pub struct SigningSession {
    pub domain_dir: PathBuf,
    pub network_dir: PathBuf,
    pub state_path: PathBuf,
    pub root: TrustDomainRoot,
    pub original_state: SignedNetworkState,
    pub original_pem: String,
}

impl SigningSession {
    /// 解析目录 → 读取 network_state → 解锁 sk_root → 校验 root id 与 trust_domain_id 一致。
    pub fn open(
        trust_domain_id: &str,
        network_local_id: &str,
        passphrase: &str,
    ) -> Result<Self> {
        let domain_dir = pnw_trust_domains_dir()?.join(trust_domain_id);
        if !domain_dir.is_dir() {
            anyhow::bail!("trust domain not found: {trust_domain_id}");
        }
        let network_dir = domain_dir.join("networks").join(network_local_id);
        let state_path = network_dir.join("network_state.cbor.pem");
        let original_pem = std::fs::read_to_string(&state_path)
            .with_context(|| format!("failed to read {}", state_path.display()))?;
        let original_state = SignedNetworkState::from_pem(&original_pem)
            .with_context(|| format!("failed to parse {}", state_path.display()))?;

        let sk_root_path = domain_dir.join("sk_root.age");
        let root = TrustDomainRoot::load_from_file(&sk_root_path, passphrase)
            .with_context(|| format!("failed to unlock {}", sk_root_path.display()))?;
        if root.id().to_string() != trust_domain_id {
            anyhow::bail!("trust_domain_id does not match sk_root.age");
        }

        Ok(Self {
            domain_dir,
            network_dir,
            state_path,
            root,
            original_state,
            original_pem,
        })
    }

    /// 当前（提交前）状态版本号。
    pub fn version(&self) -> u64 {
        self.original_state.details.version
    }

    /// 版本+1 → 运行 `mutate`（可读 root、改 next 状态）→ 签名 → 备份旧态(`.v<prev>`) → 落盘。
    /// 返回新版本号。`mutate` 失败则不落盘。
    pub fn commit(
        self,
        mutate: impl FnOnce(&mut UnsignedNetworkState, &TrustDomainRoot) -> Result<()>,
    ) -> Result<u64> {
        commit_signed(
            &self.network_dir,
            &self.state_path,
            &self.original_pem,
            &self.original_state,
            &self.root,
            mutate,
        )
    }
}

/// 一个本地信任域及其可签名网络（供 Web picker 选择"对哪个网络解锁/签名"）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct DomainInfo {
    pub trust_domain_id: String,
    pub label: String,
    /// 是否持有 `sk_root.age`（能本地签名 = 能治理）。
    pub is_root_holder: bool,
    pub networks: Vec<String>,
    /// 主网络（域的承载网络）的 network_local_id；域概念对用户隐藏，前端以此网络代表该域。
    /// `None` = 未标记（多网络域待管理员选定；单网络域由 `list_domains` 惰性回退）。
    pub base_network: Option<String>,
}

/// 枚举磁盘上的信任域及各自的网络（仅读公开元数据，不解锁任何密钥）。
pub fn list_domains() -> Result<Vec<DomainInfo>> {
    let base = pnw_trust_domains_dir()?;
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&base) else {
        return Ok(out);
    };
    for entry in entries.filter_map(std::result::Result::ok) {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let trust_domain_id = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let meta = std::fs::read_to_string(path.join("meta.toml")).unwrap_or_default();
        let meta_value = |key: &str| {
            meta.lines().find_map(|line| {
                let (k, v) = line.split_once('=')?;
                (k.trim() == key).then(|| v.trim().trim_matches('"').to_owned())
            })
        };
        let label = meta_value("label").unwrap_or_default();
        let mut networks = Vec::new();
        if let Ok(net_entries) = std::fs::read_dir(path.join("networks")) {
            for net in net_entries.filter_map(std::result::Result::ok) {
                if net.path().is_dir() {
                    networks.push(net.file_name().to_string_lossy().into_owned());
                }
            }
        }
        networks.sort();
        // base_network：meta 显式标记优先；缺失且恰有单网络时惰性回退（该网络即主网络）。
        let base_network = meta_value("base_network")
            .filter(|nid| !nid.is_empty())
            .or_else(|| (networks.len() == 1).then(|| networks[0].clone()));
        out.push(DomainInfo {
            trust_domain_id,
            label,
            is_root_holder: path.join("sk_root.age").is_file(),
            networks,
            base_network,
        });
    }
    out.sort_by(|a, b| a.trust_domain_id.cmp(&b.trust_domain_id));
    Ok(out)
}

// ---------- 成员证书读 / 重签发原语（CLI handler 与 controller 共用） ----------

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 解析 base64（URL_SAFE_NO_PAD 优先，回退 STANDARD）的成员证书指纹。
pub fn parse_member_cert_fingerprint(value: &str) -> Result<MemberCertFingerprint> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(value))
        .map_err(|_| anyhow::anyhow!("invalid fingerprint '{value}'"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("fingerprint must decode to 32 bytes"))?;
    Ok(MemberCertFingerprint(bytes))
}

/// 只读加载某网络的签名状态（不解锁 root）。返回 `(network_dir, original_pem, state)`。
pub fn read_network_state(
    trust_domain_id: &str,
    network_local_id: &str,
) -> Result<(PathBuf, String, SignedNetworkState)> {
    let domain_dir = pnw_trust_domains_dir()?.join(trust_domain_id);
    if !domain_dir.is_dir() {
        anyhow::bail!("trust domain not found: {trust_domain_id}");
    }
    let network_dir = domain_dir.join("networks").join(network_local_id);
    let state_path = network_dir.join("network_state.cbor.pem");
    let original_pem = std::fs::read_to_string(&state_path)
        .with_context(|| format!("failed to read {}", state_path.display()))?;
    let state = SignedNetworkState::from_pem(&original_pem)
        .with_context(|| format!("failed to parse {}", state_path.display()))?;
    Ok((network_dir, original_pem, state))
}

/// 读 `network_dir` 顶层散落的 `*.pem` 成员证书。
pub fn read_member_cert_cache(network_dir: &Path) -> BTreeMap<MemberCertFingerprint, MemberCert> {
    let mut certs = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(network_dir) else {
        return certs;
    };
    for entry in entries.filter_map(std::result::Result::ok) {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("pem") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(cert) = MemberCert::from_pem(&text) {
                certs.insert(cert.fingerprint(), cert);
            }
        }
    }
    certs
}

/// 读全部成员证书（顶层缓存 + `member_certs/` 子目录，后者覆盖前者）。
pub fn read_member_cert_bodies(network_dir: &Path) -> BTreeMap<MemberCertFingerprint, MemberCert> {
    let mut certs = read_member_cert_cache(network_dir);
    let Ok(entries) = std::fs::read_dir(network_dir.join("member_certs")) else {
        return certs;
    };
    for entry in entries.filter_map(std::result::Result::ok) {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("pem") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(cert) = MemberCert::from_pem(&text) {
                certs.insert(cert.fingerprint(), cert);
            }
        }
    }
    certs
}

/// 成员状态：revoked > disabled > active。
pub fn member_status(
    fingerprint: &MemberCertFingerprint,
    state: &SignedNetworkState,
) -> &'static str {
    if state
        .details
        .payload
        .revoked_certs
        .iter()
        .any(|r| r.cert_fingerprint == *fingerprint)
    {
        "revoked"
    } else if state
        .details
        .payload
        .disabled_certs
        .iter()
        .any(|d| d.cert_fingerprint == *fingerprint)
    {
        "disabled"
    } else {
        "active"
    }
}

/// 富成员视图列表（`DeviceView`，serde-Serialize），供 list-members 与 Web `/api/members`。
pub fn list_member_views(
    network_dir: &Path,
    state: &SignedNetworkState,
    network_local_id: &str,
) -> Vec<DeviceView> {
    let certs = read_member_cert_bodies(network_dir);
    let now = now_unix_secs();
    let local_device_id = std::fs::read_to_string(network_dir.join("device_id"))
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let has_root_key = network_dir
        .parent()
        .map(|domain_dir| domain_dir.join("sk_root.age").is_file())
        .unwrap_or(false);
    state
        .details
        .payload
        .member_cert_index
        .iter()
        .map(|entry| {
            view_for_member(
                entry,
                certs.get(&entry.fingerprint),
                state,
                network_local_id,
                local_device_id.as_deref(),
                has_root_key,
                now,
            )
        })
        .collect()
}

/// 组装 hostname 唯一性校验所需的"现存活跃"条目（排除 target、排除已吊销）。
pub fn live_hostname_entries(
    state: &SignedNetworkState,
    certs: &BTreeMap<MemberCertFingerprint, MemberCert>,
    target: MemberCertFingerprint,
) -> Vec<(MemberCertFingerprint, Option<HostnameLabel>)> {
    state
        .details
        .payload
        .member_cert_index
        .iter()
        .filter(|entry| entry.fingerprint != target)
        .filter(|entry| member_status(&entry.fingerprint, state) != "revoked")
        .filter_map(|entry| {
            let cert = certs.get(&entry.fingerprint)?;
            Some((
                entry.fingerprint,
                crate::trust::effective_hostname(cert, state),
            ))
        })
        .collect()
}

/// 用重签发的新证书替换 index 中旧指纹条目（移除旧 → 追加新）。
pub fn replace_member_index_entry(
    index: &mut Vec<MemberCertIndexEntry>,
    old_fp: MemberCertFingerprint,
    cert: &MemberCert,
) {
    index.retain(|entry| entry.fingerprint != old_fp);
    index.push(MemberCertIndexEntry {
        fingerprint: cert.fingerprint(),
        device_label: cert.details.device_label.clone(),
        issued_at: cert.details.not_before,
        expires_at: cert.details.expires_at,
    });
}

/// 落盘重签发的成员证书到 `member_certs/<fp>.pem`。
pub fn write_reissued_member_cert(network_dir: &Path, cert: &MemberCert) -> Result<()> {
    let cert_dir = network_dir.join("member_certs");
    std::fs::create_dir_all(&cert_dir)
        .with_context(|| format!("failed to create {}", cert_dir.display()))?;
    std::fs::write(
        cert_dir.join(format!("{}.pem", cert.fingerprint())),
        cert.to_pem(),
    )
    .context("failed to write reissued member cert")
}

// ---------- M4：建域 / 建网 / ACL tags / invite 导出 ----------

/// 管理口令长度校验（≥8 字符，去尾部换行）。Web 内联口令即用即清，绝不缓存。
fn validate_passphrase(passphrase: &str) -> Result<String> {
    let p = passphrase.trim_end_matches(['\r', '\n']).to_owned();
    if p.len() < 8 {
        anyhow::bail!("root key passphrase must be at least 8 characters");
    }
    Ok(p)
}

fn parse_default_action(value: &str) -> Result<Action> {
    match value {
        "accept" => Ok(Action::Accept),
        "drop" => Ok(Action::Drop),
        other => anyhow::bail!("unsupported default action '{other}', expected accept or drop"),
    }
}

fn default_action_name(action: Action) -> &'static str {
    match action {
        Action::Accept => "accept",
        Action::Drop => "drop",
    }
}

fn domain_label(domain_dir: &Path) -> Option<String> {
    let meta = std::fs::read_to_string(domain_dir.join("meta.toml")).unwrap_or_default();
    meta.lines().find_map(|line| {
        let (k, v) = line.split_once('=')?;
        (k.trim() == "label").then(|| v.trim().trim_matches('"').to_owned())
    })
}

#[derive(serde::Serialize)]
pub struct CreateDomainResult {
    pub trust_domain_id: String,
    pub path: String,
}

/// 生成新信任域 root（确立新管理口令）→ 落盘 sk_root.age / pk_root.pem / meta.toml。
pub fn create_domain(label: &str, passphrase: &str) -> Result<CreateDomainResult> {
    let passphrase = validate_passphrase(passphrase)?;
    let root = TrustDomainRoot::generate();
    let trust_domain_id = root.id();
    let domain_dir = pnw_trust_domains_dir()?.join(trust_domain_id.to_string());
    if domain_dir.exists() {
        anyhow::bail!(
            "trust domain directory already exists: {}",
            domain_dir.display()
        );
    }
    std::fs::create_dir_all(&domain_dir)
        .with_context(|| format!("failed to create {}", domain_dir.display()))?;
    root.save_to_file(&domain_dir.join("sk_root.age"), &passphrase)
        .with_context(|| format!("failed to write {}", domain_dir.join("sk_root.age").display()))?;
    std::fs::write(
        domain_dir.join("pk_root.pem"),
        wrap_armored("PNW-PK-ROOT", root.public_key().as_bytes()),
    )
    .with_context(|| format!("failed to write {}", domain_dir.join("pk_root.pem").display()))?;
    std::fs::write(
        domain_dir.join("meta.toml"),
        format!(
            "label = {:?}\ncreated_at = {}\ncurve = {:?}\n",
            label,
            now_unix_secs(),
            "ed25519"
        ),
    )
    .with_context(|| format!("failed to write {}", domain_dir.join("meta.toml").display()))?;
    Ok(CreateDomainResult {
        trust_domain_id: trust_domain_id.to_string(),
        path: domain_dir.display().to_string(),
    })
}

/// 标记域的主网络（承载网络）到 `meta.toml` 的 `base_network`。存在则原地替换，否则追加。
/// 供一步建网（`api_network_run`）与单网络域惰性回写复用。
pub fn set_domain_base_network(trust_domain_id: &str, network_local_id: &str) -> Result<()> {
    let meta_path = pnw_trust_domains_dir()?
        .join(trust_domain_id)
        .join("meta.toml");
    let existing = std::fs::read_to_string(&meta_path).unwrap_or_default();
    let mut lines: Vec<String> = Vec::new();
    let mut replaced = false;
    for line in existing.lines() {
        let is_base = line
            .split_once('=')
            .map(|(k, _)| k.trim() == "base_network")
            .unwrap_or(false);
        if is_base {
            lines.push(format!("base_network = {network_local_id:?}"));
            replaced = true;
        } else {
            lines.push(line.to_owned());
        }
    }
    if !replaced {
        lines.push(format!("base_network = {network_local_id:?}"));
    }
    let mut out = lines.join("\n");
    out.push('\n');
    std::fs::write(&meta_path, out)
        .with_context(|| format!("failed to write {}", meta_path.display()))?;
    Ok(())
}

#[derive(serde::Serialize)]
pub struct CreateNetworkResult {
    pub trust_domain_id: String,
    pub network_local_id: String,
    pub path: String,
    pub version: u64,
    pub default_action: String,
}

/// 在既有信任域下建网：解锁域 root → 签名 v1 空状态落盘。
pub fn create_network(
    trust_domain_id: &str,
    network_local_id: &str,
    default_action: &str,
    passphrase: &str,
) -> Result<CreateNetworkResult> {
    let domain_dir = pnw_trust_domains_dir()?.join(trust_domain_id);
    if !domain_dir.is_dir() {
        anyhow::bail!("trust domain not found: {trust_domain_id}");
    }
    let nlid = NetworkLocalId::try_from_str(network_local_id)
        .with_context(|| format!("invalid network_local_id '{network_local_id}'"))?;
    let network_dir = domain_dir.join("networks").join(nlid.to_string());
    if network_dir.exists() {
        anyhow::bail!("network already exists: {}", network_dir.display());
    }
    let root = TrustDomainRoot::load_from_file(&domain_dir.join("sk_root.age"), passphrase)
        .with_context(|| format!("failed to unlock {}", domain_dir.join("sk_root.age").display()))?;
    if root.id().to_string() != trust_domain_id {
        anyhow::bail!("trust_domain_id does not match sk_root.age");
    }
    let action = parse_default_action(default_action)?;
    let acl = AclPolicy {
        tags: BTreeMap::new(),
        rules: Vec::new(),
        default_action: action,
        schema_version: ACL_SCHEMA_VERSION,
    };
    let state = UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: nlid.clone(),
        version: 1,
        payload: NetworkStatePayload {
            member_cert_index: Vec::new(),
            revoked_certs: Vec::new(),
            disabled_certs: Vec::new(),
            acl: to_canonical_cbor(&acl),
            routes: Vec::new(),
            peer_hints: Vec::new(),
            ip_assignments: Vec::new(),
            capability_grants: Vec::new(),
            hostname_bindings: Vec::new(),
            label_bindings: Vec::new(),
        },
    }
    .sign(&root);
    std::fs::create_dir_all(&network_dir)
        .with_context(|| format!("failed to create {}", network_dir.display()))?;
    let state_path = network_dir.join("network_state.cbor.pem");
    std::fs::write(&state_path, state.to_pem())
        .with_context(|| format!("failed to write {}", state_path.display()))?;
    Ok(CreateNetworkResult {
        trust_domain_id: trust_domain_id.to_string(),
        network_local_id: nlid.to_string(),
        path: network_dir.display().to_string(),
        version: 1,
        default_action: default_action_name(action).to_string(),
    })
}

/// 从 network_state 解码 ACL 策略（tags 编辑读源）。
pub fn acl_policy_from_state(state: &SignedNetworkState) -> Result<AclPolicy> {
    from_cbor(&state.details.payload.acl).context("failed to decode network_state ACL policy")
}

/// 把 ACL 策略编码为规范 CBOR（写回 payload.acl）。
pub fn encode_acl_policy(policy: &AclPolicy) -> Vec<u8> {
    to_canonical_cbor(policy)
}

fn member_fingerprints_for_acl(state: &SignedNetworkState) -> Vec<DeviceFingerprint> {
    state
        .details
        .payload
        .member_cert_index
        .iter()
        .map(|e| DeviceFingerprint(e.fingerprint.0))
        .collect()
}

fn proxy_cidrs_for_acl(network_dir: &Path, state: &SignedNetworkState) -> Vec<Cidr> {
    let certs = read_member_cert_bodies(network_dir);
    state
        .details
        .payload
        .member_cert_index
        .iter()
        .filter_map(|e| certs.get(&e.fingerprint))
        .flat_map(|cert| cert.details.capabilities.can_proxy_subnet.iter())
        .map(|net| Cidr::new(net.ip(), net.prefix()))
        .collect()
}

/// 签名前校验 ACL 策略一致性（成员指纹/代理网段引用合法）。
pub fn validate_acl_for_signing(
    policy: &AclPolicy,
    network_dir: &Path,
    state: &SignedNetworkState,
) -> Result<()> {
    validate_for_signing(
        policy,
        &member_fingerprints_for_acl(state),
        &proxy_cidrs_for_acl(network_dir, state),
    )?;
    Ok(())
}

/// 把成员证书指纹转为 ACL tags 用的设备指纹。
pub fn cert_to_device_fingerprint(fp: MemberCertFingerprint) -> DeviceFingerprint {
    DeviceFingerprint(fp.0)
}

/// invite 导出结果：`content`=URL 或 PEM；`seed_count`=最终入网落脚点数；
/// `omitted`=URL 形态因超长而从尾部（低优先级）丢弃的落脚点数（file/pem 恒为 0）。
pub struct InviteExport {
    pub content: String,
    pub seed_count: usize,
    pub omitted: usize,
}

/// 导出入网引导（invite）。只读，不解锁。
///
/// 落脚点按优先级合并去重：`manual_seeds`（手填）> 未过期 peer-hints（当
/// `include_peer_hints`）> `local_seeds`（本机可达地址，调用方已按 public→接口序排好）。
/// `format` = url | file/pem；URL 超长时从尾部逐个丢弃低优先级落脚点直至可容，
/// file/pem 全量不截断。
pub fn export_invite(
    trust_domain_id: &str,
    network_local_id: &str,
    manual_seeds: Vec<Url>,
    local_seeds: Vec<Url>,
    include_peer_hints: bool,
    format: &str,
) -> Result<InviteExport> {
    let domain_dir = pnw_trust_domains_dir()?.join(trust_domain_id);
    if !domain_dir.is_dir() {
        anyhow::bail!("trust domain not found: {trust_domain_id}");
    }
    let (_network_dir, _pem, state) = read_network_state(trust_domain_id, network_local_id)?;
    if state.details.trust_domain_id.to_string() != trust_domain_id {
        anyhow::bail!("trust_domain_id does not match network_state");
    }
    if state.details.network_local_id.to_string() != network_local_id {
        anyhow::bail!("network_local_id does not match network_state");
    }

    let mut ordered: Vec<Url> = manual_seeds;
    if include_peer_hints {
        let now = now_unix_secs();
        for hint in &state.details.payload.peer_hints {
            if hint.expires_at.is_some_and(|exp| exp <= now) {
                continue;
            }
            if let Ok(url) = Url::parse(hint.url.trim()) {
                ordered.push(url);
            }
        }
    }
    ordered.extend(local_seeds);

    let mut seen = std::collections::HashSet::new();
    ordered.retain(|url| seen.insert(url.as_str().to_owned()));

    if ordered.is_empty() {
        anyhow::bail!("no seed available (manual, peer-hints, or local listeners all empty)");
    }

    let build = |seeds: Vec<Url>| -> Result<NetworkBootstrap, BootstrapError> {
        NetworkBootstrap::export_from_domain_dir(
            &domain_dir,
            state.details.network_local_id.clone(),
            seeds,
            domain_label(&domain_dir),
            Some(network_local_id.to_string()),
            None,
        )
    };

    match format {
        "url" => {
            let mut seeds = ordered;
            let mut omitted = 0;
            loop {
                match build(seeds.clone())?.to_url() {
                    Ok(url) => {
                        return Ok(InviteExport {
                            content: url.to_string(),
                            seed_count: seeds.len(),
                            omitted,
                        });
                    }
                    Err(BootstrapError::TooLongForQr(_)) if seeds.len() > 1 => {
                        seeds.pop();
                        omitted += 1;
                    }
                    Err(err) => return Err(err.into()),
                }
            }
        }
        "file" | "pem" => {
            let seed_count = ordered.len();
            Ok(InviteExport {
                content: build(ordered)?.to_pem(),
                seed_count,
                omitted: 0,
            })
        }
        other => anyhow::bail!("invalid format '{other}' (url|file)"),
    }
}
