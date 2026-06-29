use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ffi::OsString,
    future::Future,
    io::IsTerminal,
    io::{Read as _, Write as _},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    time::Duration,
    vec,
};

use anyhow::Context;
use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use cidr::Ipv4Inet;
use clap::{ArgAction, Args, CommandFactory, Parser, Subcommand, builder::BoolishValueParser};
use ed25519_dalek::VerifyingKey;
use humansize::format_size;
use pactmesh::ShellType;
use pnet::ipnetwork::IpNetwork as IpNet;
use rust_i18n::t;
use service_manager::*;
use tabled::settings::{Disable, Modify, Style, Width, location::ByColumnName, object::Columns};
use terminal_size::{Width as TerminalWidth, terminal_size};
use unicode_width::UnicodeWidthStr;

use pactmesh::service_manager::{Service, ServiceInstallOptions};
use tokio::time::timeout;
use url::Url;

use pactmesh::{
    common::{
        config::TomlConfigLoader,
        config_dir::{pnw_config_dir, pnw_serve_instances_dir, pnw_trust_domains_dir},
        constants::PACTMESH_VERSION,
        stun::{StunInfoCollector, StunInfoCollectorTrait},
        trust_context::{SK_SELF_AGE_FILE, SK_SELF_RAW_FILE, write_raw_sk_self},
    },
    peers,
    proto::{
        acl::AclStats,
        api::{
            config::{
                AclPatch, ApproveJoinRequestRequest, ConfigPatchAction, ConfigRpc,
                ConfigRpcClientFactory, FetchPendingMemberCertRequest, InstanceConfigPatch,
                ListPendingJoinRequestsRequest, PatchConfigRequest, PortForwardPatch,
                RejectJoinRequestRequest, StringPatch, SubmitJoinRequestRequest,
                TrustJoinManageRpc, TrustJoinManageRpcClientFactory, UpgradePeerToRootRequest,
                UrlPatch,
            },
            instance::{
                AclManageRpc, AclManageRpcClientFactory, Connector, ConnectorManageRpc,
                ConnectorManageRpcClientFactory, CredentialManageRpc,
                CredentialManageRpcClientFactory, DumpRouteRequest, ForeignNetworkEntryPb,
                GenerateCredentialRequest, GetAclStatsRequest, GetPrometheusStatsRequest,
                GetStatsRequest, GetVpnPortalInfoRequest, GetWhitelistRequest,
                GetWhitelistResponse, InstanceIdentifier, ListConnectorRequest,
                ListCredentialsRequest, ListCredentialsResponse, ListForeignNetworkRequest,
                ListGlobalForeignNetworkRequest, ListMappedListenerRequest, ListPeerRequest,
                ListPeerResponse, ListPortForwardRequest, ListPortForwardResponse,
                ListRouteRequest, ListRouteResponse, MappedListener, MappedListenerManageRpc,
                MappedListenerManageRpcClientFactory, MetricSnapshot, NodeInfo, PeerManageRpc,
                PeerManageRpcClientFactory, PortForwardManageRpc,
                PortForwardManageRpcClientFactory, RevokeCredentialRequest, ShowNodeInfoRequest,
                StatsRpc, StatsRpcClientFactory, TcpProxyEntryState, TcpProxyEntryTransportType,
                TcpProxyRpc, TcpProxyRpcClientFactory, TrustedKeySourcePb, VpnPortalInfo,
                VpnPortalRpc, VpnPortalRpcClientFactory,
                instance_identifier::{InstanceSelector, Selector},
                list_global_foreign_network_response, list_peer_route_pair,
            },
            logger::{
                GetLoggerConfigRequest, LogLevel, LoggerRpc, LoggerRpcClientFactory,
                SetLoggerConfigRequest,
            },
            manage::{
                ListNetworkInstanceMetaRequest, ListNetworkInstanceRequest, WebClientService,
                WebClientServiceClientFactory,
            },
        },
        common::{NatType, PortForwardConfigPb, SocketType},
        rpc_impl::standalone::StandAloneClient,
        rpc_types::controller::BaseController,
    },
    trust::{
        ACL_SCHEMA_VERSION, AclPolicy, AclRule, Action, DeviceFingerprint, HostnameLabel,
        JoinRequest, MemberCertIndexEntry, NetworkLocalId, NetworkStatePayload, PacketTuple,
        PeerHint, PeerMatchContext, PortSpec, Proto, Selector as AclSelector, SignKey,
        SignedNetworkState, TagName, TrustDomainRoot, UnsignedNetworkState, decide, from_cbor,
        hostname::check_hostname_unique,
        network_bootstrap::{NetworkBootstrap, bootstrap_to_qr_svg},
        revocation::RevocationReason,
        selector_match, to_canonical_cbor, wrap_armored,
    },
    tunnel::{TunnelScheme, tcp::TcpTunnelConnector},
    utils::{PeerRoutePair, string::cost_to_str},
};

rust_i18n::i18n!("locales", fallback = "en");

#[derive(Parser, Debug)]
#[command(name = "pactmesh", author, version = PACTMESH_VERSION, about, long_about = None)]
struct Cli {
    #[arg(
        short = 'p',
        long,
        default_value = "127.0.0.1:15888",
        help = "pactmesh-core rpc portal address"
    )]
    rpc_portal: SocketAddr,

    #[arg(short, long, default_value = "false", help = "verbose output")]
    verbose: bool,

    #[arg(
        short = 'o',
        long = "output",
        value_enum,
        default_value = "table",
        help = "output format"
    )]
    output_format: OutputFormat,

    #[arg(
        long = "no-trunc",
        default_value = "false",
        help = "disable column truncation"
    )]
    no_trunc: bool,

    #[command(flatten)]
    instance_select: InstanceSelectArgs,

    #[command(subcommand)]
    sub_command: SubCommand,
}

#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
enum SubCommand {
    #[command(about = "show peers info")]
    Peer(PeerArgs),
    #[command(about = "manage connectors")]
    Connector(ConnectorArgs),
    #[command(about = "manage mapped listeners")]
    MappedListener(MappedListenerArgs),
    #[command(about = "do stun test")]
    Stun,
    #[command(about = "show route info")]
    Route(RouteArgs),
    #[command(about = "show vpn portal (wireguard) info")]
    VpnPortal,
    #[command(about = "inspect self pactmesh-core status")]
    Node(NodeArgs),
    #[command(about = "manage pactmesh-core as a system service")]
    Service(ServiceArgs),
    #[command(about = "show tcp/kcp proxy status")]
    Proxy,
    #[command(about = "show ACL rules statistics")]
    Acl(AclArgs),
    #[command(about = "manage port forwarding")]
    PortForward(PortForwardArgs),
    #[command(about = "manage TCP/UDP whitelist")]
    Whitelist(WhitelistArgs),
    #[command(about = "show statistics information")]
    Stats(StatsArgs),
    #[command(about = "manage logger configuration")]
    Logger(LoggerArgs),
    #[command(about = "manage temporary credentials")]
    Credential(CredentialArgs),
    #[command(about = "export/import trust-domain bootstrap bundles")]
    Bootstrap(BootstrapArgs),
    #[command(about = "deprecated no-TTY test fallback; prefer 'pactmesh tui'")]
    Lab(LabArgs),
    #[command(about = "manage privateNetwork trust domains")]
    Trust(TrustArgs),
    #[command(about = "serve the local web controller (browser admin console)")]
    Controller(ControllerArgs),
    #[command(about = "first-run setup: create domain+network, bootstrap this device, start daemon and web console")]
    Quickstart(QuickstartArgs),
    #[command(about = "open the running web controller in the default browser")]
    Web,
    #[command(about = "run the Windows system-tray launcher for the web controller")]
    Tray,
    #[command(about = "unattended supervisor: unseal device passphrase, run daemon + web console (for boot autostart)")]
    Serve(ServeArgs),
    #[command(about = "interactive ratatui console (Node + Peers v0)")]
    Tui,
    #[command(about = t!("core_clap.generate_completions").to_string())]
    GenAutocomplete { shell: ShellType },
}

#[derive(clap::ValueEnum, Debug, Clone, PartialEq)]
enum OutputFormat {
    Table,
    Json,
}

#[derive(Parser, Debug)]
struct InstanceSelectArgs {
    #[arg(short = 'i', long = "instance-id", help = "the instance id")]
    id: Option<uuid::Uuid>,

    #[arg(short = 'n', long = "instance-name", help = "the instance name")]
    name: Option<String>,
}

impl From<&InstanceSelectArgs> for InstanceIdentifier {
    fn from(args: &InstanceSelectArgs) -> Self {
        InstanceIdentifier {
            selector: match args.id {
                Some(id) => Some(Selector::Id(id.into())),
                None => Some(Selector::InstanceSelector(InstanceSelector {
                    name: args.name.clone(),
                })),
            },
        }
    }
}

#[derive(Args, Debug)]
struct ControllerArgs {
    #[arg(
        long,
        default_value = "127.0.0.1:15810",
        help = "address for the web controller to listen on (loopback only)"
    )]
    listen: SocketAddr,
    #[arg(
        long,
        env = "PACTMESH_CONTROLLER_TOKEN",
        help = "fixed access token (random per-run if omitted)"
    )]
    token: Option<String>,
    #[arg(
        long,
        default_value = "900",
        help = "root passphrase unlock TTL in seconds (reserved for later milestones)"
    )]
    unlock_ttl_secs: u64,
}

#[derive(Args, Debug)]
struct QuickstartArgs {
    #[arg(long, default_value = "home", help = "network id to create")]
    network_id: String,
    #[arg(long, default_value = "home", help = "trust-domain label")]
    domain_label: String,
    #[arg(long, help = "this device's label (defaults to hostname)")]
    device_label: Option<String>,
    #[arg(
        long,
        default_value = "accept",
        help = "network default ACL action (accept|drop)"
    )]
    default_action: String,
    #[arg(
        long,
        default_value = "tcp://0.0.0.0:11010",
        help = "daemon listener url"
    )]
    listeners: String,
    #[arg(
        long,
        help = "run daemon without a TUN device (no VPN dataplane; for testing)"
    )]
    no_tun: bool,
    #[arg(
        long,
        default_value = "127.0.0.1:15810",
        help = "web console listen address (loopback only)"
    )]
    listen: SocketAddr,
    #[arg(
        long,
        env = "PACTMESH_CONTROLLER_TOKEN",
        help = "fixed web console access token (random per-run if omitted)"
    )]
    token: Option<String>,
    #[arg(
        long,
        default_value = "900",
        help = "root passphrase unlock TTL in seconds"
    )]
    unlock_ttl_secs: u64,
    #[arg(long, help = "file containing the root management passphrase")]
    passphrase_file: Option<PathBuf>,
    #[arg(long, help = "file containing the device key passphrase")]
    device_passphrase_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct ServeArgs {
    #[arg(
        long,
        default_value = "127.0.0.1:15810",
        help = "web console listen address (loopback only)"
    )]
    listen: SocketAddr,
    #[arg(
        long,
        default_value = "900",
        help = "root passphrase unlock TTL in seconds"
    )]
    unlock_ttl_secs: u64,
    #[arg(
        long,
        help = "run the daemon without a TUN device (no VPN dataplane; for testing)"
    )]
    no_tun: bool,
    #[command(subcommand)]
    sub_command: Option<ServeSubCommand>,
}

#[derive(Subcommand, Debug)]
enum ServeSubCommand {
    #[command(about = "seal the device passphrase and write serve config for unattended boot")]
    Seal(ServeSealArgs),
    #[command(about = "run the supervised daemon pinned to a sealed network (legacy; new installs start empty and attach networks at runtime)")]
    Run(ServeRunArgs),
}

#[derive(Args, Debug)]
struct ServeSealArgs {
    #[arg(long, help = "trust domain id (auto-detected if exactly one exists)")]
    trust_domain_id: Option<String>,
    #[arg(long, help = "network id (auto-detected if the domain has exactly one)")]
    network_id: Option<String>,
    #[arg(
        long,
        default_value = "tcp://0.0.0.0:11010",
        help = "daemon listener url"
    )]
    listeners: String,
    #[arg(
        long,
        help = "run daemon without a TUN device (no VPN dataplane; for testing)"
    )]
    no_tun: bool,
    #[arg(
        long,
        default_value = "127.0.0.1:15810",
        help = "web console listen address (loopback only)"
    )]
    listen: SocketAddr,
    #[arg(long, help = "file containing the device key passphrase")]
    device_passphrase_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct ServeRunArgs {
    #[arg(
        long,
        default_value = "900",
        help = "root passphrase unlock TTL in seconds"
    )]
    unlock_ttl_secs: u64,
}

/// Non-secret boot config persisted by `serve seal` and consumed by `serve run`.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct ServeConfig {
    trust_domain_id: String,
    network_id: String,
    listeners: String,
    no_tun: bool,
    listen: String,
}

const SERVE_CONFIG_FILE: &str = "serve.json";
const SERVE_SEALED_FILE: &str = "serve-device.sealed";

fn serve_seal(args: &ServeSealArgs) -> Result<(), Error> {
    let domains = pactmesh::control::list_domains()?;
    if domains.is_empty() {
        anyhow::bail!("no trust domain found; run `pactmesh quickstart` first");
    }
    let trust_domain_id = match &args.trust_domain_id {
        Some(td) => {
            if !domains.iter().any(|d| &d.trust_domain_id == td) {
                anyhow::bail!("trust domain '{td}' not found");
            }
            td.clone()
        }
        None => {
            if domains.len() != 1 {
                let ids: Vec<&str> = domains.iter().map(|d| d.trust_domain_id.as_str()).collect();
                anyhow::bail!(
                    "multiple trust domains exist; pass --trust-domain-id (one of: {})",
                    ids.join(", ")
                );
            }
            domains[0].trust_domain_id.clone()
        }
    };
    let domain = domains
        .iter()
        .find(|d| d.trust_domain_id == trust_domain_id)
        .expect("trust domain just validated to exist");
    let network_id = match &args.network_id {
        Some(nid) => {
            if !domain.networks.iter().any(|n| n == nid) {
                anyhow::bail!("network '{nid}' not found in trust domain '{trust_domain_id}'");
            }
            nid.clone()
        }
        None => {
            if domain.networks.len() != 1 {
                anyhow::bail!(
                    "trust domain '{trust_domain_id}' has {} networks; pass --network-id (one of: {})",
                    domain.networks.len(),
                    domain.networks.join(", ")
                );
            }
            domain.networks[0].clone()
        }
    };

    let device_passphrase =
        resolve_quickstart_device_passphrase(args.device_passphrase_file.as_ref())?;
    let sealed = pactmesh::secret_seal::seal(device_passphrase.as_bytes())
        .context("failed to seal device passphrase")?;
    // The sealed blob must round-trip on this machine before we trust it at boot.
    let roundtrip = pactmesh::secret_seal::unseal(&sealed).context("seal self-check failed")?;
    if roundtrip != device_passphrase.as_bytes() {
        anyhow::bail!("seal self-check mismatch; refusing to write a bad sealed file");
    }

    let config_dir = pnw_config_dir()?;
    let sealed_path = config_dir.join(SERVE_SEALED_FILE);
    let config_path = config_dir.join(SERVE_CONFIG_FILE);
    write_private_file(&sealed_path, &sealed)?;
    let config = ServeConfig {
        trust_domain_id: trust_domain_id.clone(),
        network_id: network_id.clone(),
        listeners: args.listeners.clone(),
        no_tun: args.no_tun,
        listen: args.listen.to_string(),
    };
    write_private_file(&config_path, serde_json::to_string_pretty(&config)?.as_bytes())?;

    println!("sealed device passphrase -> {}", sealed_path.display());
    println!("serve config            -> {}", config_path.display());
    println!("trust domain: {trust_domain_id}");
    println!("network:      {network_id}");
    println!();
    println!("unattended start:        `pactmesh serve run`");
    println!("register as boot service: `pactmesh service install --serve`");
    Ok(())
}

fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> Result<(), Error> {
    std::fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to chmod {}", path.display()))?;
    }
    Ok(())
}

fn quickstart_core_path(exe: &std::path::Path) -> Result<PathBuf, Error> {
    let name = if cfg!(windows) {
        "pactmesh-core.exe"
    } else {
        "pactmesh-core"
    };
    let core = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("failed to locate pactmesh binary directory"))?
        .join(name);
    if !core.is_file() {
        anyhow::bail!(
            "pactmesh-core not found next to {}: {}",
            exe.display(),
            core.display()
        );
    }
    Ok(core)
}

fn resolve_quickstart_device_passphrase(file: Option<&PathBuf>) -> Result<String, Error> {
    if let Some(passphrase) = read_optional_device_passphrase(file)? {
        return Ok(passphrase);
    }
    if std::io::stdin().is_terminal() {
        let first = prompt_line("Device key passphrase: ")?;
        let second = prompt_line("Confirm device key passphrase: ")?;
        if first != second {
            anyhow::bail!("device key passphrase confirmation does not match");
        }
        if first.len() < 8 {
            anyhow::bail!("device key passphrase must be at least 8 characters");
        }
        return Ok(first);
    }
    anyhow::bail!(
        "PNW_DEVICE_PASSPHRASE is required unless --device-passphrase-file is provided; interactive prompt is only available on a TTY"
    )
}

fn spawn_quickstart_daemon(
    core: &std::path::Path,
    log_path: &std::path::Path,
    args: &[&str],
    device_passphrase: Option<&str>,
) -> Result<std::process::Child, Error> {
    let stdout = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .with_context(|| format!("failed to open {}", log_path.display()))?;
    let stderr = stdout.try_clone()?;
    let mut command = std::process::Command::new(core);
    command.args(args);
    if let Some(passphrase) = device_passphrase {
        command.env("PNW_DEVICE_PASSPHRASE", passphrase);
    }
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(stdout))
        .stderr(std::process::Stdio::from(stderr))
        .spawn()
        .with_context(|| format!("failed to start {}", core.display()))
}

fn quickstart_json_field(text: &str, field: &str) -> Result<String, Error> {
    let value: serde_json::Value = serde_json::from_str(text)
        .with_context(|| format!("failed to parse JSON output: {text}"))?;
    value
        .get(field)
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("missing JSON string field '{field}' in: {text}"))
}

#[derive(Args, Debug)]
struct PeerArgs {
    #[command(subcommand)]
    sub_command: Option<PeerSubCommand>,
}

#[derive(Subcommand, Debug)]
enum PeerSubCommand {
    List,
    ListForeign {
        #[arg(
            long,
            default_value = "false",
            help = "include trusted keys for each foreign network"
        )]
        trusted_keys: bool,
    },
    ListGlobalForeign,
}

#[derive(Args, Debug)]
struct RouteArgs {
    #[command(subcommand)]
    sub_command: Option<RouteSubCommand>,
}

#[derive(Subcommand, Debug)]
enum RouteSubCommand {
    List,
    Dump,
}

#[derive(Args, Debug)]
struct ConnectorArgs {
    #[arg(short, long)]
    ipv4: Option<String>,

    #[arg(short, long)]
    peers: Vec<String>,

    #[command(subcommand)]
    sub_command: Option<ConnectorSubCommand>,
}

#[derive(Subcommand, Debug)]
enum ConnectorSubCommand {
    /// Add a connector
    Add {
        #[arg(help = "connector url, e.g., tcp://1.2.3.4:11010")]
        url: String,
    },
    /// Remove a connector
    Remove {
        #[arg(help = "connector url, e.g., tcp://1.2.3.4:11010")]
        url: String,
    },
    List,
}

#[derive(Args, Debug)]
struct MappedListenerArgs {
    #[command(subcommand)]
    sub_command: Option<MappedListenerSubCommand>,
}

#[derive(Subcommand, Debug)]
enum MappedListenerSubCommand {
    /// Add Mapped Listerner
    Add { url: String },
    /// Remove Mapped Listener
    Remove { url: String },
    /// List Existing Mapped Listener
    List,
}

#[derive(Subcommand, Debug)]
enum NodeSubCommand {
    #[command(about = "show node info")]
    Info,
    #[command(about = "show node config")]
    Config,
}

#[derive(Args, Debug)]
struct NodeArgs {
    #[command(subcommand)]
    sub_command: Option<NodeSubCommand>,
}

#[derive(Args, Debug)]
struct AclArgs {
    #[command(subcommand)]
    sub_command: Option<AclSubCommand>,
}

#[derive(Subcommand, Debug)]
enum AclSubCommand {
    Stats,
}

#[derive(Args, Debug)]
struct PortForwardArgs {
    #[command(subcommand)]
    sub_command: Option<PortForwardSubCommand>,
}

#[derive(Subcommand, Debug)]
enum PortForwardSubCommand {
    /// Add port forward rule
    Add {
        #[arg(help = "Protocol (tcp/udp)")]
        protocol: String,
        #[arg(help = "Local bind address (e.g., 0.0.0.0:8080)")]
        bind_addr: String,
        #[arg(help = "Destination address (e.g., 10.1.1.1:80)")]
        dst_addr: String,
    },
    /// Remove port forward rule
    Remove {
        #[arg(help = "Protocol (tcp/udp)")]
        protocol: String,
        #[arg(help = "Local bind address (e.g., 0.0.0.0:8080)")]
        bind_addr: String,
        #[arg(help = "Optional Destination address (e.g., 10.1.1.1:80)")]
        dst_addr: Option<String>,
    },
    /// List port forward rules
    List,
}

#[derive(Args, Debug)]
struct WhitelistArgs {
    #[command(subcommand)]
    sub_command: Option<WhitelistSubCommand>,
}

#[derive(Subcommand, Debug)]
enum WhitelistSubCommand {
    /// Set TCP port whitelist
    SetTcp {
        #[arg(help = "TCP ports (e.g., 80,443,8000-9000)")]
        ports: String,
    },
    /// Set UDP port whitelist
    SetUdp {
        #[arg(help = "UDP ports (e.g., 53,5000-6000)")]
        ports: String,
    },
    /// Clear TCP whitelist
    ClearTcp,
    /// Clear UDP whitelist
    ClearUdp,
    /// Show current whitelist configuration
    Show,
}

#[derive(Args, Debug)]
struct StatsArgs {
    #[command(subcommand)]
    sub_command: Option<StatsSubCommand>,
}

#[derive(Subcommand, Debug)]
enum StatsSubCommand {
    /// Show general statistics
    Show,
    /// Show statistics in Prometheus format
    Prometheus,
}

#[derive(Args, Debug)]
struct LoggerArgs {
    #[command(subcommand)]
    sub_command: Option<LoggerSubCommand>,
}

#[derive(Subcommand, Debug)]
enum LoggerSubCommand {
    /// Get current logger configuration
    Get,
    /// Set logger level
    Set {
        #[arg(help = "Log level (disabled, error, warning, info, debug, trace)")]
        level: String,
    },
}

#[derive(Args, Debug)]
struct CredentialArgs {
    #[command(subcommand)]
    sub_command: CredentialSubCommand,
}

#[derive(Subcommand, Debug)]
enum CredentialSubCommand {
    /// Generate a new temporary credential
    Generate {
        #[arg(long, help = "TTL in seconds (required)")]
        ttl: i64,
        #[arg(
            long,
            help = "custom credential ID, return existing credential if already generated"
        )]
        credential_id: Option<String>,
        #[arg(long, value_delimiter = ',', help = "ACL groups (comma-separated)")]
        groups: Option<Vec<String>>,
        #[arg(
            long,
            default_value = "false",
            help = "allow relay through this credential node"
        )]
        allow_relay: bool,
        #[arg(
            long,
            value_delimiter = ',',
            help = "allowed proxy CIDRs (comma-separated)"
        )]
        allowed_proxy_cidrs: Option<Vec<String>>,
        #[arg(
            long,
            action = ArgAction::Set,
            default_value = "true",
            value_parser = BoolishValueParser::new(),
            help = "whether this credential may be reused by multiple peers concurrently"
        )]
        reusable: bool,
    },
    /// Revoke a credential by its ID
    Revoke {
        #[arg(help = "credential ID (UUID)")]
        credential_id: String,
    },
    /// List all active credentials
    List,
}

#[derive(Args, Debug)]
struct BootstrapArgs {
    #[command(subcommand)]
    sub_command: BootstrapSubCommand,
}

#[derive(Args, Debug)]
struct LabArgs {
    #[command(subcommand)]
    sub_command: Option<LabSubCommand>,
}

#[derive(Subcommand, Debug)]
enum LabSubCommand {
    #[command(about = "deprecated command generator for manual tests")]
    Wizard,
    #[command(about = "check local test environment and key files")]
    Doctor {
        #[arg(long, default_value = "office-net", help = "network-local id")]
        network_local_id: String,
        #[arg(long, help = "trust-domain id; auto-detected when omitted")]
        trust_domain_id: Option<String>,
    },
    #[command(about = "summarize local files, daemon RPC, peers, and recent logs")]
    Status {
        #[arg(long, default_value = "office-net", help = "network-local id")]
        network_local_id: String,
        #[arg(long, help = "trust-domain id; auto-detected when omitted")]
        trust_domain_id: Option<String>,
        #[arg(long, help = "daemon log file to scan")]
        log: Option<PathBuf>,
    },
    #[command(about = "run no-TTY fallback test steps")]
    Run {
        #[command(subcommand)]
        command: LabRunSubCommand,
    },
    #[command(about = "fallback approval command; prefer TUI Joins tab")]
    Approve {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(long, help = "approve this pending device id prefix without prompting")]
        device: Option<String>,
        #[arg(long, help = "emit machine-readable JSON from approve")]
        json: bool,
        #[arg(
            long,
            help = "file containing the root key passphrase (management password)"
        )]
        passphrase_file: Option<PathBuf>,
    },
    #[command(about = "explain peer route status and likely test issues")]
    Peers {
        #[command(subcommand)]
        command: LabPeersSubCommand,
    },
    #[command(about = "SSH preflight for remote A/B/C test automation")]
    RemoteCheck {
        #[arg(long = "host", required = true, help = "SSH host alias or user@host")]
        hosts: Vec<String>,
        #[arg(
            long,
            help = "directory containing pactmesh binaries on the remote host"
        )]
        bin_dir: Option<String>,
    },

    #[command(
        about = "run an SSH-driven three-node no-TUN regression test using existing trust files"
    )]
    RemoteRun {
        #[arg(long, help = "SSH host for the public/root A node")]
        a_host: String,
        #[arg(long, help = "SSH host for the Windows/Linux C node")]
        c_host: String,
        #[arg(
            long,
            help = "trust-domain id used by existing test files",
            allow_hyphen_values = true
        )]
        trust_domain_id: String,
        #[arg(long, default_value = "office-net", help = "network-local id")]
        network_local_id: String,
        #[arg(
            long,
            env = "PACTMESH_LAB_SEED",
            default_value = "tcp://127.0.0.1:11010",
            help = "seed URL used by B/C"
        )]
        seed: String,
        #[arg(
            long,
            default_value = "target/release",
            help = "local Linux release dir containing pactmesh and pactmesh-core"
        )]
        linux_bin_dir: PathBuf,
        #[arg(
            long,
            help = "local Windows artifact dir containing pactmesh.exe and pactmesh-core.exe"
        )]
        windows_bin_dir: Option<PathBuf>,
        #[arg(
            long,
            default_value = "/root/pactmesh-test-34addb4/bin",
            help = "remote A bin dir"
        )]
        a_bin_dir: String,
        #[arg(
            long,
            default_value = "/tmp/pactmesh-test-34addb4/bin",
            help = "local B bin dir"
        )]
        b_bin_dir: String,
        #[arg(
            long,
            default_value = "M:\\workarea\\testPactMesh\\bin",
            help = "remote C bin dir"
        )]
        c_bin_dir: String,
        #[arg(
            long,
            default_value = "/root/pactmesh-test-34addb4/run/xdg",
            help = "remote A XDG_CONFIG_HOME"
        )]
        a_xdg: String,
        #[arg(
            long,
            default_value = "/tmp/pactmesh-test-34addb4/run-b/xdg",
            help = "local B XDG_CONFIG_HOME"
        )]
        b_xdg: String,
        #[arg(
            long,
            default_value = "D:\\pactmesh-test-e8b014c\\xdg",
            help = "remote C XDG_CONFIG_HOME"
        )]
        c_xdg: String,
        #[arg(
            long,
            default_value = "/root/pactmesh-test-34addb4/run/logs/root-a.log",
            help = "remote A log path"
        )]
        a_log: String,
        #[arg(
            long,
            default_value = "/tmp/pactmesh-test-34addb4/run-b/logs/node-b.log",
            help = "local B log path"
        )]
        b_log: String,
        #[arg(
            long,
            default_value = "D:\\pactmesh-test-e8b014c\\win-c.log",
            help = "remote C log path"
        )]
        c_log: String,
        #[arg(long, default_value = "15889", help = "A RPC port")]
        a_rpc: u16,
        #[arg(long, default_value = "15890", help = "B RPC port")]
        b_rpc: u16,
        #[arg(long, default_value = "15891", help = "C RPC port")]
        c_rpc: u16,
        #[arg(long, default_value = "11010", help = "A listener port")]
        a_listen: u16,
        #[arg(long, default_value = "11020", help = "B listener port")]
        b_listen: u16,
        #[arg(long, default_value = "11020", help = "C listener port")]
        c_listen: u16,
        #[arg(
            long,
            default_value = "600",
            help = "seconds to wait before collecting results"
        )]
        wait_secs: u64,
        #[arg(
            long,
            default_value = "20",
            help = "seconds between peer checks while waiting for B/C direct"
        )]
        poll_secs: u64,
        #[arg(long, default_value = "false", help = "skip binary upload/copy")]
        no_deploy: bool,
        #[arg(
            long,
            default_value = "false",
            help = "leave daemons running after collection"
        )]
        keep_running: bool,
        #[arg(
            long,
            default_value = "LAPTOP",
            help = "hostname substring B should see for C"
        )]
        b_expect_peer: String,
        #[arg(
            long,
            default_value = "user",
            help = "hostname substring C should see for B"
        )]
        c_expect_peer: String,
    },
    #[command(about = "run an SSH-driven three-node no-TUN test from a fresh trust domain")]
    RemoteFreshRun {
        #[arg(long, help = "SSH host for the public/root A node")]
        a_host: String,
        #[arg(long, help = "SSH host for the Windows/Linux C node")]
        c_host: String,
        #[arg(long, default_value = "office-net", help = "network-local id")]
        network_local_id: String,
        #[arg(long, default_value = "remote-fresh", help = "trust-domain label")]
        domain_label: String,
        #[arg(
            long,
            default_value = "pactmesh-lab-root-pass",
            help = "temporary root management passphrase for this fresh lab"
        )]
        root_passphrase: String,
        #[arg(
            long,
            env = "PACTMESH_LAB_SEED",
            default_value = "tcp://127.0.0.1:11010",
            help = "public seed URL exported into the invite"
        )]
        seed: String,
        #[arg(
            long,
            default_value = "target/release",
            help = "local Linux release dir containing pactmesh and pactmesh-core"
        )]
        linux_bin_dir: PathBuf,
        #[arg(
            long,
            help = "local Windows artifact dir containing pactmesh.exe and pactmesh-core.exe"
        )]
        windows_bin_dir: Option<PathBuf>,
        #[arg(
            long,
            default_value = "/root/pactmesh-fresh-test/bin",
            help = "remote A bin dir"
        )]
        a_bin_dir: String,
        #[arg(
            long,
            default_value = "/tmp/pactmesh-fresh-test/bin",
            help = "local B bin dir"
        )]
        b_bin_dir: String,
        #[arg(
            long,
            default_value = "M:\\workarea\\testPactMesh\\bin",
            help = "remote C bin dir"
        )]
        c_bin_dir: String,
        #[arg(
            long,
            default_value = "/root/pactmesh-fresh-test/xdg",
            help = "remote A XDG_CONFIG_HOME"
        )]
        a_xdg: String,
        #[arg(
            long,
            default_value = "/tmp/pactmesh-fresh-test/xdg",
            help = "local B XDG_CONFIG_HOME"
        )]
        b_xdg: String,
        #[arg(
            long,
            default_value = "M:\\workarea\\testPactMesh\\xdg",
            help = "remote C XDG_CONFIG_HOME"
        )]
        c_xdg: String,
        #[arg(
            long,
            default_value = "/root/pactmesh-fresh-test/logs/root-a.log",
            help = "remote A log path"
        )]
        a_log: String,
        #[arg(
            long,
            default_value = "/tmp/pactmesh-fresh-test/logs/node-b.log",
            help = "local B log path"
        )]
        b_log: String,
        #[arg(
            long,
            default_value = "M:\\workarea\\testPactMesh\\logs\\win-c.log",
            help = "remote C log path"
        )]
        c_log: String,
        #[arg(long, default_value = "15889", help = "A RPC port")]
        a_rpc: u16,
        #[arg(long, default_value = "15890", help = "B RPC port")]
        b_rpc: u16,
        #[arg(long, default_value = "15891", help = "C RPC port")]
        c_rpc: u16,
        #[arg(long, default_value = "11010", help = "A listener port")]
        a_listen: u16,
        #[arg(long, default_value = "11020", help = "B listener port")]
        b_listen: u16,
        #[arg(long, default_value = "11020", help = "C listener port")]
        c_listen: u16,
        #[arg(long, default_value_t = 180, help = "join approval timeout in seconds")]
        join_wait_secs: u64,
        #[arg(
            long,
            default_value_t = 10,
            help = "join approval poll interval in seconds"
        )]
        poll_secs: u64,
        #[arg(
            long,
            default_value_t = 600,
            help = "seconds to wait for peers/config propagation or direct route"
        )]
        wait_secs: u64,
        #[arg(long, default_value = "false", help = "skip binary upload/copy")]
        no_deploy: bool,
        #[arg(
            long,
            default_value = "false",
            help = "leave daemons running after collection"
        )]
        keep_running: bool,
        #[arg(
            long,
            default_value = "false",
            help = "fail if B and C do not report a direct/p2p route"
        )]
        require_bc_direct: bool,
        #[arg(
            long,
            default_value = "",
            help = "pin C punch/connector sockets to this physical NIC (adds --bind-device/--bind-device-public/--bind-device-name); empty keeps default behavior"
        )]
        c_bind_device_name: String,
        #[arg(
            long,
            default_value = "10.18.0.0/16",
            help = "comma-separated overlay CIDRs; with --require-bc-direct, also require a direct conn whose remote_addr is outside these (guards against overlay fake-direct). Empty disables the check"
        )]
        overlay_cidr: String,
    },
    #[command(about = "disable a member interactively")]
    Disable {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(long, help = "device id/fingerprint prefix; prompts when omitted")]
        device: Option<String>,
        #[arg(long, help = "RFC3339 timestamp when disable should expire")]
        until: Option<String>,
        #[arg(long, help = "disable note")]
        note: Option<String>,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
        #[arg(
            long,
            help = "file containing the root key passphrase (management password)"
        )]
        passphrase_file: Option<PathBuf>,
    },
    #[command(about = "enable a disabled member interactively")]
    Enable {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(long, help = "device id/fingerprint prefix; prompts when omitted")]
        device: Option<String>,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
        #[arg(
            long,
            help = "file containing the root key passphrase (management password)"
        )]
        passphrase_file: Option<PathBuf>,
    },
    #[command(about = "print ready-to-run commands for a test role")]
    Commands {
        #[arg(long, value_enum, help = "node role to generate commands for")]
        role: LabRole,
        #[arg(long, default_value = "office-net", help = "network-local id")]
        network_local_id: String,
        #[arg(long, default_value = "11010", help = "listener port")]
        listen_port: u16,
        #[arg(long, default_value = "15888", help = "local RPC portal port")]
        rpc_port: u16,
        #[arg(
            long,
            default_value = "pactmesh-test",
            help = "PNW_TEST_HOME directory name"
        )]
        test_home_name: String,
        #[arg(long, help = "public seed URL, e.g. tcp://1.2.3.4:11010")]
        seed: Option<String>,
        #[arg(long, default_value = "node", help = "device/instance label")]
        label: String,
        #[arg(long, help = "invite URL for joiner role")]
        invite: Option<String>,
        #[arg(long, help = "trust-domain id for root role")]
        trust_domain_id: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum LabRunSubCommand {
    #[command(about = "print or execute a daemon command with preflight checks")]
    Daemon {
        #[arg(long, default_value = "joiner", value_enum, help = "node role")]
        role: LabRole,
        #[arg(long, default_value = "office-net", help = "network-local id")]
        network_local_id: String,
        #[arg(long, default_value = "11010", help = "listener port")]
        listen_port: u16,
        #[arg(long, default_value = "15889", help = "local RPC portal port")]
        rpc_port: u16,
        #[arg(long, default_value = "node", help = "instance label")]
        label: String,
        #[arg(
            long,
            help = "trust-domain id; required for root role when printing --trust-domain-dir"
        )]
        trust_domain_id: Option<String>,
        #[arg(
            long,
            help = "execute pactmesh-core in foreground instead of only printing"
        )]
        exec: bool,
    },
    #[command(about = "accept an invite, check files, and print daemon start command")]
    Joiner {
        #[arg(help = "invite URL or bootstrap PEM path")]
        invite: String,
        #[arg(long, default_value = "node", help = "device/instance label")]
        label: String,
        #[arg(
            long,
            default_value = "office-net",
            help = "network-local id for checks and commands"
        )]
        network_local_id: String,
        #[arg(
            long,
            default_value = "11010",
            help = "listener port for generated daemon command"
        )]
        listen_port: u16,
        #[arg(
            long,
            default_value = "15889",
            help = "local RPC portal port for generated daemon command"
        )]
        rpc_port: u16,
        #[arg(
            long,
            default_value_t = 600,
            help = "online approval timeout in seconds"
        )]
        wait_secs: u64,
        #[arg(
            long,
            default_value_t = 2,
            help = "online approval poll interval in seconds"
        )]
        poll_secs: u64,
        #[arg(long, default_value = "", help = "operator-visible join hint")]
        hint: String,
        #[arg(long, help = "file containing the device key passphrase")]
        passphrase_file: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum LabPeersSubCommand {
    #[command(about = "explain current peer routes")]
    Explain,
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq)]
enum LabRole {
    Root,
    Joiner,
}

#[derive(Args, Debug)]
struct TrustArgs {
    #[command(subcommand)]
    sub_command: TrustSubCommand,
}

#[derive(Subcommand, Debug)]
enum TrustSubCommand {
    CreateDomain {
        #[arg(long, help = "human-readable trust-domain label")]
        label: String,
        #[arg(long, help = "parent output directory")]
        out_dir: Option<PathBuf>,
        #[arg(long, default_value = "ed25519", help = "root key curve")]
        curve: String,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
        #[arg(
            long,
            help = "file containing the root key passphrase (management password)"
        )]
        passphrase_file: Option<PathBuf>,
    },
    ListDomains {
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
    },
    CreateNetwork {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(
            long,
            default_value = "accept",
            help = "default ACL action: accept or drop"
        )]
        default_action: String,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
        #[arg(
            long,
            help = "file containing the root key passphrase (management password)"
        )]
        passphrase_file: Option<PathBuf>,
    },
    BootstrapSelf {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(long, help = "device label for the local root member")]
        device_label: Option<String>,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
        #[arg(
            long,
            help = "file containing the root key passphrase (management password)"
        )]
        passphrase_file: Option<PathBuf>,
        #[arg(long, help = "file containing the device key passphrase")]
        device_passphrase_file: Option<PathBuf>,
    },
    Invite {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(long = "seed", help = "bootstrap peer URL", action = ArgAction::Append)]
        seeds: Vec<Url>,
        #[arg(long, value_enum, default_value = "url", help = "output format")]
        format: BootstrapFormat,
        #[arg(long, help = "write file/qr output to path")]
        out: Option<PathBuf>,
    },
    AcceptInvite {
        #[arg(help = "bootstrap URL or PEM file path")]
        source: String,
        #[arg(long, help = "device label for join request")]
        device_label: Option<String>,
        #[arg(long, default_value = "", help = "operator-visible join hint")]
        hint: String,
        #[arg(long, help = "file containing the device key passphrase")]
        passphrase_file: Option<PathBuf>,
        #[arg(
            long,
            help = "deprecated: online submission is the default now; kept for compatibility"
        )]
        online: bool,
        #[arg(
            long,
            help = "write the join request to disk only, skip daemon submission (air-gapped/manual approval)"
        )]
        offline: bool,
        #[arg(
            long,
            default_value_t = 3600,
            help = "online approval timeout in seconds"
        )]
        wait_secs: u64,
        #[arg(
            long,
            default_value_t = 30,
            help = "online approval poll interval in seconds"
        )]
        poll_secs: u64,
    },
    Revoke {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(help = "member-cert fingerprint", allow_hyphen_values = true)]
        fingerprint: String,
        #[arg(
            long,
            value_enum,
            default_value = "unspecified",
            help = "revocation reason"
        )]
        reason: RevokeReasonArg,
        #[arg(long, help = "revocation note")]
        note: Option<String>,
        #[arg(
            long,
            help = "file containing the root key passphrase (management password)"
        )]
        passphrase_file: Option<PathBuf>,
    },
    Disable {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(help = "member-cert fingerprint", allow_hyphen_values = true)]
        fingerprint: String,
        #[arg(long, help = "RFC3339 timestamp when disable should expire")]
        until: Option<String>,
        #[arg(long, help = "disable note")]
        note: Option<String>,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
        #[arg(
            long,
            help = "file containing the root key passphrase (management password)"
        )]
        passphrase_file: Option<PathBuf>,
    },
    Enable {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(help = "member-cert fingerprint", allow_hyphen_values = true)]
        fingerprint: String,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
        #[arg(
            long,
            help = "file containing the root key passphrase (management password)"
        )]
        passphrase_file: Option<PathBuf>,
    },
    #[command(
        about = "assign or clear a member's fixed virtual IPv4 (root-signed network_state; no cert reissue)"
    )]
    AssignedIpv4 {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(help = "member-cert fingerprint", allow_hyphen_values = true)]
        fingerprint: String,
        #[arg(
            long,
            help = "CIDR to assign (e.g. 10.0.0.7/24); omit or pass --clear to remove"
        )]
        ipv4: Option<String>,
        #[arg(long, help = "clear the assignment, reverting the device to DHCP/static")]
        clear: bool,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
        #[arg(
            long,
            help = "file containing the root key passphrase (management password)"
        )]
        passphrase_file: Option<PathBuf>,
    },
    ListMembers {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(
            long,
            value_enum,
            default_value = "active",
            help = "member status filter"
        )]
        include: MemberIncludeArg,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
    },
    ListExternal {
        #[arg(long, help = "pactmesh-core TOML config file to inspect")]
        config: PathBuf,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
        #[arg(long, help = "show runtime enforcement notes for each capability")]
        explain: bool,
    },
    ShowDevice {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(help = "device id or unique prefix", allow_hyphen_values = true)]
        device_id: String,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
    },
    RenameDevice {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(help = "device id or unique prefix", allow_hyphen_values = true)]
        device_id: String,
        #[arg(long, help = "new human-readable device label")]
        label: String,
        #[arg(long, help = "audit note for superseding old cert")]
        note: Option<String>,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
        #[arg(
            long,
            help = "file containing the root key passphrase (management password)"
        )]
        passphrase_file: Option<PathBuf>,
    },
    Capability {
        #[command(subcommand)]
        command: TrustCapabilitySubCommand,
    },
    Tag {
        #[command(subcommand)]
        command: TrustTagSubCommand,
    },
    PeerHint {
        #[command(subcommand)]
        command: TrustPeerHintSubCommand,
    },
    Acl {
        #[command(subcommand)]
        command: TrustAclSubCommand,
    },
    SetHostname {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(help = "member-cert fingerprint", allow_hyphen_values = true)]
        fingerprint: String,
        #[arg(help = "DNS hostname label")]
        hostname: String,
        #[arg(long, help = "audit note for superseding old cert")]
        note: Option<String>,
        #[arg(
            long,
            help = "file containing the root key passphrase (management password)"
        )]
        passphrase_file: Option<PathBuf>,
    },
    UnsetHostname {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(help = "member-cert fingerprint", allow_hyphen_values = true)]
        fingerprint: String,
        #[arg(
            long,
            help = "file containing the root key passphrase (management password)"
        )]
        passphrase_file: Option<PathBuf>,
    },
    Approve {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(
            value_name = "DEVICE_ID",
            help = "pending device id or unique prefix from 'trust list-pending'",
            allow_hyphen_values = true
        )]
        applicant_pk: String,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
        #[arg(
            long,
            help = "file containing the root key passphrase (management password)"
        )]
        passphrase_file: Option<PathBuf>,
    },
    Reject {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(
            value_name = "DEVICE_ID",
            help = "pending device id or unique prefix from 'trust list-pending'",
            allow_hyphen_values = true
        )]
        applicant_pk: String,
    },
    UpgradePeerToRoot {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(help = "target peer id shown by peer list")]
        peer_id: u32,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
        #[arg(
            long,
            help = "file containing the root key passphrase (management password)"
        )]
        passphrase_file: Option<PathBuf>,
    },
    ListPending {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(long, help = "filter by network-local id")]
        network_local_id: Option<String>,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum TrustCapabilitySubCommand {
    Set {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(help = "member-cert fingerprint", allow_hyphen_values = true)]
        fingerprint: String,
        #[arg(long, help = "set can_relay_data")]
        relay_data: Option<bool>,
        #[arg(long, help = "set can_relay_control")]
        relay_control: Option<bool>,
        #[arg(long = "proxy-subnet", action = ArgAction::Append, help = "replace can_proxy_subnet with this CIDR; repeatable")]
        proxy_subnet: Vec<IpNet>,
        #[arg(long, help = "clear all proxy-subnet capabilities")]
        clear_proxy_subnet: bool,
        #[arg(long, help = "audit note for superseding old cert")]
        note: Option<String>,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
        #[arg(
            long,
            help = "file containing the root key passphrase (management password)"
        )]
        passphrase_file: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum TrustTagSubCommand {
    List {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
    },
    Add {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(help = "device id or unique prefix", allow_hyphen_values = true)]
        device_id: String,
        #[arg(help = "tag name")]
        tag: String,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
        #[arg(
            long,
            help = "file containing the root key passphrase (management password)"
        )]
        passphrase_file: Option<PathBuf>,
    },
    Remove {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(help = "device id or unique prefix", allow_hyphen_values = true)]
        device_id: String,
        #[arg(help = "tag name")]
        tag: String,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
        #[arg(
            long,
            help = "file containing the root key passphrase (management password)"
        )]
        passphrase_file: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum TrustPeerHintSubCommand {
    List {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
    },
    Add {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(help = "peer hint URL")]
        url: Url,
        #[arg(long, help = "human-readable hint label")]
        label: Option<String>,
        #[arg(long = "capability", action = ArgAction::Append, help = "hint capability tag")]
        capabilities: Vec<String>,
        #[arg(long, help = "unix timestamp when this hint expires")]
        expires_at: Option<u64>,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
        #[arg(
            long,
            help = "file containing the root key passphrase (management password)"
        )]
        passphrase_file: Option<PathBuf>,
    },
    Remove {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(help = "peer hint URL")]
        url: Url,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
        #[arg(
            long,
            help = "file containing the root key passphrase (management password)"
        )]
        passphrase_file: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum TrustAclSubCommand {
    Explain {
        #[arg(help = "trust-domain id", allow_hyphen_values = true)]
        trust_domain_id: String,
        #[arg(help = "network-local id")]
        network_local_id: String,
        #[arg(help = "source device id or unique prefix", allow_hyphen_values = true)]
        src_device_id: String,
        #[arg(
            help = "destination device id or unique prefix",
            allow_hyphen_values = true
        )]
        dst_device_id: String,
        #[arg(long, default_value = "tcp", help = "protocol: tcp, udp, icmp, or any")]
        proto: String,
        #[arg(long, help = "destination port for tcp/udp explanations")]
        port: Option<u16>,
        #[arg(long, default_value = "100.64.0.1", help = "source packet IP")]
        src_ip: IpAddr,
        #[arg(long, default_value = "100.64.0.2", help = "destination packet IP")]
        dst_ip: IpAddr,
        #[arg(long, help = "emit machine-readable JSON")]
        json: bool,
    },
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum BootstrapFormat {
    Url,
    File,
    Qr,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum RevokeReasonArg {
    KeyCompromise,
    DeviceLost,
    Removed,
    Superseded,
    Unspecified,
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq)]
enum MemberIncludeArg {
    Active,
    Disabled,
    Revoked,
    Expired,
    All,
}

#[derive(Subcommand, Debug)]
enum BootstrapSubCommand {
    Export {
        #[arg(long, help = "trust-domain directory containing pk_root.pem")]
        domain_dir: PathBuf,
        #[arg(long, help = "network local id")]
        network_local_id: String,
        #[arg(long, value_enum, default_value = "url", help = "output format")]
        format: BootstrapFormat,
        #[arg(long, help = "write output to file instead of stdout")]
        out: Option<PathBuf>,
        #[arg(long = "bootstrap-seed", help = "invite peer hint URL (legacy option name)", action = ArgAction::Append)]
        bootstrap_seeds: Vec<Url>,
        #[arg(long, help = "optional trust-domain label")]
        trust_domain_label: Option<String>,
        #[arg(long, help = "optional user-facing network name")]
        network_name: Option<String>,
        #[arg(long, help = "optional free-form description")]
        description: Option<String>,
    },
    Import {
        #[arg(long, help = "destination trust-domain directory")]
        domain_dir: PathBuf,
        #[arg(help = "bootstrap URL or PEM file path")]
        source: String,
    },
}

#[derive(Args, Debug)]
struct ServiceArgs {
    #[arg(short, long, default_value = env!("CARGO_PKG_NAME"), help = "service name")]
    name: String,

    #[command(subcommand)]
    sub_command: ServiceSubCommand,
}

#[derive(Subcommand, Debug)]
enum ServiceSubCommand {
    #[command(about = "register pactmesh-core as a system service")]
    Install(InstallArgs),
    #[command(about = "unregister pactmesh-core system service")]
    Uninstall,
    #[command(about = "check pactmesh-core system service status")]
    Status,
    #[command(about = "start pactmesh-core system service")]
    Start,
    #[command(about = "stop pactmesh-core system service")]
    Stop,
    #[command(about = "restart pactmesh-core system service")]
    Restart,
}

#[derive(Args, Debug)]
struct InstallArgs {
    #[arg(long, default_value = env!("CARGO_PKG_DESCRIPTION"), help = "service description")]
    description: String,

    #[arg(long)]
    display_name: Option<String>,

    #[arg(long)]
    disable_autostart: Option<bool>,

    #[arg(long)]
    disable_restart_on_failure: Option<bool>,

    #[arg(long, help = "path to pactmesh-core binary")]
    core_path: Option<PathBuf>,

    #[arg(
        long,
        help = "register `pactmesh serve run` (daemon + web console, self-unsealing) instead of bare pactmesh-core"
    )]
    serve: bool,

    #[arg(long)]
    service_work_dir: Option<PathBuf>,

    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        help = "args to pass to pactmesh-core"
    )]
    core_args: Option<Vec<OsString>>,
}

type Error = anyhow::Error;

#[derive(Clone, Debug)]
struct InstanceTarget {
    identifier: InstanceIdentifier,
    instance_id: String,
    instance_name: String,
}

struct InstanceResult<T> {
    target: Option<InstanceTarget>,
    value: T,
}

impl InstanceTarget {
    fn label(&self) -> String {
        match (self.instance_name.is_empty(), self.instance_id.is_empty()) {
            (false, false) => format!("{} ({})", self.instance_name, self.instance_id),
            (false, true) => self.instance_name.clone(),
            (true, false) => self.instance_id.clone(),
            (true, true) => "selected instance".to_string(),
        }
    }
}

impl<T> InstanceResult<T> {
    fn new(target: Option<InstanceTarget>, value: T) -> Self {
        Self { target, value }
    }

    fn map<U>(self, f: impl FnOnce(T) -> U) -> InstanceResult<U> {
        InstanceResult {
            target: self.target,
            value: f(self.value),
        }
    }
}

struct CommandHandler<'a> {
    client: Arc<tokio::sync::Mutex<RpcClient>>,
    verbose: bool,
    output_format: &'a OutputFormat,
    no_trunc: bool,
    instance_select: &'a InstanceSelectArgs,
    instance_selector: InstanceIdentifier,
    resolved_target: Option<InstanceTarget>,
}

type RpcClient = StandAloneClient<TcpTunnelConnector>;
type LocalBoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, Error>> + 'a>>;
type ForeignNetworkMap = BTreeMap<String, ForeignNetworkEntryPb>;
type GlobalForeignNetworkMap = BTreeMap<u32, list_global_foreign_network_response::ForeignNetworks>;

#[derive(serde::Serialize)]
struct PeerListData {
    node_info: NodeInfo,
    peer_routes: Vec<PeerRoutePair>,
}

#[derive(serde::Serialize)]
struct RouteListData {
    node_info: NodeInfo,
    peer_routes: Vec<PeerRoutePair>,
}

impl<'a> CommandHandler<'a> {
    fn has_explicit_instance_selector(&self) -> bool {
        self.instance_select.id.is_some() || self.instance_select.name.is_some()
    }

    fn scoped_to_instance(&self, target: &InstanceTarget) -> Self {
        Self {
            client: self.client.clone(),
            verbose: self.verbose,
            output_format: self.output_format,
            no_trunc: self.no_trunc,
            instance_select: self.instance_select,
            instance_selector: target.identifier.clone(),
            resolved_target: Some(target.clone()),
        }
    }

    fn print_target_header(&self, target: &InstanceTarget) {
        println!("== {} ==", target.label());
    }

    async fn get_manage_client(
        &self,
    ) -> Result<Box<dyn WebClientService<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<WebClientServiceClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get manage client")?)
    }

    async fn fanout_targets(&self) -> Result<Option<Vec<InstanceTarget>>, Error> {
        if self.resolved_target.is_some() || self.has_explicit_instance_selector() {
            return Ok(None);
        }

        let client = self.get_manage_client().await?;
        let inst_ids = client
            .list_network_instance(BaseController::default(), ListNetworkInstanceRequest {})
            .await?
            .inst_ids
            .into_iter()
            .map(uuid::Uuid::from)
            .collect::<Vec<_>>();

        if inst_ids.is_empty() {
            return Err(anyhow::anyhow!("no running instances found"));
        }

        let metas = client
            .list_network_instance_meta(
                BaseController::default(),
                ListNetworkInstanceMetaRequest {
                    inst_ids: inst_ids.iter().cloned().map(Into::into).collect(),
                },
            )
            .await?
            .metas;

        let mut name_map = HashMap::new();
        for meta in metas {
            if let Some(inst_id) = meta.inst_id {
                name_map.insert(
                    uuid::Uuid::from(inst_id),
                    if meta.instance_name.is_empty() {
                        meta.network_name
                    } else {
                        meta.instance_name
                    },
                );
            }
        }

        let mut targets = inst_ids
            .into_iter()
            .map(|inst_id| InstanceTarget {
                identifier: InstanceIdentifier {
                    selector: Some(Selector::Id(inst_id.into())),
                },
                instance_id: inst_id.to_string(),
                instance_name: name_map.remove(&inst_id).unwrap_or_default(),
            })
            .collect::<Vec<_>>();

        targets.sort_by_key(|a| a.label());
        Ok(Some(targets))
    }

    async fn collect_instance_results<T, F>(
        &self,
        fetch: F,
    ) -> Result<Vec<InstanceResult<T>>, Error>
    where
        F: for<'b> Fn(&'b CommandHandler<'a>) -> LocalBoxFuture<'b, T>,
    {
        if let Some(targets) = self.fanout_targets().await? {
            let mut results = Vec::with_capacity(targets.len());
            for target in targets {
                let scoped = self.scoped_to_instance(&target);
                let value = fetch(&scoped)
                    .await
                    .with_context(|| format!("instance {}", target.label()))?;
                results.push(InstanceResult::new(Some(target), value));
            }
            Ok(results)
        } else {
            Ok(vec![InstanceResult::new(None, fetch(self).await?)])
        }
    }

    async fn apply_to_instances<F>(&self, apply: F) -> Result<(), Error>
    where
        F: for<'b> Fn(&'b CommandHandler<'a>) -> LocalBoxFuture<'b, ()>,
    {
        self.collect_instance_results(apply).await?;
        Ok(())
    }

    fn print_results<T>(
        &self,
        results: &[InstanceResult<T>],
        mut render: impl FnMut(&T) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let multi = results.len() > 1;
        for (idx, result) in results.iter().enumerate() {
            if multi {
                if idx > 0 {
                    println!();
                }
                if let Some(target) = result.target.as_ref() {
                    self.print_target_header(target);
                }
            }
            render(&result.value)?;
        }
        Ok(())
    }

    fn print_json_results<T: serde::Serialize>(
        &self,
        results: Vec<InstanceResult<T>>,
    ) -> Result<(), Error> {
        if results.len() == 1 {
            println!("{}", serde_json::to_string_pretty(&results[0].value)?);
            return Ok(());
        }

        let wrapped = results
            .into_iter()
            .map(|result| {
                let target = result
                    .target
                    .ok_or_else(|| anyhow::anyhow!("missing instance target for multi-result"))?;
                Ok(serde_json::json!({
                    "instance_id": target.instance_id,
                    "instance_name": target.instance_name,
                    "result": result.value,
                }))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        println!("{}", serde_json::to_string_pretty(&wrapped)?);
        Ok(())
    }

    async fn get_peer_manager_client(
        &self,
    ) -> Result<Box<dyn PeerManageRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<PeerManageRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get peer manager client")?)
    }

    async fn get_connector_manager_client(
        &self,
    ) -> Result<Box<dyn ConnectorManageRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<ConnectorManageRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get connector manager client")?)
    }

    async fn get_mapped_listener_manager_client(
        &self,
    ) -> Result<Box<dyn MappedListenerManageRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<MappedListenerManageRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get mapped listener manager client")?)
    }

    async fn get_vpn_portal_client(
        &self,
    ) -> Result<Box<dyn VpnPortalRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<VpnPortalRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get vpn portal client")?)
    }

    async fn get_acl_manager_client(
        &self,
    ) -> Result<Box<dyn AclManageRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<AclManageRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get acl manager client")?)
    }

    async fn get_tcp_proxy_client(
        &self,
        transport_type: &str,
    ) -> Result<Box<dyn TcpProxyRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<TcpProxyRpcClientFactory<BaseController>>(transport_type.to_string())
            .await
            .with_context(|| "failed to get vpn portal client")?)
    }

    async fn get_port_forward_manager_client(
        &self,
    ) -> Result<Box<dyn PortForwardManageRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<PortForwardManageRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get port forward manager client")?)
    }

    async fn get_stats_client(
        &self,
    ) -> Result<Box<dyn StatsRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<StatsRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get stats client")?)
    }

    async fn get_logger_client(
        &self,
    ) -> Result<Box<dyn LoggerRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<LoggerRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get logger client")?)
    }

    async fn get_config_client(
        &self,
    ) -> Result<Box<dyn ConfigRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<ConfigRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get config client")?)
    }

    async fn get_trust_join_manage_client(
        &self,
    ) -> Result<Box<dyn TrustJoinManageRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<TrustJoinManageRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get trust join manage client")?)
    }

    async fn get_credential_client(
        &self,
    ) -> Result<Box<dyn CredentialManageRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<CredentialManageRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get credential client")?)
    }

    async fn list_peers(&self) -> Result<ListPeerResponse, Error> {
        let client = self.get_peer_manager_client().await?;
        let request = ListPeerRequest {
            instance: Some(self.instance_selector.clone()),
        };
        let response = client.list_peer(BaseController::default(), request).await?;
        Ok(response)
    }

    async fn list_routes(&self) -> Result<ListRouteResponse, Error> {
        let client = self.get_peer_manager_client().await?;
        let request = ListRouteRequest {
            instance: Some(self.instance_selector.clone()),
        };
        let response = client
            .list_route(BaseController::default(), request)
            .await?;
        Ok(response)
    }

    async fn list_peer_route_pair(&self) -> Result<Vec<PeerRoutePair>, Error> {
        let peers = self.list_peers().await?.peer_infos;
        let routes = self.list_routes().await?.routes;
        Ok(list_peer_route_pair(peers, routes))
    }

    async fn fetch_node_info(&self) -> Result<NodeInfo, Error> {
        self.get_peer_manager_client()
            .await?
            .show_node_info(
                BaseController::default(),
                ShowNodeInfoRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?
            .node_info
            .ok_or(anyhow::anyhow!("node info not found"))
    }

    async fn fetch_peer_list_data(&self) -> Result<PeerListData, Error> {
        Ok(PeerListData {
            node_info: self.fetch_node_info().await?,
            peer_routes: self.list_peer_route_pair().await?,
        })
    }

    async fn fetch_route_dump(&self) -> Result<String, Error> {
        Ok(self
            .get_peer_manager_client()
            .await?
            .dump_route(
                BaseController::default(),
                DumpRouteRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?
            .result)
    }

    async fn fetch_foreign_networks(
        &self,
        include_trusted_keys: bool,
    ) -> Result<ForeignNetworkMap, Error> {
        Ok(self
            .get_peer_manager_client()
            .await?
            .list_foreign_network(
                BaseController::default(),
                ListForeignNetworkRequest {
                    instance: Some(self.instance_selector.clone()),
                    include_trusted_keys,
                },
            )
            .await?
            .foreign_networks)
    }

    async fn fetch_global_foreign_networks(&self) -> Result<GlobalForeignNetworkMap, Error> {
        Ok(self
            .get_peer_manager_client()
            .await?
            .list_global_foreign_network(
                BaseController::default(),
                ListGlobalForeignNetworkRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?
            .foreign_networks)
    }

    async fn fetch_route_list_data(&self) -> Result<RouteListData, Error> {
        Ok(RouteListData {
            node_info: self.fetch_node_info().await?,
            peer_routes: self.list_peer_route_pair().await?,
        })
    }

    async fn fetch_connector_list(&self) -> Result<Vec<Connector>, Error> {
        Ok(self
            .get_connector_manager_client()
            .await?
            .list_connector(
                BaseController::default(),
                ListConnectorRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?
            .connectors)
    }

    async fn fetch_acl_stats(&self) -> Result<Option<AclStats>, Error> {
        Ok(self
            .get_acl_manager_client()
            .await?
            .get_acl_stats(
                BaseController::default(),
                GetAclStatsRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?
            .acl_stats)
    }

    async fn fetch_mapped_listener_list(&self) -> Result<Vec<MappedListener>, Error> {
        Ok(self
            .get_mapped_listener_manager_client()
            .await?
            .list_mapped_listener(
                BaseController::default(),
                ListMappedListenerRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?
            .mappedlisteners)
    }

    async fn fetch_port_forward_list(&self) -> Result<ListPortForwardResponse, Error> {
        Ok(self
            .get_port_forward_manager_client()
            .await?
            .list_port_forward(
                BaseController::default(),
                ListPortForwardRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?)
    }

    async fn fetch_whitelist(&self) -> Result<GetWhitelistResponse, Error> {
        Ok(self
            .get_acl_manager_client()
            .await?
            .get_whitelist(
                BaseController::default(),
                GetWhitelistRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?)
    }

    async fn fetch_credential_list(&self) -> Result<ListCredentialsResponse, Error> {
        Ok(self
            .get_credential_client()
            .await?
            .list_credentials(
                BaseController::default(),
                ListCredentialsRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?)
    }

    async fn fetch_vpn_portal_info(&self) -> Result<VpnPortalInfo, Error> {
        Ok(self
            .get_vpn_portal_client()
            .await?
            .get_vpn_portal_info(
                BaseController::default(),
                GetVpnPortalInfoRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?
            .vpn_portal_info
            .unwrap_or_default())
    }

    async fn fetch_stats(&self) -> Result<Vec<MetricSnapshot>, Error> {
        Ok(self
            .get_stats_client()
            .await?
            .get_stats(
                BaseController::default(),
                GetStatsRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?
            .metrics)
    }

    async fn fetch_prometheus_stats(&self) -> Result<String, Error> {
        Ok(self
            .get_stats_client()
            .await?
            .get_prometheus_stats(
                BaseController::default(),
                GetPrometheusStatsRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?
            .prometheus_text)
    }

    fn connector_validate_url(url: &str) -> Result<url::Url, Error> {
        let url = url::Url::parse(url).map_err(|e| anyhow::anyhow!("invalid url ({url}): {e}"))?;
        TunnelScheme::try_from(&url).map_err(|_| {
            anyhow::anyhow!("unsupported scheme \"{}\" in url ({url})", url.scheme())
        })?;
        Ok(url)
    }

    async fn apply_connector_modify(
        &self,
        url: &str,
        action: ConfigPatchAction,
    ) -> Result<(), Error> {
        let url = match action {
            ConfigPatchAction::Add => Self::connector_validate_url(url)?,
            ConfigPatchAction::Remove => {
                url::Url::parse(url).map_err(|e| anyhow::anyhow!("invalid url ({url}): {e}"))?
            }
            ConfigPatchAction::Clear => {
                return Err(anyhow::anyhow!(
                    "unsupported connector patch action: {:?}",
                    action
                ));
            }
        };
        let client = self.get_config_client().await?;
        let request = PatchConfigRequest {
            instance: Some(self.instance_selector.clone()),
            patch: Some(InstanceConfigPatch {
                connectors: vec![UrlPatch {
                    action: action.into(),
                    url: Some(url.into()),
                }],
                ..Default::default()
            }),
            network_state_cbor: None,
        };
        let _response = client
            .patch_config(BaseController::default(), request)
            .await?;
        Ok(())
    }

    async fn handle_connector_modify(
        &self,
        url: &str,
        action: ConfigPatchAction,
    ) -> Result<(), Error> {
        let url = url.to_string();
        self.apply_to_instances(|handler| {
            let url = url.clone();
            Box::pin(async move { handler.apply_connector_modify(&url, action).await })
        })
        .await
    }

    async fn run_tui(&self) -> Result<(), Error> {
        pactmesh::tui::run(self.client.clone(), self.instance_selector.clone()).await
    }

    fn run_web(&self) -> Result<(), Error> {
        use std::io::Write;
        let url = pactmesh::controller::read_endpoint_url()?;
        println!("opening pactmesh web controller: {url}");
        let _ = std::io::stdout().flush();
        if let Err(e) = open::that(&url) {
            eprintln!("could not launch a browser automatically ({e}); open this URL manually:");
            println!("{url}");
        }
        Ok(())
    }

    fn run_tray(&self) -> Result<(), Error> {
        #[cfg(windows)]
        {
            pactmesh::tray::run()
        }
        #[cfg(not(windows))]
        {
            anyhow::bail!("the system tray is only available on Windows; use `pactmesh web` instead")
        }
    }

    async fn run_controller(&self, args: &ControllerArgs) -> Result<(), Error> {
        pactmesh::controller::run(
            self.client.clone(),
            self.instance_selector.clone(),
            pactmesh::controller::ControllerConfig {
                listen: args.listen,
                token: args.token.clone(),
                unlock_ttl_secs: args.unlock_ttl_secs,
            },
        )
        .await
    }

    async fn run_quickstart(
        &self,
        rpc_portal: SocketAddr,
        args: &QuickstartArgs,
    ) -> Result<(), Error> {
        use std::io::Write as _;
        let exe = std::env::current_exe().context("failed to locate the pactmesh executable")?;
        let core = quickstart_core_path(&exe)?;
        let device_label = args
            .device_label
            .clone()
            .unwrap_or_else(|| gethostname::gethostname().to_string_lossy().to_string());

        let root_passphrase = read_root_passphrase(args.passphrase_file.as_ref())?;
        let device_passphrase =
            resolve_quickstart_device_passphrase(args.device_passphrase_file.as_ref())?;

        let run_step = |step_args: &[&str], capture: bool| -> Result<String, Error> {
            let mut cmd = std::process::Command::new(&exe);
            cmd.args(step_args)
                .env("PNW_ROOT_PASSPHRASE", &root_passphrase)
                .env("PNW_DEVICE_PASSPHRASE", &device_passphrase);
            if capture {
                let out = cmd
                    .output()
                    .with_context(|| format!("failed to run pactmesh {}", step_args.join(" ")))?;
                if !out.status.success() {
                    std::io::stderr().write_all(&out.stderr).ok();
                    anyhow::bail!("`pactmesh {}` exited with {}", step_args.join(" "), out.status);
                }
                Ok(String::from_utf8(out.stdout)
                    .context("pactmesh output was not valid UTF-8")?
                    .trim()
                    .to_owned())
            } else {
                let status = cmd
                    .status()
                    .with_context(|| format!("failed to run pactmesh {}", step_args.join(" ")))?;
                if !status.success() {
                    anyhow::bail!("`pactmesh {}` exited with {status}", step_args.join(" "));
                }
                Ok(String::new())
            }
        };

        println!("[1/4] Creating trust domain '{}'...", args.domain_label);
        let domain_json = run_step(
            &["trust", "create-domain", "--label", &args.domain_label, "--json"],
            true,
        )?;
        let trust_domain_id = quickstart_json_field(&domain_json, "trust_domain_id")?;
        println!("      trust domain: {trust_domain_id}");

        println!("[2/4] Creating network '{}'...", args.network_id);
        run_step(
            &[
                "trust",
                "create-network",
                &trust_domain_id,
                &args.network_id,
                "--default-action",
                &args.default_action,
            ],
            false,
        )?;

        println!("[3/4] Bootstrapping this device '{device_label}'...");
        run_step(
            &[
                "trust",
                "bootstrap-self",
                &trust_domain_id,
                &args.network_id,
                "--device-label",
                &device_label,
            ],
            false,
        )?;

        let domain_dir = pnw_trust_domains_dir()?.join(&trust_domain_id);
        let domain_dir_str = domain_dir
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("trust-domain path is not UTF-8"))?;
        let log_path = pnw_config_dir()?.join("pactmesh-core-quickstart.log");
        let rpc_arg = format!("{}:{}", rpc_portal.ip(), rpc_portal.port());
        let no_tun = if args.no_tun { "true" } else { "false" };
        let daemon_args = [
            "--network-name",
            &args.network_id,
            "--trust-domain-dir",
            domain_dir_str,
            "--network-local-id",
            &args.network_id,
            "--rpc-portal",
            &rpc_arg,
            "--listeners",
            &args.listeners,
            "--no-tun",
            no_tun,
            "--disable-ipv6",
            "true",
            "--instance-name",
            &device_label,
            "--console-log-level",
            "info",
            "--daemon",
        ];
        println!(
            "[4/4] Starting pactmesh-core daemon (log: {})...",
            log_path.display()
        );
        let child = spawn_quickstart_daemon(&core, &log_path, &daemon_args, Some(&device_passphrase))?;
        println!("      daemon pid {}", child.id());

        // Let the daemon bind its rpc portal before the console starts serving live panels.
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

        let controller_args = ControllerArgs {
            listen: args.listen,
            token: args.token.clone(),
            unlock_ttl_secs: args.unlock_ttl_secs,
        };
        println!();
        println!("Setup complete. Starting the web console (Ctrl-C to stop; the daemon keeps running).");
        self.run_controller(&controller_args).await
    }

    async fn run_serve(&self, rpc_portal: SocketAddr, args: &ServeArgs) -> Result<(), Error> {
        match args.sub_command.as_ref() {
            Some(ServeSubCommand::Seal(seal_args)) => serve_seal(seal_args),
            Some(ServeSubCommand::Run(run_args)) => self.serve_run(rpc_portal, run_args).await,
            None => self.serve_empty(rpc_portal, args).await,
        }
    }

    /// Boot-time default: bring up an always-on daemon with **no** network and a
    /// persistent web console. No device passphrase is needed because no trust
    /// network is attached at startup; networks are created/joined at runtime
    /// through the console (see `RunNetworkInstance`). This fixes the desktop
    /// icon flash (the endpoint file now lives as long as the service) and the
    /// plaintext passphrase prompt at boot.
    async fn serve_empty(&self, rpc_portal: SocketAddr, args: &ServeArgs) -> Result<(), Error> {
        let config_dir = pnw_config_dir()?;
        let exe = std::env::current_exe().context("failed to locate the pactmesh executable")?;
        let core = quickstart_core_path(&exe)?;
        let instance_name = gethostname::gethostname().to_string_lossy().to_string();
        let log_path = config_dir.join("pactmesh-core-serve.log");
        let rpc_arg = format!("{}:{}", rpc_portal.ip(), rpc_portal.port());
        let no_tun = if args.no_tun { "true" } else { "false" };
        // 实例持久化目录：运行时加网的「记住」实例落 toml 于此，重启自动加载并经
        // sk_self.seal 重连（--empty 只跳过自动建默认网，不抑制加载已持久化实例）。
        let instances_dir = pnw_serve_instances_dir()?;
        std::fs::create_dir_all(&instances_dir).with_context(|| {
            format!("failed to create {}", instances_dir.display())
        })?;
        let instances_dir_str = instances_dir
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("serve instances path is not UTF-8"))?;
        let daemon_args = [
            "--empty",
            "--rpc-portal",
            &rpc_arg,
            "--no-tun",
            no_tun,
            "--config-dir",
            instances_dir_str,
            "--instance-name",
            &instance_name,
            "--console-log-level",
            "info",
            "--daemon",
        ];
        println!(
            "starting empty pactmesh-core daemon (log: {})...",
            log_path.display()
        );
        let child = spawn_quickstart_daemon(&core, &log_path, &daemon_args, None)?;
        println!("daemon pid {}", child.id());

        // Let the daemon bind its rpc portal before the console starts serving.
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

        let controller_args = ControllerArgs {
            listen: args.listen,
            token: None,
            unlock_ttl_secs: args.unlock_ttl_secs,
        };
        println!(
            "starting web console on {} (Ctrl-C to stop; no network attached yet)",
            args.listen
        );
        self.run_controller(&controller_args).await
    }

    async fn serve_run(&self, rpc_portal: SocketAddr, args: &ServeRunArgs) -> Result<(), Error> {
        let config_dir = pnw_config_dir()?;
        let config_path = config_dir.join(SERVE_CONFIG_FILE);
        let sealed_path = config_dir.join(SERVE_SEALED_FILE);

        let config: ServeConfig = serde_json::from_str(
            &std::fs::read_to_string(&config_path).with_context(|| {
                format!(
                    "serve config not found at {} (run `pactmesh serve seal` first)",
                    config_path.display()
                )
            })?,
        )
        .context("failed to parse serve config")?;

        let sealed = std::fs::read(&sealed_path).with_context(|| {
            format!(
                "sealed device passphrase not found at {} (run `pactmesh serve seal` first)",
                sealed_path.display()
            )
        })?;
        let device_passphrase = String::from_utf8(
            pactmesh::secret_seal::unseal(&sealed).context("failed to unseal device passphrase")?,
        )
        .context("unsealed device passphrase is not valid UTF-8")?;

        let exe = std::env::current_exe().context("failed to locate the pactmesh executable")?;
        let core = quickstart_core_path(&exe)?;
        let instance_name = gethostname::gethostname().to_string_lossy().to_string();

        let domain_dir = pnw_trust_domains_dir()?.join(&config.trust_domain_id);
        let domain_dir_str = domain_dir
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("trust-domain path is not UTF-8"))?;
        let log_path = config_dir.join("pactmesh-core-serve.log");
        let rpc_arg = format!("{}:{}", rpc_portal.ip(), rpc_portal.port());
        let no_tun = if config.no_tun { "true" } else { "false" };
        let daemon_args = [
            "--network-name",
            &config.network_id,
            "--trust-domain-dir",
            domain_dir_str,
            "--network-local-id",
            &config.network_id,
            "--rpc-portal",
            &rpc_arg,
            "--listeners",
            &config.listeners,
            "--no-tun",
            no_tun,
            "--disable-ipv6",
            "true",
            "--instance-name",
            &instance_name,
            "--console-log-level",
            "info",
            "--daemon",
        ];
        let listen: SocketAddr = config.listen.parse().with_context(|| {
            format!("invalid listen address in serve config: {}", config.listen)
        })?;
        println!(
            "starting pactmesh-core daemon (log: {})...",
            log_path.display()
        );
        let child = spawn_quickstart_daemon(&core, &log_path, &daemon_args, Some(&device_passphrase))?;
        println!("daemon pid {}", child.id());

        // Let the daemon bind its rpc portal before the console starts serving live panels.
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

        let controller_args = ControllerArgs {
            listen,
            token: None,
            unlock_ttl_secs: args.unlock_ttl_secs,
        };
        println!("starting web console on {listen} (Ctrl-C to stop)");
        self.run_controller(&controller_args).await
    }

    async fn handle_peer_list(&self) -> Result<(), Error> {
        #[derive(tabled::Tabled, serde::Serialize)]
        struct PeerTableItem {
            #[tabled(rename = "ipv4")]
            cidr: String,
            #[tabled(skip)]
            ipv4: String,
            hostname: String,
            cost: String,
            #[tabled(rename = "lat(ms)")]
            lat_ms: String,
            #[tabled(rename = "loss")]
            loss_rate: String,
            #[tabled(rename = "rx")]
            rx_bytes: String,
            #[tabled(rename = "tx")]
            tx_bytes: String,
            #[tabled(rename = "tunnel")]
            tunnel_proto: String,
            #[tabled(rename = "NAT")]
            nat_type: String,
            #[tabled(skip)]
            id: String,
            version: String,
        }

        impl From<PeerRoutePair> for PeerTableItem {
            fn from(p: PeerRoutePair) -> Self {
                let route = p.route.clone().unwrap_or_default();
                let lat_ms = if route.cost == 1 {
                    p.get_latency_ms().unwrap_or(0.0)
                } else {
                    route.path_latency_latency_first() as f64
                };
                PeerTableItem {
                    cidr: route.ipv4_addr.map(|ip| ip.to_string()).unwrap_or_default(),
                    ipv4: route
                        .ipv4_addr
                        .map(|ip: pactmesh::proto::common::Ipv4Inet| ip.address.unwrap_or_default())
                        .map(|ip| ip.to_string())
                        .unwrap_or_default(),
                    hostname: route.hostname.clone(),
                    cost: cost_to_str(route.cost),
                    lat_ms: format!("{:.2}", lat_ms),
                    loss_rate: format!("{:.1}%", p.get_loss_rate().unwrap_or(0.0) * 100.0),
                    rx_bytes: format_size(p.get_rx_bytes().unwrap_or(0), humansize::DECIMAL),
                    tx_bytes: format_size(p.get_tx_bytes().unwrap_or(0), humansize::DECIMAL),
                    tunnel_proto: p.get_conn_protos().unwrap_or_default().join(","),
                    nat_type: p.get_udp_nat_type(),
                    id: route.peer_id.to_string(),
                    version: if route.version.is_empty() {
                        "unknown".to_string()
                    } else {
                        route.version
                    },
                }
            }
        }

        impl From<NodeInfo> for PeerTableItem {
            fn from(p: NodeInfo) -> Self {
                PeerTableItem {
                    cidr: p.ipv4_addr.clone(),
                    ipv4: Ipv4Inet::from_str(&p.ipv4_addr)
                        .map(|ip| ip.address().to_string())
                        .unwrap_or_default(),
                    hostname: p.hostname.clone(),
                    cost: "Local".to_string(),
                    lat_ms: "-".to_string(),
                    loss_rate: "-".to_string(),
                    rx_bytes: "-".to_string(),
                    tx_bytes: "-".to_string(),
                    tunnel_proto: "-".to_string(),
                    nat_type: if let Some(info) = p.stun_info {
                        info.udp_nat_type().as_str_name().to_string()
                    } else {
                        "Unknown".to_string()
                    },
                    id: p.peer_id.to_string(),
                    version: p.version,
                }
            }
        }

        let build_items = |data: &PeerListData| {
            let mut items = Vec::with_capacity(data.peer_routes.len() + 1);
            items.push(PeerTableItem::from(data.node_info.clone()));
            items.extend(data.peer_routes.iter().cloned().map(Into::into));
            items.sort_by(|a, b| {
                use std::net::{IpAddr, Ipv4Addr};

                let a_is_local = a.cost == "Local";
                let b_is_local = b.cost == "Local";
                if a_is_local != b_is_local {
                    return if a_is_local {
                        std::cmp::Ordering::Less
                    } else {
                        std::cmp::Ordering::Greater
                    };
                }

                let a_is_public = a.hostname.starts_with(peers::PUBLIC_SERVER_HOSTNAME_PREFIX);
                let b_is_public = b.hostname.starts_with(peers::PUBLIC_SERVER_HOSTNAME_PREFIX);
                if a_is_public != b_is_public {
                    return if a_is_public {
                        std::cmp::Ordering::Less
                    } else {
                        std::cmp::Ordering::Greater
                    };
                }

                let a_ip = IpAddr::from_str(&a.ipv4).unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                let b_ip = IpAddr::from_str(&b.ipv4).unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                match a_ip.cmp(&b_ip) {
                    std::cmp::Ordering::Equal => a.hostname.cmp(&b.hostname),
                    other => other,
                }
            });
            items
        };

        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_peer_list_data()))
            .await?;

        if self.verbose {
            return self.print_json_results(
                results
                    .into_iter()
                    .map(|result| result.map(|data| data.peer_routes))
                    .collect(),
            );
        }
        if *self.output_format == OutputFormat::Json {
            return self.print_json_results(
                results
                    .into_iter()
                    .map(|result| result.map(|data| build_items(&data)))
                    .collect(),
            );
        }

        self.print_results(&results, |data| {
            let items = build_items(data);
            print_output(
                &items,
                self.output_format,
                &["tunnel", "version"],
                &["version", "tunnel", "nat", "tx", "rx", "loss", "lat(ms)"],
                self.no_trunc,
            )
        })
    }

    async fn handle_route_dump(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_route_dump()))
            .await?;
        if self.verbose || *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }
        self.print_results(&results, |result| {
            println!("response: {}", result);
            Ok(())
        })
    }

    async fn handle_foreign_network_list(&self, include_trusted_keys: bool) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| {
                Box::pin(handler.fetch_foreign_networks(include_trusted_keys))
            })
            .await?;
        if self.verbose || *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }

        self.print_results(&results, |networks| {
            for (idx, (k, v)) in networks.iter().enumerate() {
                println!("{} Network Name: {}", idx + 1, k);
                for peer in v.peers.iter() {
                    println!(
                        "  peer_id: {}, peer_conn_count: {}, conns: [ {} ]",
                        peer.peer_id,
                        peer.conns.len(),
                        peer.conns
                            .iter()
                            .map(|conn| format!(
                                "remote_addr: {}, rx_bytes: {}, tx_bytes: {}, latency_us: {}",
                                conn.tunnel
                                    .as_ref()
                                    .and_then(|t| t.display_remote_addr())
                                    .unwrap_or_default(),
                                conn.stats.as_ref().map(|s| s.rx_bytes).unwrap_or_default(),
                                conn.stats.as_ref().map(|s| s.tx_bytes).unwrap_or_default(),
                                conn.stats
                                    .as_ref()
                                    .map(|s| s.latency_us)
                                    .unwrap_or_default(),
                            ))
                            .collect::<Vec<_>>()
                            .join("; ")
                    );
                }
                if include_trusted_keys {
                    println!("  trusted_keys:");
                    for trusted_key in &v.trusted_keys {
                        let source = TrustedKeySourcePb::try_from(trusted_key.source)
                            .map(|source| source.as_str_name())
                            .unwrap_or("TRUSTED_KEY_SOURCE_PB_UNSPECIFIED");
                        let expiry = trusted_key
                            .expiry_unix
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_string());
                        println!(
                            "    source: {}, expiry_unix: {}, pubkey: {}",
                            source,
                            expiry,
                            BASE64_STANDARD.encode(&trusted_key.pubkey),
                        );
                    }
                }
            }
            Ok(())
        })
    }

    async fn handle_global_foreign_network_list(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_global_foreign_networks()))
            .await?;
        if self.verbose || *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }

        self.print_results(&results, |networks| {
            for (k, v) in networks.iter() {
                println!("Peer ID: {}", k);
                for n in v.foreign_networks.iter() {
                    println!(
                        "  Network Name: {}, Last Updated: {}, Version: {}, PeerIds: {:?}",
                        n.network_name, n.last_updated, n.version, n.peer_ids
                    );
                }
            }
            Ok(())
        })
    }

    async fn handle_route_list(&self) -> Result<(), Error> {
        #[derive(tabled::Tabled, serde::Serialize)]
        struct RouteTableItem {
            ipv4: String,
            hostname: String,
            proxy_cidrs: String,

            next_hop_ipv4: String,
            next_hop_hostname: String,
            next_hop_lat: f64,
            path_len: i32,
            path_latency: i32,

            next_hop_ipv4_lat_first: String,
            next_hop_hostname_lat_first: String,
            path_len_lat_first: i32,
            path_latency_lat_first: i32,

            version: String,
        }

        let build_items = |data: &RouteListData| {
            let mut items = vec![RouteTableItem {
                ipv4: data.node_info.ipv4_addr.clone(),
                hostname: data.node_info.hostname.clone(),
                proxy_cidrs: data.node_info.proxy_cidrs.join(", "),
                next_hop_ipv4: "-".to_string(),
                next_hop_hostname: "Local".to_string(),
                next_hop_lat: 0.0,
                path_len: 0,
                path_latency: 0,
                next_hop_ipv4_lat_first: "-".to_string(),
                next_hop_hostname_lat_first: "Local".to_string(),
                path_len_lat_first: 0,
                path_latency_lat_first: 0,
                version: data.node_info.version.clone(),
            }];

            for p in data.peer_routes.iter() {
                let Some(next_hop_pair) = data.peer_routes.iter().find(|pair| {
                    pair.route.clone().unwrap_or_default().peer_id
                        == p.route.clone().unwrap_or_default().next_hop_peer_id
                }) else {
                    continue;
                };

                let next_hop_pair_latency_first = data.peer_routes.iter().find(|pair| {
                    pair.route.clone().unwrap_or_default().peer_id
                        == p.route
                            .clone()
                            .unwrap_or_default()
                            .next_hop_peer_id_latency_first
                            .unwrap_or_default()
                });

                let route = p.route.clone().unwrap_or_default();
                items.push(RouteTableItem {
                    ipv4: route.ipv4_addr.map(|ip| ip.to_string()).unwrap_or_default(),
                    hostname: route.hostname.clone(),
                    proxy_cidrs: route.proxy_cidrs.clone().join(","),
                    next_hop_ipv4: if route.cost == 1 {
                        "DIRECT".to_string()
                    } else {
                        next_hop_pair
                            .route
                            .clone()
                            .unwrap_or_default()
                            .ipv4_addr
                            .map(|ip| ip.to_string())
                            .unwrap_or_default()
                    },
                    next_hop_hostname: if route.cost == 1 {
                        "DIRECT".to_string()
                    } else {
                        next_hop_pair.route.clone().unwrap_or_default().hostname
                    },
                    next_hop_lat: next_hop_pair.get_latency_ms().unwrap_or(0.0),
                    path_len: route.cost,
                    path_latency: route.path_latency,
                    next_hop_ipv4_lat_first: if route.cost_latency_first.unwrap_or_default() == 1 {
                        "DIRECT".to_string()
                    } else {
                        next_hop_pair_latency_first
                            .map(|pair| pair.route.clone().unwrap_or_default().ipv4_addr)
                            .unwrap_or_default()
                            .map(|ip| ip.to_string())
                            .unwrap_or_default()
                    },
                    next_hop_hostname_lat_first: if route.cost_latency_first.unwrap_or_default()
                        == 1
                    {
                        "DIRECT".to_string()
                    } else {
                        next_hop_pair_latency_first
                            .map(|pair| pair.route.clone().unwrap_or_default().hostname)
                            .unwrap_or_default()
                    },
                    path_latency_lat_first: route.path_latency_latency_first.unwrap_or_default(),
                    path_len_lat_first: route.cost_latency_first.unwrap_or_default(),
                    version: if route.version.is_empty() {
                        "unknown".to_string()
                    } else {
                        route.version
                    },
                });
            }

            items
        };

        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_route_list_data()))
            .await?;

        if self.verbose {
            return self.print_json_results(results);
        }
        if *self.output_format == OutputFormat::Json {
            return self.print_json_results(
                results
                    .into_iter()
                    .map(|result| result.map(|data| build_items(&data)))
                    .collect(),
            );
        }

        self.print_results(&results, |data| {
            let items = build_items(data);
            print_output(
                &items,
                self.output_format,
                &["proxy_cidrs", "version"],
                &["proxy_cidrs", "version"],
                self.no_trunc,
            )
        })
    }

    async fn handle_connector_list(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_connector_list()))
            .await?;
        if self.verbose || *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }
        self.print_results(&results, |connectors| {
            println!("response: {:#?}", connectors);
            Ok(())
        })
    }

    async fn handle_acl_stats(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_acl_stats()))
            .await?;
        if *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }

        self.print_results(&results, |acl_stats| {
            if let Some(acl_stats) = acl_stats {
                println!("{}", acl_stats);
            } else {
                println!("No ACL statistics available");
            }
            Ok(())
        })
    }

    async fn handle_mapped_listener_list(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_mapped_listener_list()))
            .await?;
        if self.verbose || *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }
        self.print_results(&results, |listeners| {
            println!("response: {:#?}", listeners);
            Ok(())
        })
    }

    async fn apply_mapped_listener_modify(
        &self,
        url: &str,
        action: ConfigPatchAction,
    ) -> Result<(), Error> {
        let url = Self::mapped_listener_validate_url(url)?;
        let client = self.get_config_client().await?;
        let request = PatchConfigRequest {
            instance: Some(self.instance_selector.clone()),
            patch: Some(InstanceConfigPatch {
                mapped_listeners: vec![UrlPatch {
                    action: action.into(),
                    url: Some(url.into()),
                }],
                ..Default::default()
            }),
            network_state_cbor: None,
        };
        let _response = client
            .patch_config(BaseController::default(), request)
            .await?;
        Ok(())
    }

    async fn apply_network_state_to_daemon(
        &self,
        state: &pactmesh::trust::SignedNetworkState,
    ) -> Result<(), Error> {
        let client = self.get_config_client().await?;
        client
            .patch_config(
                BaseController::default(),
                PatchConfigRequest {
                    instance: Some(self.instance_selector.clone()),
                    patch: None,
                    network_state_cbor: Some(to_canonical_cbor(state)),
                },
            )
            .await
            .with_context(|| "failed to apply network_state to running daemon")?;
        Ok(())
    }

    async fn handle_mapped_listener_modify(
        &self,
        url: &str,
        action: ConfigPatchAction,
    ) -> Result<(), Error> {
        let url = url.to_string();
        self.apply_to_instances(|handler| {
            let url = url.clone();
            Box::pin(async move { handler.apply_mapped_listener_modify(&url, action).await })
        })
        .await
    }

    fn mapped_listener_validate_url(url: &str) -> Result<url::Url, Error> {
        let url = url::Url::parse(url)?;
        if url.scheme() != "tcp" && url.scheme() != "udp" {
            return Err(anyhow::anyhow!(
                "Url ({url}) must start with tcp:// or udp://"
            ));
        } else if url.port().is_none() {
            return Err(anyhow::anyhow!("Url ({url}) is missing port num"));
        }
        Ok(url)
    }

    async fn apply_port_forward_modify(
        &self,
        action: ConfigPatchAction,
        protocol: &str,
        bind_addr: &str,
        dst_addr: Option<&str>,
    ) -> Result<(), Error> {
        let bind_addr: std::net::SocketAddr = bind_addr
            .parse()
            .with_context(|| format!("Invalid bind address: {}", bind_addr))?;

        let socket_type = match protocol {
            "tcp" => SocketType::Tcp,
            "udp" => SocketType::Udp,
            _ => return Err(anyhow::anyhow!("Protocol must be 'tcp' or 'udp'")),
        };

        let client = self.get_config_client().await?;
        let request = PatchConfigRequest {
            instance: Some(self.instance_selector.clone()),
            patch: Some(InstanceConfigPatch {
                port_forwards: vec![PortForwardPatch {
                    action: action.into(),
                    cfg: Some(PortForwardConfigPb {
                        bind_addr: Some(bind_addr.into()),
                        dst_addr: dst_addr.map(|s| s.parse::<SocketAddr>().unwrap().into()),
                        socket_type: socket_type.into(),
                    }),
                }],
                ..Default::default()
            }),
            network_state_cbor: None,
        };

        client
            .patch_config(BaseController::default(), request)
            .await?;
        println!(
            "Port forward rule {}: {} {}",
            action.as_str_name().to_lowercase(),
            protocol,
            bind_addr
        );
        Ok(())
    }

    async fn handle_port_forward_modify(
        &self,
        action: ConfigPatchAction,
        protocol: &str,
        bind_addr: &str,
        dst_addr: Option<&str>,
    ) -> Result<(), Error> {
        let protocol = protocol.to_string();
        let bind_addr = bind_addr.to_string();
        let dst_addr = dst_addr.map(str::to_string);
        self.apply_to_instances(|handler| {
            let protocol = protocol.clone();
            let bind_addr = bind_addr.clone();
            let dst_addr = dst_addr.clone();
            Box::pin(async move {
                handler
                    .apply_port_forward_modify(action, &protocol, &bind_addr, dst_addr.as_deref())
                    .await
            })
        })
        .await
    }

    async fn handle_port_forward_list(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_port_forward_list()))
            .await?;
        if self.verbose || *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }

        #[derive(tabled::Tabled, serde::Serialize)]
        struct PortForwardTableItem {
            protocol: String,
            bind_addr: String,
            dst_addr: String,
        }

        self.print_results(&results, |response| {
            let items: Vec<PortForwardTableItem> = response
                .cfgs
                .iter()
                .cloned()
                .map(|rule| PortForwardTableItem {
                    protocol: format!(
                        "{:?}",
                        SocketType::try_from(rule.socket_type).unwrap_or(SocketType::Tcp)
                    ),
                    bind_addr: rule
                        .bind_addr
                        .map(|addr| addr.to_string())
                        .unwrap_or_default(),
                    dst_addr: rule
                        .dst_addr
                        .map(|addr| addr.to_string())
                        .unwrap_or_default(),
                })
                .collect();

            print_output(&items, self.output_format, &[], &[], self.no_trunc)
        })
    }

    async fn apply_whitelist_set(&self, ports: &str, is_tcp: bool) -> Result<(), Error> {
        let mut whitelist = Self::parse_port_list(ports)?
            .into_iter()
            .map(|p| StringPatch {
                action: ConfigPatchAction::Add.into(),
                value: p,
            })
            .collect::<Vec<_>>();
        whitelist.insert(
            0,
            StringPatch {
                action: ConfigPatchAction::Clear.into(),
                value: "".to_string(),
            },
        );
        let client = self.get_config_client().await?;

        let request = PatchConfigRequest {
            instance: Some(self.instance_selector.clone()),
            patch: Some(InstanceConfigPatch {
                acl: Some(AclPatch {
                    tcp_whitelist: if is_tcp { whitelist.clone() } else { vec![] },
                    udp_whitelist: if is_tcp { vec![] } else { whitelist },
                    ..Default::default()
                }),
                ..Default::default()
            }),
            network_state_cbor: None,
        };

        client
            .patch_config(BaseController::default(), request)
            .await?;
        Ok(())
    }

    async fn handle_whitelist_set_tcp(&self, ports: &str) -> Result<(), Error> {
        let ports = ports.to_string();
        self.apply_to_instances(|handler| {
            let ports = ports.clone();
            Box::pin(async move { handler.apply_whitelist_set(&ports, true).await })
        })
        .await?;
        println!("TCP whitelist updated: {}", ports);
        Ok(())
    }

    async fn handle_whitelist_set_udp(&self, ports: &str) -> Result<(), Error> {
        let ports = ports.to_string();
        self.apply_to_instances(|handler| {
            let ports = ports.clone();
            Box::pin(async move { handler.apply_whitelist_set(&ports, false).await })
        })
        .await?;
        println!("UDP whitelist updated: {}", ports);
        Ok(())
    }

    async fn apply_whitelist_clear(&self, is_tcp: bool) -> Result<(), Error> {
        let client = self.get_config_client().await?;

        let request = PatchConfigRequest {
            instance: Some(self.instance_selector.clone()),
            patch: Some(InstanceConfigPatch {
                acl: Some(AclPatch {
                    tcp_whitelist: if is_tcp {
                        vec![StringPatch {
                            action: ConfigPatchAction::Clear.into(),
                            value: "".to_string(),
                        }]
                    } else {
                        vec![]
                    },
                    udp_whitelist: if is_tcp {
                        vec![]
                    } else {
                        vec![StringPatch {
                            action: ConfigPatchAction::Clear.into(),
                            value: "".to_string(),
                        }]
                    },
                    ..Default::default()
                }),
                ..Default::default()
            }),
            network_state_cbor: None,
        };

        client
            .patch_config(BaseController::default(), request)
            .await?;
        Ok(())
    }

    async fn handle_whitelist_clear_tcp(&self) -> Result<(), Error> {
        self.apply_to_instances(|handler| Box::pin(handler.apply_whitelist_clear(true)))
            .await?;
        println!("TCP whitelist cleared");
        Ok(())
    }

    async fn handle_whitelist_clear_udp(&self) -> Result<(), Error> {
        self.apply_to_instances(|handler| Box::pin(handler.apply_whitelist_clear(false)))
            .await?;
        println!("UDP whitelist cleared");
        Ok(())
    }

    async fn handle_whitelist_show(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_whitelist()))
            .await?;
        if self.verbose || *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }

        self.print_results(&results, |response| {
            println!(
                "TCP Whitelist: {}",
                if response.tcp_ports.is_empty() {
                    "None".to_string()
                } else {
                    response.tcp_ports.join(", ")
                }
            );

            println!(
                "UDP Whitelist: {}",
                if response.udp_ports.is_empty() {
                    "None".to_string()
                } else {
                    response.udp_ports.join(", ")
                }
            );
            Ok(())
        })
    }

    async fn handle_logger_get(&self) -> Result<(), Error> {
        let client = self.get_logger_client().await?;
        let request = GetLoggerConfigRequest::default();
        let response = client
            .get_logger_config(BaseController::default(), request)
            .await?;

        match self.output_format {
            OutputFormat::Table => {
                let level_str = match response.level() {
                    LogLevel::Disabled => "disabled",
                    LogLevel::Error => "error",
                    LogLevel::Warning => "warning",
                    LogLevel::Info => "info",
                    LogLevel::Debug => "debug",
                    LogLevel::Trace => "trace",
                };
                println!("Current Log Level: {}", level_str);
            }
            OutputFormat::Json => {
                let json = serde_json::to_string_pretty(&response)?;
                println!("{}", json);
            }
        }

        Ok(())
    }

    async fn handle_logger_set(&self, level: &str) -> Result<(), Error> {
        let log_level = match level.to_lowercase().as_str() {
            "disabled" => LogLevel::Disabled,
            "error" => LogLevel::Error,
            "warning" => LogLevel::Warning,
            "info" => LogLevel::Info,
            "debug" => LogLevel::Debug,
            "trace" => LogLevel::Trace,
            _ => {
                return Err(anyhow::anyhow!(
                    "Invalid log level: {}. Valid levels are: disabled, error, warning, info, debug, trace",
                    level
                ));
            }
        };

        let client = self.get_logger_client().await?;
        let request = SetLoggerConfigRequest {
            level: log_level.into(),
        };
        let response = client
            .set_logger_config(BaseController::default(), request)
            .await?;

        match self.output_format {
            OutputFormat::Table => {
                println!("Log level successfully set to: {}", level);
            }
            OutputFormat::Json => {
                let json = serde_json::to_string_pretty(&response)?;
                println!("{}", json);
            }
        }

        Ok(())
    }

    async fn handle_credential_generate(
        &self,
        ttl: i64,
        credential_id: Option<String>,
        groups: Vec<String>,
        allow_relay: bool,
        allowed_proxy_cidrs: Vec<String>,
        reusable: bool,
    ) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| {
                let credential_id = credential_id.clone();
                let groups = groups.clone();
                let allowed_proxy_cidrs = allowed_proxy_cidrs.clone();
                Box::pin(async move {
                    handler
                        .get_credential_client()
                        .await?
                        .generate_credential(
                            BaseController::default(),
                            GenerateCredentialRequest {
                                credential_id,
                                groups,
                                allow_relay,
                                allowed_proxy_cidrs,
                                ttl_seconds: ttl,
                                instance: Some(handler.instance_selector.clone()),
                                reusable: Some(reusable),
                            },
                        )
                        .await
                        .map_err(Into::into)
                })
            })
            .await?;

        if *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }

        self.print_results(&results, |response| {
            println!("Credential generated successfully:");
            println!("  credential_id:     {}", response.credential_id);
            println!("  credential_secret: {}", response.credential_secret);
            println!();
            println!("To use this credential on a new node:");
            println!(
                "  pactmesh-core --network-name <name> --secure-mode --credential {} -p <node-url>",
                response.credential_secret
            );
            Ok(())
        })
    }

    async fn handle_credential_revoke(&self, credential_id: &str) -> Result<(), Error> {
        let credential_id = credential_id.to_string();
        let results = self
            .collect_instance_results(|handler| {
                let credential_id = credential_id.clone();
                Box::pin(async move {
                    handler
                        .get_credential_client()
                        .await?
                        .revoke_credential(
                            BaseController::default(),
                            RevokeCredentialRequest {
                                credential_id,
                                instance: Some(handler.instance_selector.clone()),
                            },
                        )
                        .await
                        .map_err(Into::into)
                })
            })
            .await?;

        if *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }

        self.print_results(&results, |response| {
            if response.success {
                println!("Credential revoked successfully");
            } else {
                println!("Credential not found");
            }
            Ok(())
        })
    }

    async fn handle_credential_list(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_credential_list()))
            .await?;

        if *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }

        self.print_results(&results, |response| {
            if response.credentials.is_empty() {
                println!("No active credentials");
            } else {
                use tabled::{builder::Builder, settings::Style};
                let mut builder = Builder::default();
                builder.push_record([
                    "ID",
                    "Groups",
                    "Relay",
                    "Reusable",
                    "Expiry",
                    "Allowed CIDRs",
                ]);
                for cred in &response.credentials {
                    let expiry = {
                        let secs = cred.expiry_unix;
                        let remaining = secs
                            - std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs() as i64;
                        if remaining > 0 {
                            format!("{}s remaining", remaining)
                        } else {
                            "expired".to_string()
                        }
                    };
                    builder.push_record([
                        &cred.credential_id[..],
                        &cred.groups.join(","),
                        if cred.allow_relay { "yes" } else { "no" },
                        if cred.reusable.unwrap_or(true) {
                            "yes"
                        } else {
                            "no"
                        },
                        &expiry,
                        &cred.allowed_proxy_cidrs.join(","),
                    ]);
                }
                let table = builder.build().with(Style::rounded()).to_string();
                println!("{}", table);
            }
            Ok(())
        })
    }

    async fn handle_vpn_portal(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_vpn_portal_info()))
            .await?;

        if *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }

        self.print_results(&results, |resp| {
            println!("portal_name: {}", resp.vpn_type);
            println!(
                r#"
############### client_config_start ###############
{}
############### client_config_end ###############
"#,
                resp.client_config
            );
            println!("connected_clients:\n{:#?}", resp.connected_clients);
            Ok(())
        })
    }

    async fn handle_node(&self, sub_command: Option<&NodeSubCommand>) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_node_info()))
            .await?;

        if self.verbose || *self.output_format == OutputFormat::Json {
            return match sub_command {
                Some(NodeSubCommand::Config) => self.print_json_results(
                    results
                        .into_iter()
                        .map(|result| result.map(|node| node.config))
                        .collect(),
                ),
                _ => self.print_json_results(results),
            };
        }

        self.print_results(&results, |node_info| match sub_command {
            Some(NodeSubCommand::Config) => {
                println!("{}", node_info.config);
                Ok(())
            }
            Some(NodeSubCommand::Info) | None => {
                let stun_info = node_info.stun_info.clone().unwrap_or_default();
                let ip_list = node_info.ip_list.clone().unwrap_or_default();

                let mut builder = tabled::builder::Builder::default();
                builder.push_record(vec!["Virtual IP", node_info.ipv4_addr.as_str()]);
                builder.push_record(vec!["Hostname", node_info.hostname.as_str()]);
                builder.push_record(vec![
                    "Proxy CIDRs",
                    node_info.proxy_cidrs.join(", ").as_str(),
                ]);
                builder.push_record(vec!["Peer ID", node_info.peer_id.to_string().as_str()]);
                stun_info.public_ip.iter().for_each(|ip| {
                    let Ok(ip) = ip.parse::<IpAddr>() else {
                        return;
                    };
                    if ip.is_ipv4() {
                        builder.push_record(vec!["Public IPv4", ip.to_string().as_str()]);
                    } else {
                        builder.push_record(vec!["Public IPv6", ip.to_string().as_str()]);
                    }
                });
                builder.push_record(vec![
                    "UDP Stun Type",
                    format!("{:?}", stun_info.udp_nat_type()).as_str(),
                ]);
                ip_list.interface_ipv4s.iter().for_each(|ip| {
                    builder.push_record(vec!["Interface IPv4", ip.to_string().as_str()]);
                });
                ip_list.interface_ipv6s.iter().for_each(|ip| {
                    builder.push_record(vec!["Interface IPv6", ip.to_string().as_str()]);
                });
                for (idx, l) in node_info.listeners.iter().enumerate() {
                    if l.starts_with("ring") {
                        continue;
                    }
                    builder.push_record(vec![format!("Listener {}", idx).as_str(), l]);
                }

                println!("{}", builder.build().with(Style::markdown()));
                Ok(())
            }
        })
    }

    async fn handle_stats_show(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_stats()))
            .await?;

        if *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }

        #[derive(tabled::Tabled, serde::Serialize)]
        struct StatsTableRow {
            #[tabled(rename = "Metric Name")]
            name: String,
            #[tabled(rename = "Value")]
            value: String,
            #[tabled(rename = "Labels")]
            labels: String,
        }

        self.print_results(&results, |metrics| {
            let table_rows: Vec<StatsTableRow> = metrics
                .iter()
                .map(|metric| {
                    let labels_str = if metric.labels.is_empty() {
                        "-".to_string()
                    } else {
                        metric
                            .labels
                            .iter()
                            .map(|(k, v)| format!("{}={}", k, v))
                            .collect::<Vec<_>>()
                            .join(", ")
                    };

                    let formatted_value = if metric.name.contains("bytes") {
                        format_size(metric.value, humansize::BINARY)
                    } else if metric.name.contains("duration") {
                        format!("{} ms", metric.value)
                    } else {
                        metric.value.to_string()
                    };

                    StatsTableRow {
                        name: metric.name.clone(),
                        value: formatted_value,
                        labels: labels_str,
                    }
                })
                .collect();

            print_output(
                &table_rows,
                self.output_format,
                &["labels"],
                &["labels"],
                self.no_trunc,
            )
        })
    }

    async fn handle_stats_prometheus(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_prometheus_stats()))
            .await?;

        if *self.output_format == OutputFormat::Json {
            return self.print_json_results(
                results
                    .into_iter()
                    .map(|result| result.map(|text| serde_json::json!({ "prometheus_text": text })))
                    .collect(),
            );
        }

        self.print_results(&results, |text| {
            println!("{}", text);
            Ok(())
        })
    }

    fn parse_port_list(ports_str: &str) -> Result<Vec<String>, Error> {
        let mut ports = Vec::new();
        for port_spec in ports_str.split(',') {
            let port_spec = port_spec.trim();
            if port_spec.contains('-') {
                // Handle port range
                let parts: Vec<&str> = port_spec.split('-').collect();
                if parts.len() != 2 {
                    return Err(anyhow::anyhow!("Invalid port range: {}", port_spec));
                }
                let start: u16 = parts[0]
                    .parse()
                    .with_context(|| format!("Invalid start port: {}", parts[0]))?;
                let end: u16 = parts[1]
                    .parse()
                    .with_context(|| format!("Invalid end port: {}", parts[1]))?;
                if start > end {
                    return Err(anyhow::anyhow!("Invalid port range: start > end"));
                }
                ports.push(format!("{}-{}", start, end));
            } else {
                // Handle single port
                let port: u16 = port_spec
                    .parse()
                    .with_context(|| format!("Invalid port number: {}", port_spec))?;
                ports.push(port.to_string());
            }
        }
        Ok(ports)
    }
}

fn parse_bootstrap_source(source: &str) -> Result<NetworkBootstrap, Error> {
    if source.starts_with("privatenetwork://") {
        let url = Url::parse(source)?;
        return Ok(NetworkBootstrap::from_url(&url)?);
    }

    let text = std::fs::read_to_string(source)
        .with_context(|| format!("failed to read bootstrap file {source}"))?;
    Ok(NetworkBootstrap::from_pem(&text)?)
}

fn write_or_print_output(out: Option<&PathBuf>, content: &str) -> Result<(), Error> {
    if let Some(path) = out {
        std::fs::write(path, content)
            .with_context(|| format!("failed to write output file {}", path.display()))?;
    } else {
        println!("{content}");
    }
    Ok(())
}

fn discover_lab_domain_dir(
    trust_domain_id: Option<&str>,
    network_local_id: &str,
) -> Result<Option<PathBuf>, Error> {
    let base = pnw_config_dir()?.join("trust-domains");
    if let Some(td) = trust_domain_id {
        let path = base.join(td);
        return Ok(path.is_dir().then_some(path));
    }
    let Ok(entries) = std::fs::read_dir(&base) else {
        return Ok(None);
    };
    let mut matches = Vec::new();
    for entry in entries {
        let path = entry?.path();
        let network_dir = path.join("networks").join(network_local_id);
        if network_dir.join("member_cert.pem").is_file()
            || network_dir.join("network_state.cbor.pem").is_file()
        {
            matches.push(path);
        }
    }
    Ok((matches.len() == 1).then(|| matches.remove(0)))
}

async fn handle_lab(handler: &CommandHandler<'_>, args: LabArgs) -> Result<(), Error> {
    match args.sub_command.unwrap_or(LabSubCommand::Wizard) {
        LabSubCommand::Wizard => handle_lab_wizard(),
        LabSubCommand::Doctor {
            network_local_id,
            trust_domain_id,
        } => handle_lab_doctor(&network_local_id, trust_domain_id.as_deref()),
        LabSubCommand::Status {
            network_local_id,
            trust_domain_id,
            log,
        } => {
            handle_lab_status(
                handler,
                &network_local_id,
                trust_domain_id.as_deref(),
                log.as_ref(),
            )
            .await
        }
        LabSubCommand::Run { command } => match command {
            LabRunSubCommand::Daemon {
                role,
                network_local_id,
                listen_port,
                rpc_port,
                label,
                trust_domain_id,
                exec,
            } => {
                handle_lab_run_daemon(LabRunDaemonOptions {
                    role,
                    network_local_id,
                    listen_port,
                    rpc_port,
                    label,
                    trust_domain_id,
                    exec,
                })
                .await
            }
            LabRunSubCommand::Joiner {
                invite,
                label,
                network_local_id,
                listen_port,
                rpc_port,
                wait_secs,
                poll_secs,
                hint,
                passphrase_file,
            } => {
                handle_lab_run_joiner(
                    handler,
                    LabRunJoinerOptions {
                        invite,
                        label,
                        network_local_id,
                        listen_port,
                        rpc_port,
                        wait_secs,
                        poll_secs,
                        hint,
                        passphrase_file,
                    },
                )
                .await
            }
        },
        LabSubCommand::Approve {
            trust_domain_id,
            network_local_id,
            device,
            json,
            passphrase_file,
        } => {
            handle_lab_approve(
                handler,
                trust_domain_id,
                network_local_id,
                device,
                json,
                passphrase_file,
            )
            .await
        }
        LabSubCommand::Peers { command } => match command {
            LabPeersSubCommand::Explain => handle_lab_peers_explain(handler).await,
        },
        LabSubCommand::RemoteCheck { hosts, bin_dir } => {
            handle_lab_remote_check(&hosts, bin_dir.as_deref())
        }
        LabSubCommand::RemoteRun {
            a_host,
            c_host,
            trust_domain_id,
            network_local_id,
            seed,
            linux_bin_dir,
            windows_bin_dir,
            a_bin_dir,
            b_bin_dir,
            c_bin_dir,
            a_xdg,
            b_xdg,
            c_xdg,
            a_log,
            b_log,
            c_log,
            a_rpc,
            b_rpc,
            c_rpc,
            a_listen,
            b_listen,
            c_listen,
            wait_secs,
            poll_secs,
            no_deploy,
            keep_running,
            b_expect_peer,
            c_expect_peer,
        } => handle_lab_remote_run(LabRemoteRunOptions {
            a_host,
            c_host,
            trust_domain_id,
            network_local_id,
            seed,
            linux_bin_dir,
            windows_bin_dir,
            a_bin_dir,
            b_bin_dir,
            c_bin_dir,
            a_xdg,
            b_xdg,
            c_xdg,
            a_log,
            b_log,
            c_log,
            a_rpc,
            b_rpc,
            c_rpc,
            a_listen,
            b_listen,
            c_listen,
            wait_secs,
            poll_secs,
            no_deploy,
            keep_running,
            b_expect_peer,
            c_expect_peer,
        }),
        LabSubCommand::RemoteFreshRun {
            a_host,
            c_host,
            network_local_id,
            domain_label,
            root_passphrase,
            seed,
            linux_bin_dir,
            windows_bin_dir,
            a_bin_dir,
            b_bin_dir,
            c_bin_dir,
            a_xdg,
            b_xdg,
            c_xdg,
            a_log,
            b_log,
            c_log,
            a_rpc,
            b_rpc,
            c_rpc,
            a_listen,
            b_listen,
            c_listen,
            join_wait_secs,
            poll_secs,
            wait_secs,
            no_deploy,
            keep_running,
            require_bc_direct,
            c_bind_device_name,
            overlay_cidr,
        } => handle_lab_remote_fresh_run(LabRemoteFreshRunOptions {
            a_host,
            c_host,
            network_local_id,
            domain_label,
            root_passphrase,
            seed,
            linux_bin_dir,
            windows_bin_dir,
            a_bin_dir,
            b_bin_dir,
            c_bin_dir,
            a_xdg,
            b_xdg,
            c_xdg,
            a_log,
            b_log,
            c_log,
            a_rpc,
            b_rpc,
            c_rpc,
            a_listen,
            b_listen,
            c_listen,
            join_wait_secs,
            poll_secs,
            wait_secs,
            no_deploy,
            keep_running,
            require_bc_direct,
            c_bind_device_name,
            overlay_cidr,
        }),
        LabSubCommand::Disable {
            trust_domain_id,
            network_local_id,
            device,
            until,
            note,
            json,
            passphrase_file,
        } => {
            handle_lab_member_toggle(
                handler,
                trust_domain_id,
                network_local_id,
                device,
                true,
                until,
                note,
                json,
                passphrase_file,
            )
            .await
        }
        LabSubCommand::Enable {
            trust_domain_id,
            network_local_id,
            device,
            json,
            passphrase_file,
        } => {
            handle_lab_member_toggle(
                handler,
                trust_domain_id,
                network_local_id,
                device,
                false,
                None,
                None,
                json,
                passphrase_file,
            )
            .await
        }
        LabSubCommand::Commands {
            role,
            network_local_id,
            listen_port,
            rpc_port,
            test_home_name,
            seed,
            label,
            invite,
            trust_domain_id,
        } => handle_lab_commands(LabCommandOptions {
            role,
            network_local_id,
            listen_port,
            rpc_port,
            test_home_name,
            seed,
            label,
            invite,
            trust_domain_id,
        }),
    }
}

struct LabCommandOptions {
    role: LabRole,
    network_local_id: String,
    listen_port: u16,
    rpc_port: u16,
    test_home_name: String,
    seed: Option<String>,
    label: String,
    invite: Option<String>,
    trust_domain_id: Option<String>,
}

struct LabRunDaemonOptions {
    role: LabRole,
    network_local_id: String,
    listen_port: u16,
    rpc_port: u16,
    label: String,
    trust_domain_id: Option<String>,
    exec: bool,
}

struct LabRunJoinerOptions {
    invite: String,
    label: String,
    network_local_id: String,
    listen_port: u16,
    rpc_port: u16,
    wait_secs: u64,
    poll_secs: u64,
    hint: String,
    passphrase_file: Option<PathBuf>,
}

fn handle_lab_wizard() -> Result<(), Error> {
    if !std::io::stdin().is_terminal() {
        println!("PactMesh lab wizard needs an interactive terminal.");
        println!("Use 'pactmesh lab commands --help' for automation-friendly command generation.");
        return Ok(());
    }

    println!("PactMesh lab wizard (MVP)");
    println!(
        "Tip: try 'pactmesh tui' for a full-screen interactive console (peers + joins + logs in one terminal)."
    );
    println!("Generate ready-to-run commands for manual tests. Press Enter to accept defaults.");
    println!();

    let role_input = prompt_with_default("Role: root or joiner", "joiner")?;
    let role = match role_input.trim().to_ascii_lowercase().as_str() {
        "root" | "r" | "a" => LabRole::Root,
        "joiner" | "j" | "b" | "c" => LabRole::Joiner,
        other => anyhow::bail!("unknown lab role '{other}', expected root or joiner"),
    };
    let network_local_id = prompt_with_default("Network local id", "office-net")?;
    let listen_port = prompt_with_default("Listener port", "11010")?
        .parse::<u16>()
        .context("listener port must be a number")?;
    let default_rpc = if role == LabRole::Root {
        "15888"
    } else {
        "15889"
    };
    let rpc_port = prompt_with_default("Local RPC port", default_rpc)?
        .parse::<u16>()
        .context("RPC port must be a number")?;
    let test_home_name = prompt_with_default("Test directory name", "pactmesh-test")?;
    let label_default = if role == LabRole::Root {
        "root-a"
    } else {
        "node-b"
    };
    let label = prompt_with_default("Device/instance label", label_default)?;

    let (seed, invite, trust_domain_id) = match role {
        LabRole::Root => {
            let seed = prompt_required("Public seed URL, e.g. tcp://1.2.3.4:11010")?;
            let trust_domain_id =
                prompt_with_default("Trust domain id if already created", "<TRUST_DOMAIN_ID>")?;
            (Some(seed), None, Some(trust_domain_id))
        }
        LabRole::Joiner => {
            let invite = prompt_required("Invite URL")?;
            (None, Some(invite), None)
        }
    };

    println!();
    println!("# Generated commands");
    handle_lab_commands(LabCommandOptions {
        role,
        network_local_id,
        listen_port,
        rpc_port,
        test_home_name,
        seed,
        label,
        invite,
        trust_domain_id,
    })
}

fn prompt_with_default(prompt: &str, default: &str) -> Result<String, Error> {
    print!("{prompt} [{default}]: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        Ok(default.to_owned())
    } else {
        Ok(trimmed.to_owned())
    }
}

fn prompt_required(prompt: &str) -> Result<String, Error> {
    print!("{prompt}: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        anyhow::bail!("{prompt} is required");
    }
    Ok(trimmed.to_owned())
}

fn handle_lab_doctor(network_local_id: &str, trust_domain_id: Option<&str>) -> Result<(), Error> {
    let config_dir = pnw_config_dir()?;
    println!("Config dir: {}", config_dir.display());
    println!(
        "XDG_CONFIG_HOME: {}",
        std::env::var("XDG_CONFIG_HOME").unwrap_or_default()
    );
    println!(
        "PNW_DEVICE_PASSPHRASE: {}",
        if std::env::var("PNW_DEVICE_PASSPHRASE").is_ok() {
            "set"
        } else {
            "unset"
        }
    );

    let Some(domain_dir) = discover_lab_domain_dir(trust_domain_id, network_local_id)? else {
        println!("Trust domain: not found for network_local_id={network_local_id}");
        return Ok(());
    };
    let td = domain_dir
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "<unknown>".to_string());
    let network_dir = domain_dir.join("networks").join(network_local_id);
    println!("Trust domain: {td}");
    println!("Network dir: {}", network_dir.display());

    for file in [
        "member_cert.pem",
        "network_state.cbor.pem",
        "network_bootstrap.cbor.pem",
        "sk_self.raw",
        "sk_self.age",
    ] {
        let path = network_dir.join(file);
        println!(
            "  {:28} {}",
            file,
            if path.is_file() { "ok" } else { "missing" }
        );
    }

    if network_dir.join("sk_self.age").is_file() {
        println!("Device key mode: encrypted sk_self.age; daemon needs PNW_DEVICE_PASSPHRASE.");
    } else if network_dir.join("sk_self.raw").is_file() {
        println!("Device key mode: raw sk_self.raw; daemon should not need PNW_DEVICE_PASSPHRASE.");
    } else {
        println!("Device key mode: missing; run bootstrap-self or accept-invite first.");
    }

    println!();
    println!("Useful checks:");
    println!("  pactmesh --rpc-portal 127.0.0.1:<RPC_PORT> -o json peer list");
    println!("  grep -Ei 'udp hole|tcp hole|syn|sack|stun|relay|listener|error' <log> | tail -200");
    Ok(())
}

async fn handle_lab_status(
    handler: &CommandHandler<'_>,
    network_local_id: &str,
    trust_domain_id: Option<&str>,
    log: Option<&PathBuf>,
) -> Result<(), Error> {
    println!("== Local trust files ==");
    handle_lab_doctor(network_local_id, trust_domain_id)?;

    println!();
    println!("== Daemon node ==");
    if let Err(err) = handler.handle_node(None).await {
        println!("daemon RPC unavailable: {err:#}");
    }

    println!();
    println!("== Peers ==");
    if let Err(err) = handler.handle_peer_list().await {
        println!("peer list unavailable: {err:#}");
    }

    if let Some(log_path) = log {
        println!();
        println!("== Recent diagnostic log lines ==");
        print_lab_log_summary(log_path)?;
    }
    Ok(())
}

fn print_lab_log_summary(path: &PathBuf) -> Result<(), Error> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read log file {}", path.display()))?;
    let keywords = [
        "udp hole", "tcp hole", "syn", "sack", "stun", "relay", "listener", "error", "failed",
        "timeout",
    ];
    let mut matches = text
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            keywords.iter().any(|keyword| lower.contains(keyword))
        })
        .collect::<Vec<_>>();
    let keep_from = matches.len().saturating_sub(80);
    matches.drain(..keep_from);
    if matches.is_empty() {
        println!("No diagnostic lines matched in {}", path.display());
    } else {
        for line in matches {
            println!("{line}");
        }
    }
    Ok(())
}

async fn handle_lab_run_joiner(
    handler: &CommandHandler<'_>,
    options: LabRunJoinerOptions,
) -> Result<(), Error> {
    println!("Step 1/3: accepting invite online as {}", options.label);
    if std::env::var("PNW_DEVICE_PASSPHRASE").is_ok() && options.passphrase_file.is_none() {
        println!(
            "Note: PNW_DEVICE_PASSPHRASE is set; new device keys may be stored as encrypted sk_self.age."
        );
    }
    handle_trust_accept_invite(
        handler,
        AcceptInviteOptions {
            source: options.invite.clone(),
            device_label: Some(options.label.clone()),
            hint: options.hint.clone(),
            passphrase_file: options.passphrase_file.clone(),
            online: true,
            wait_secs: options.wait_secs,
            poll_secs: options.poll_secs,
        },
    )
    .await?;

    println!();
    println!("Step 2/3: checking local trust files");
    handle_lab_doctor(&options.network_local_id, None)?;

    println!();
    println!("Step 3/3: start daemon with this command");
    print_lab_joiner_daemon_command(&LabCommandOptions {
        role: LabRole::Joiner,
        network_local_id: options.network_local_id,
        listen_port: options.listen_port,
        rpc_port: options.rpc_port,
        test_home_name: std::env::var("PNW_TEST_HOME")
            .ok()
            .and_then(|path| {
                PathBuf::from(path)
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
            })
            .unwrap_or_else(|| "pactmesh-test".to_owned()),
        seed: None,
        label: options.label,
        invite: Some(options.invite),
        trust_domain_id: None,
    });
    Ok(())
}

async fn handle_lab_run_daemon(options: LabRunDaemonOptions) -> Result<(), Error> {
    println!("== Preflight ==");
    handle_lab_doctor(
        &options.network_local_id,
        options.trust_domain_id.as_deref(),
    )?;
    println!();
    println!("== Daemon command ==");
    let command = build_lab_daemon_command(&options)?;
    println!("{}", command.join(" "));
    if !options.exec {
        println!();
        println!("Add --exec to run pactmesh-core in the foreground after preflight checks.");
        return Ok(());
    }
    println!();
    println!("Starting pactmesh-core in foreground...");
    let status = std::process::Command::new(&command[0])
        .args(&command[1..])
        .status()
        .context("failed to start pactmesh-core")?;
    if !status.success() {
        anyhow::bail!("pactmesh-core exited with {status}");
    }
    Ok(())
}

fn build_lab_daemon_command(options: &LabRunDaemonOptions) -> Result<Vec<String>, Error> {
    let mut command = vec![
        "./pactmesh-core".to_owned(),
        "--network-name".to_owned(),
        options.network_local_id.clone(),
        "--network-local-id".to_owned(),
        options.network_local_id.clone(),
        "--rpc-portal".to_owned(),
        format!("127.0.0.1:{}", options.rpc_port),
        "--listeners".to_owned(),
        options.listen_port.to_string(),
        "--no-tun".to_owned(),
        "true".to_owned(),
        "--disable-ipv6".to_owned(),
        "true".to_owned(),
        "--instance-name".to_owned(),
        options.label.clone(),
        "--console-log-level".to_owned(),
        "debug".to_owned(),
        "--daemon".to_owned(),
    ];
    if options.role == LabRole::Root {
        let td = options
            .trust_domain_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--trust-domain-id is required for root role"))?;
        let dir = pnw_config_dir()?.join("trust-domains").join(td);
        command.insert(5, dir.display().to_string());
        command.insert(5, "--trust-domain-dir".to_owned());
    }
    Ok(command)
}

async fn handle_lab_peers_explain(handler: &CommandHandler<'_>) -> Result<(), Error> {
    let data = handler.fetch_peer_list_data().await?;
    println!(
        "Local peer: {} host={} version={}",
        data.node_info.peer_id, data.node_info.hostname, data.node_info.version
    );
    if data.peer_routes.is_empty() {
        println!(
            "No remote peers. Check daemon startup, invite approval, firewall, and seed reachability."
        );
        return Ok(());
    }
    for pair in data.peer_routes {
        let route = pair.route.clone().unwrap_or_default();
        let cost = cost_to_str(route.cost);
        let protos = pair.get_conn_protos().unwrap_or_default().join(",");
        println!(
            "peer={} host={} cost={} tunnel={} nat={} loss={:.1}%",
            route.peer_id,
            route.hostname,
            cost,
            if protos.is_empty() { "-" } else { &protos },
            pair.get_udp_nat_type(),
            pair.get_loss_rate().unwrap_or(0.0) * 100.0,
        );
        if cost.starts_with("relay") {
            println!("  explanation: reachable through relay, but direct P2P is not active.");
            println!(
                "  check: both sides should use --listeners 11010, Windows firewall should allow UDP/TCP 11010, then inspect UDP SYN/SACK timeout logs."
            );
        } else if cost == "p2p" || route.cost == 1 {
            println!("  explanation: direct peer route is active.");
        } else if cost == "Local" {
            println!("  explanation: this is the local node.");
        } else {
            println!("  explanation: non-direct route cost; inspect route and peer logs.");
        }
        if protos.is_empty() && !cost.starts_with("relay") {
            println!("  note: tunnel protocol is empty; direct tunnel may not be established yet.");
        }
    }
    Ok(())
}

fn handle_lab_remote_check(hosts: &[String], bin_dir: Option<&str>) -> Result<(), Error> {
    let bin_dir = bin_dir.unwrap_or(".");
    for host in hosts {
        println!("== {host} ==");
        let os = ssh_capture(
            host,
            "uname -s 2>/dev/null || powershell -NoProfile -Command \"Write-Output Windows\"",
        )?;
        let os = os.trim();
        println!("os: {}", if os.is_empty() { "unknown" } else { os });
        let command = if os.to_ascii_lowercase().contains("windows") {
            let dir = bin_dir.replace('\'', "''");
            format!(
                "powershell -NoProfile -Command \"& '{}\\pactmesh.exe' --version; & '{}\\pactmesh-core.exe' --version\"",
                dir, dir
            )
        } else {
            let dir = bin_dir.replace('\'', "'\\''");
            format!("'{dir}/pactmesh' --version && '{dir}/pactmesh-core' --version")
        };
        let versions = ssh_capture(host, &command)?;
        print!("{versions}");
        if !versions.ends_with('\n') {
            println!();
        }
    }
    Ok(())
}

#[derive(Debug)]
struct LabRemoteRunOptions {
    a_host: String,
    c_host: String,
    trust_domain_id: String,
    network_local_id: String,
    seed: String,
    linux_bin_dir: PathBuf,
    windows_bin_dir: Option<PathBuf>,
    a_bin_dir: String,
    b_bin_dir: String,
    c_bin_dir: String,
    a_xdg: String,
    b_xdg: String,
    c_xdg: String,
    a_log: String,
    b_log: String,
    c_log: String,
    a_rpc: u16,
    b_rpc: u16,
    c_rpc: u16,
    a_listen: u16,
    b_listen: u16,
    c_listen: u16,
    wait_secs: u64,
    poll_secs: u64,
    no_deploy: bool,
    keep_running: bool,
    b_expect_peer: String,
    c_expect_peer: String,
}

#[derive(Debug)]
struct LabRemoteFreshRunOptions {
    a_host: String,
    c_host: String,
    network_local_id: String,
    domain_label: String,
    root_passphrase: String,
    seed: String,
    linux_bin_dir: PathBuf,
    windows_bin_dir: Option<PathBuf>,
    a_bin_dir: String,
    b_bin_dir: String,
    c_bin_dir: String,
    a_xdg: String,
    b_xdg: String,
    c_xdg: String,
    a_log: String,
    b_log: String,
    c_log: String,
    a_rpc: u16,
    b_rpc: u16,
    c_rpc: u16,
    a_listen: u16,
    b_listen: u16,
    c_listen: u16,
    join_wait_secs: u64,
    poll_secs: u64,
    wait_secs: u64,
    no_deploy: bool,
    keep_running: bool,
    require_bc_direct: bool,
    c_bind_device_name: String,
    overlay_cidr: String,
}

#[derive(Debug)]
struct FreshRootSetup {
    trust_domain_id: String,
    invite: String,
    root_passphrase_file: String,
}

fn handle_lab_remote_run(options: LabRemoteRunOptions) -> Result<(), Error> {
    println!("remote-run: checking SSH reachability");
    ssh_capture(&options.a_host, "echo ok")?;
    ssh_capture(&options.c_host, "echo ok")?;

    let result = (|| -> Result<(), Error> {
        if !options.no_deploy {
            remote_run_deploy(&options)?;
        }
        remote_run_stop(&options)?;
        remote_run_start(&options)?;
        println!(
            "remote-run: waiting up to {}s for B/C direct route",
            options.wait_secs
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(options.wait_secs);
        let poll_interval = Duration::from_secs(options.poll_secs.max(1));
        let (b, c) = loop {
            std::thread::sleep(
                poll_interval.min(deadline.saturating_duration_since(std::time::Instant::now())),
            );
            let b = remote_run_collect_linux(
                "B",
                None,
                &options.b_bin_dir,
                options.b_rpc,
                &options.b_log,
            )?;
            let c = remote_run_collect_windows(&options)?;
            let b_direct =
                remote_run_assert_direct_quiet("B", &b.peer_json, &options.b_expect_peer);
            let c_direct =
                remote_run_assert_direct_quiet("C", &c.peer_json, &options.c_expect_peer);
            if b_direct.is_ok() && c_direct.is_ok() {
                break (b, c);
            }
            if std::time::Instant::now() >= deadline {
                break (b, c);
            }
        };

        let a = remote_run_collect_linux(
            "A",
            Some(&options.a_host),
            &options.a_bin_dir,
            options.a_rpc,
            &options.a_log,
        )?;

        println!("\n== A ==\n{}", trim_remote_output(&a.explain, 4000));
        println!("\n== B ==\n{}", trim_remote_output(&b.explain, 4000));
        println!("\n== C ==\n{}", trim_remote_output(&c.explain, 4000));
        println!("\n== key logs ==");
        println!("A:\n{}", trim_remote_output(&a.logs, 2500));
        println!("B:\n{}", trim_remote_output(&b.logs, 2500));
        println!("C:\n{}", trim_remote_output(&c.logs, 2500));

        remote_run_assert_direct("B", &b.peer_json, &options.b_expect_peer)?;
        remote_run_assert_direct("C", &c.peer_json, &options.c_expect_peer)?;
        println!("remote-run: PASS, B and C both report a direct/p2p route");
        Ok(())
    })();

    if !options.keep_running
        && let Err(err) = remote_run_stop(&options)
    {
        eprintln!("remote-run: cleanup failed: {err:#}");
    }

    result
}

fn handle_lab_remote_fresh_run(options: LabRemoteFreshRunOptions) -> Result<(), Error> {
    println!("remote-fresh-run: checking SSH reachability");
    ssh_capture(&options.a_host, "echo ok")?;
    ssh_capture(&options.c_host, "echo ok")?;

    let result = (|| -> Result<(), Error> {
        remote_fresh_clean_state(&options)?;
        if !options.no_deploy {
            remote_fresh_deploy(&options)?;
        }
        let root = remote_fresh_setup_root(&options)?;
        remote_fresh_start_root(&options, &root)?;
        remote_fresh_join_node_b(&options, &root)?;
        remote_fresh_join_node_c(&options, &root)?;
        remote_fresh_approve_until_joined(&options, &root, &["node-b", "win-c"])?;
        remote_fresh_start_joiners(&options, &root)?;
        remote_fresh_wait_for_peers(&options, &root)?;
        remote_fresh_verify_config_sync(&options, &root)?;
        remote_fresh_verify_assignment(&options, &root)?;
        println!("remote-fresh-run: PASS fresh trust-domain bootstrap and config-sync checks");
        Ok(())
    })();

    if !options.keep_running
        && let Err(err) = remote_fresh_stop(&options)
    {
        eprintln!("remote-fresh-run: cleanup failed: {err:#}");
    }

    result
}

#[derive(Debug)]
struct RemoteNodeReport {
    peer_json: String,
    explain: String,
    logs: String,
}

fn windows_c_daemon_ssh_log(local_log_dir: &str) -> String {
    format!("{local_log_dir}/win-c-daemon-ssh.log")
}

fn windows_c_daemon_ssh_pid(local_log_dir: &str) -> String {
    format!("{local_log_dir}/win-c-daemon-ssh.pid")
}

fn remote_run_deploy(options: &LabRemoteRunOptions) -> Result<(), Error> {
    println!("remote-run: deploying binaries");
    let local_pactmesh = options.linux_bin_dir.join("pactmesh");
    let local_core = options.linux_bin_dir.join("pactmesh-core");
    anyhow::ensure!(
        local_pactmesh.exists(),
        "missing {}",
        local_pactmesh.display()
    );
    anyhow::ensure!(local_core.exists(), "missing {}", local_core.display());

    ssh_capture(
        &options.a_host,
        &format!("mkdir -p {}", sh_quote(&options.a_bin_dir)),
    )?;
    run_status(
        "scp linux binaries to A",
        "scp",
        &[
            local_pactmesh.display().to_string(),
            local_core.display().to_string(),
            format!("{}:{}/", options.a_host, options.a_bin_dir),
        ],
    )?;

    std::fs::create_dir_all(&options.b_bin_dir)
        .with_context(|| format!("failed to create {}", options.b_bin_dir))?;
    std::fs::copy(&local_pactmesh, format!("{}/pactmesh", options.b_bin_dir))
        .context("failed to copy pactmesh to B bin dir")?;
    std::fs::copy(&local_core, format!("{}/pactmesh-core", options.b_bin_dir))
        .context("failed to copy pactmesh-core to B bin dir")?;

    if let Some(windows_bin_dir) = &options.windows_bin_dir {
        let win_pactmesh = windows_bin_dir.join("pactmesh.exe");
        let win_core = windows_bin_dir.join("pactmesh-core.exe");
        anyhow::ensure!(win_pactmesh.exists(), "missing {}", win_pactmesh.display());
        anyhow::ensure!(win_core.exists(), "missing {}", win_core.display());
        ssh_capture_powershell(
            &options.c_host,
            &format!(
                "New-Item -ItemType Directory -Force {} | Out-Null",
                ps_quote(&options.c_bin_dir)
            ),
        )?;
        let c_scp_dir = options.c_bin_dir.replace('\\', "/");
        let mut scp_args = vec!["-r".to_owned()];
        for entry in std::fs::read_dir(windows_bin_dir)
            .with_context(|| format!("failed to read {}", windows_bin_dir.display()))?
        {
            let entry = entry.with_context(|| {
                format!("failed to read entry under {}", windows_bin_dir.display())
            })?;
            scp_args.push(entry.path().display().to_string());
        }
        scp_args.push(format!("{}:{}/", options.c_host, c_scp_dir));
        run_status("scp windows binaries to C", "scp", &scp_args)?;
    } else {
        println!("remote-run: --windows-bin-dir omitted, reusing existing C binaries");
    }
    Ok(())
}

fn remote_fresh_deploy(options: &LabRemoteFreshRunOptions) -> Result<(), Error> {
    println!("remote-fresh-run: deploying binaries");
    let local_pactmesh = options.linux_bin_dir.join("pactmesh");
    let local_core = options.linux_bin_dir.join("pactmesh-core");
    anyhow::ensure!(
        local_pactmesh.exists(),
        "missing {}",
        local_pactmesh.display()
    );
    anyhow::ensure!(local_core.exists(), "missing {}", local_core.display());

    ssh_capture(
        &options.a_host,
        &format!("mkdir -p {}", sh_quote(&options.a_bin_dir)),
    )?;
    run_status(
        "scp linux binaries to A",
        "scp",
        &[
            local_pactmesh.display().to_string(),
            local_core.display().to_string(),
            format!("{}:{}/", options.a_host, options.a_bin_dir),
        ],
    )?;

    std::fs::create_dir_all(&options.b_bin_dir)
        .with_context(|| format!("failed to create {}", options.b_bin_dir))?;
    std::fs::copy(&local_pactmesh, format!("{}/pactmesh", options.b_bin_dir))
        .context("failed to copy pactmesh to B bin dir")?;
    std::fs::copy(&local_core, format!("{}/pactmesh-core", options.b_bin_dir))
        .context("failed to copy pactmesh-core to B bin dir")?;

    if let Some(windows_bin_dir) = &options.windows_bin_dir {
        let win_pactmesh = windows_bin_dir.join("pactmesh.exe");
        let win_core = windows_bin_dir.join("pactmesh-core.exe");
        anyhow::ensure!(win_pactmesh.exists(), "missing {}", win_pactmesh.display());
        anyhow::ensure!(win_core.exists(), "missing {}", win_core.display());
        ssh_capture_powershell(
            &options.c_host,
            &format!(
                "New-Item -ItemType Directory -Force {} | Out-Null",
                ps_quote(&options.c_bin_dir)
            ),
        )?;
        let c_scp_dir = options.c_bin_dir.replace('\\', "/");
        let mut scp_args = vec!["-r".to_owned()];
        for entry in std::fs::read_dir(windows_bin_dir)
            .with_context(|| format!("failed to read {}", windows_bin_dir.display()))?
        {
            let entry = entry.with_context(|| {
                format!("failed to read entry under {}", windows_bin_dir.display())
            })?;
            scp_args.push(entry.path().display().to_string());
        }
        scp_args.push(format!("{}:{}/", options.c_host, c_scp_dir));
        run_status("scp windows binaries to C", "scp", &scp_args)?;
    } else {
        println!("remote-fresh-run: --windows-bin-dir omitted, reusing existing C binaries");
    }
    Ok(())
}

fn remote_run_stop(options: &LabRemoteRunOptions) -> Result<(), Error> {
    println!("remote-run: stopping old daemons");
    let _ = ssh_capture(&options.a_host, "pkill -f pactmesh-core || true");
    let _ = run_status(
        "stop B daemon",
        "pkill",
        &["-f".into(), "pactmesh-core".into()],
    );
    let _ = ssh_capture_powershell(
        &options.c_host,
        "Get-Process pactmesh-core -ErrorAction SilentlyContinue | Stop-Process -Force",
    );
    let c_daemon_pid = windows_c_daemon_ssh_pid(&parent_path_unix(&options.b_log));
    let _ = run_local_sh(&format!(
        "if [ -f {pid} ]; then kill $(cat {pid}) 2>/dev/null || true; rm -f {pid}; fi",
        pid = sh_quote(&c_daemon_pid),
    ));
    std::thread::sleep(Duration::from_secs(2));
    Ok(())
}

fn remote_fresh_stop(options: &LabRemoteFreshRunOptions) -> Result<(), Error> {
    println!("remote-fresh-run: stopping daemons");
    let c_accept_pid = format!("{}/win-c-accept-ssh.pid", parent_path_unix(&options.b_log));
    let c_daemon_pid = format!("{}/win-c-daemon-ssh.pid", parent_path_unix(&options.b_log));
    let _ = run_local_sh(&format!(
        "for pidfile in {accept_pid} {daemon_pid}; do if [ -f \"$pidfile\" ]; then kill $(cat \"$pidfile\") 2>/dev/null || true; rm -f \"$pidfile\"; fi; done",
        accept_pid = sh_quote(&c_accept_pid),
        daemon_pid = sh_quote(&c_daemon_pid),
    ));
    let _ = ssh_capture(&options.a_host, "pkill -9 -x pactmesh-core || true");
    let _ = run_status(
        "stop local B daemon",
        "pkill",
        &["-9".into(), "-x".into(), "pactmesh-core".into()],
    );
    let _ = ssh_capture_powershell(
        &options.c_host,
        "$self=$PID; Get-CimInstance Win32_Process -Filter \"name = 'powershell.exe'\" | Where-Object { $_.ProcessId -ne $self -and $_.CommandLine -like '*win-c-accept.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }; Get-Process pactmesh-core -ErrorAction SilentlyContinue | Stop-Process -Force",
    );
    std::thread::sleep(Duration::from_secs(2));
    Ok(())
}

fn remote_fresh_clean_state(options: &LabRemoteFreshRunOptions) -> Result<(), Error> {
    println!("remote-fresh-run: cleaning previous fresh lab state");
    remote_fresh_stop(options)?;
    ssh_capture_sh(
        &options.a_host,
        &format!(
            "rm -rf {} {}",
            sh_quote(&options.a_xdg),
            sh_quote(&parent_path_unix(&options.a_log))
        ),
    )?;
    run_local_sh(&format!(
        "rm -rf {} {}",
        sh_quote(&options.b_xdg),
        sh_quote(&parent_path_unix(&options.b_log))
    ))?;
    let _ = ssh_capture_powershell(
        &options.c_host,
        &format!(
            "Remove-Item -Recurse -Force {} -ErrorAction SilentlyContinue",
            ps_quote(&common_parent_path_windows(&options.c_xdg, &options.c_log)),
        ),
    );
    Ok(())
}

fn remote_fresh_setup_root(options: &LabRemoteFreshRunOptions) -> Result<FreshRootSetup, Error> {
    println!("remote-fresh-run: creating fresh trust domain on A");
    let root_dir = parent_path_unix(&options.a_xdg);
    let root_passphrase_file = format!("{root_dir}/root.pass");
    let script = format!(
        "set -e\n\
         mkdir -p {root_dir} {a_xdg} {log_dir}\n\
         printf '%s\\n' {passphrase} > {pass_file}\n\
         chmod 600 {pass_file}\n\
         export XDG_CONFIG_HOME={a_xdg}\n\
         cd {a_bin}\n\
         domain_json=$(./pactmesh trust create-domain --label {label} --passphrase-file {pass_file} --json)\n\
         printf '%s\\n' \"$domain_json\"\n\
         td=$(printf '%s' \"$domain_json\" | sed -n 's/.*\"trust_domain_id\":\"\\([^\"]*\\)\".*/\\1/p')\n\
         if [ -z \"$td\" ]; then echo failed-to-parse-trust-domain >&2; exit 1; fi\n\
         ./pactmesh trust create-network \"$td\" {network} --default-action accept --passphrase-file {pass_file} --json\n\
         ./pactmesh trust bootstrap-self \"$td\" {network} --device-label root-a --passphrase-file {pass_file} --json\n\
         ./pactmesh trust invite \"$td\" {network} --seed {seed} --format url\n",
        root_dir = sh_quote(&root_dir),
        a_xdg = sh_quote(&options.a_xdg),
        log_dir = sh_quote(&parent_path_unix(&options.a_log)),
        passphrase = sh_quote(&options.root_passphrase),
        pass_file = sh_quote(&root_passphrase_file),
        a_bin = sh_quote(&options.a_bin_dir),
        label = sh_quote(&options.domain_label),
        network = sh_quote(&options.network_local_id),
        seed = sh_quote(&options.seed),
    );
    let output = ssh_capture_sh(&options.a_host, &script)?;
    let trust_domain_id = parse_json_field(&output, "trust_domain_id")?;
    let invite = output
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with("privatenetwork://"))
        .map(|line| line.trim().to_owned())
        .ok_or_else(|| anyhow::anyhow!("invite URL not found in root setup output: {output}"))?;
    println!("remote-fresh-run: trust_domain_id={trust_domain_id}");
    Ok(FreshRootSetup {
        trust_domain_id,
        invite,
        root_passphrase_file,
    })
}

fn wait_for_local_rpc(bin_dir: &str, rpc: u16, timeout_secs: u64) -> Result<(), Error> {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let cmd = format!(
            "cd {} && ./pactmesh --rpc-portal 127.0.0.1:{} node >/dev/null",
            sh_quote(bin_dir),
            rpc,
        );
        if local_capture(&cmd).is_ok() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for local RPC 127.0.0.1:{rpc}");
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn wait_for_remote_rpc(
    host: &str,
    bin_dir: &str,
    rpc: u16,
    timeout_secs: u64,
) -> Result<(), Error> {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let cmd = format!(
            "cd {} && ./pactmesh --rpc-portal 127.0.0.1:{} node >/dev/null",
            sh_quote(bin_dir),
            rpc,
        );
        if ssh_capture(host, &cmd).is_ok() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for {host} RPC 127.0.0.1:{rpc}");
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn wait_for_windows_rpc(
    host: &str,
    bin_dir: &str,
    rpc: u16,
    timeout_secs: u64,
) -> Result<(), Error> {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let script = format!(
            "Set-Location {}; & .\\pactmesh.exe --rpc-portal 127.0.0.1:{} node | Out-Null",
            ps_quote(bin_dir),
            rpc,
        );
        if ssh_capture_powershell(host, &script).is_ok() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for {host} RPC 127.0.0.1:{rpc}");
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn remote_fresh_start_root(
    options: &LabRemoteFreshRunOptions,
    root: &FreshRootSetup,
) -> Result<(), Error> {
    println!("remote-fresh-run: starting A root daemon");
    let trust_dir = format!(
        "{}/privateNetwork/trust-domains/{}",
        options.a_xdg, root.trust_domain_id
    );
    let script = format!(
        "set -e\n\
         mkdir -p {log_dir}\n\
         rm -f {log}\n\
         export XDG_CONFIG_HOME={xdg}\n\
         cd {bin}\n\
         setsid -f ./pactmesh-core --network-name {net} --trust-domain-dir {trust_dir} --network-local-id {net} --rpc-portal 127.0.0.1:{rpc} --listeners tcp://0.0.0.0:{listen} --listeners udp://0.0.0.0:{listen} --no-tun true --disable-ipv6 true --instance-name root-a --console-log-level debug --daemon > {log} 2>&1\n",
        log_dir = sh_quote(&parent_path_unix(&options.a_log)),
        log = sh_quote(&options.a_log),
        xdg = sh_quote(&options.a_xdg),
        bin = sh_quote(&options.a_bin_dir),
        net = sh_quote(&options.network_local_id),
        trust_dir = sh_quote(&trust_dir),
        rpc = options.a_rpc,
        listen = options.a_listen,
    );
    ssh_capture_sh(&options.a_host, &script)?;
    wait_for_remote_rpc(&options.a_host, &options.a_bin_dir, options.a_rpc, 20)
}

fn remote_fresh_join_node_b(
    options: &LabRemoteFreshRunOptions,
    root: &FreshRootSetup,
) -> Result<(), Error> {
    println!("remote-fresh-run: submitting B join request");
    let accept_log = format!("{}/node-b-accept.log", parent_path_unix(&options.b_log));
    let accept_code = format!("{}/node-b-accept.code", parent_path_unix(&options.b_log));
    let job = format!(
        "mkdir -p {log_dir} {xdg}\n\
         rm -f {accept_log} {accept_code}\n\
         export XDG_CONFIG_HOME={xdg}\n\
         cd {bin}\n\
         ./pactmesh trust accept-invite {invite} --device-label node-b --online --wait-secs {wait_secs} --poll-secs {poll_secs} > {accept_log} 2>&1\n\
         printf '%s\\n' \"$?\" > {accept_code}\n",
        log_dir = sh_quote(&parent_path_unix(&options.b_log)),
        xdg = sh_quote(&options.b_xdg),
        accept_log = sh_quote(&accept_log),
        accept_code = sh_quote(&accept_code),
        bin = sh_quote(&options.b_bin_dir),
        invite = sh_quote(&root.invite),
        wait_secs = options.join_wait_secs,
        poll_secs = options.poll_secs,
    );
    let script = format!(
        "nohup sh -c {} >/dev/null 2>&1 < /dev/null &\n",
        sh_quote(&job)
    );
    run_local_sh(&script)?;
    Ok(())
}

fn remote_fresh_join_node_c(
    options: &LabRemoteFreshRunOptions,
    root: &FreshRootSetup,
) -> Result<(), Error> {
    println!("remote-fresh-run: submitting C join request");
    let c_log_dir = parent_path_windows(&options.c_log);
    let accept_log = format!("{}\\win-c-accept.log", c_log_dir);
    let accept_code = format!("{}\\win-c-accept.code", c_log_dir);
    let accept_script = format!(
        "$ErrorActionPreference='Continue'\nNew-Item -ItemType Directory -Force {log_dir} | Out-Null\n'win-c accept started' | Set-Content -Path {accept_log}\n$env:XDG_CONFIG_HOME={xdg}\nSet-Location {bin}\n& .\\pactmesh.exe trust accept-invite {invite} --device-label win-c --online --wait-secs {wait_secs} --poll-secs {poll_secs} *>> {accept_log}\n$code=$LASTEXITCODE\n$code | Set-Content -Path {accept_code}\nexit $code\n",
        log_dir = ps_quote(&c_log_dir),
        xdg = ps_quote(&options.c_xdg),
        bin = ps_quote(&options.c_bin_dir),
        invite = ps_quote(&root.invite),
        wait_secs = options.join_wait_secs,
        poll_secs = options.poll_secs,
        accept_log = ps_quote(&accept_log),
        accept_code = ps_quote(&accept_code),
    );
    let ssh_log = format!("{}/win-c-accept-ssh.log", parent_path_unix(&options.b_log));
    let ssh_pid = format!("{}/win-c-accept-ssh.pid", parent_path_unix(&options.b_log));
    let command = powershell_encoded_command(&accept_script);
    let timeout_secs = options.join_wait_secs.saturating_add(60).max(60);
    let local_script = format!(
        "mkdir -p {log_dir}\nrm -f {ssh_log} {ssh_pid}\nnohup timeout {timeout_secs} ssh -o BatchMode=yes -o ConnectTimeout=8 {host} {command} > {ssh_log} 2>&1 < /dev/null &\necho $! > {ssh_pid}\n",
        log_dir = sh_quote(&parent_path_unix(&options.b_log)),
        ssh_log = sh_quote(&ssh_log),
        ssh_pid = sh_quote(&ssh_pid),
        timeout_secs = timeout_secs,
        host = sh_quote(&options.c_host),
        command = sh_quote(&command),
    );
    run_local_sh(&local_script)?;
    Ok(())
}

fn remote_fresh_pending_rows(
    options: &LabRemoteFreshRunOptions,
    root: &FreshRootSetup,
) -> Result<Vec<serde_json::Value>, Error> {
    let script = format!(
        "set -e\nexport XDG_CONFIG_HOME={xdg}\ncd {bin}\n./pactmesh --rpc-portal 127.0.0.1:{rpc} trust list-pending {td} --network-local-id {net} --json\n",
        xdg = sh_quote(&options.a_xdg),
        bin = sh_quote(&options.a_bin_dir),
        rpc = options.a_rpc,
        td = sh_quote(&root.trust_domain_id),
        net = sh_quote(&options.network_local_id),
    );
    let output = ssh_capture_sh(&options.a_host, &script)?;
    let value: serde_json::Value = serde_json::from_str(output.trim())
        .with_context(|| format!("failed to parse pending JSON: {output}"))?;
    Ok(value.as_array().cloned().unwrap_or_default())
}

fn remote_fresh_approve_until_joined(
    options: &LabRemoteFreshRunOptions,
    root: &FreshRootSetup,
    labels: &[&str],
) -> Result<(), Error> {
    println!("remote-fresh-run: approving B/C join requests");
    let mut approved = HashSet::new();
    let wanted = labels.iter().copied().collect::<HashSet<_>>();
    let deadline = std::time::Instant::now() + Duration::from_secs(options.join_wait_secs);
    loop {
        for row in remote_fresh_pending_rows(options, root)? {
            let Some(label) = row.get("device_label").and_then(|value| value.as_str()) else {
                continue;
            };
            if !wanted.contains(label) || approved.contains(label) {
                continue;
            }
            let Some(device_id) = row.get("device_id").and_then(|value| value.as_str()) else {
                continue;
            };
            let script = format!(
                "set -e\nexport XDG_CONFIG_HOME={xdg}\ncd {bin}\n./pactmesh --rpc-portal 127.0.0.1:{rpc} trust approve {td} {net} {device_id} --passphrase-file {pass_file} --json\n",
                xdg = sh_quote(&options.a_xdg),
                bin = sh_quote(&options.a_bin_dir),
                rpc = options.a_rpc,
                td = sh_quote(&root.trust_domain_id),
                net = sh_quote(&options.network_local_id),
                device_id = sh_quote(device_id),
                pass_file = sh_quote(&root.root_passphrase_file),
            );
            let output = ssh_capture_sh(&options.a_host, &script)?;
            println!("remote-fresh-run: approved {label}: {}", output.trim());
            approved.insert(label.to_owned());
        }
        if approved.len() == labels.len() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "timed out approving join requests; approved {:?}, wanted {:?}",
                approved,
                labels
            );
        }
        std::thread::sleep(Duration::from_secs(options.poll_secs.max(1)));
    }

    remote_fresh_wait_for_accepts(options)
}

fn remote_fresh_wait_for_accepts(options: &LabRemoteFreshRunOptions) -> Result<(), Error> {
    println!("remote-fresh-run: waiting for B/C accept-invite completion");
    let deadline = std::time::Instant::now() + Duration::from_secs(options.join_wait_secs);
    let b_code = format!("{}/node-b-accept.code", parent_path_unix(&options.b_log));
    let c_code = format!("{}\\win-c-accept.code", parent_path_windows(&options.c_log));
    loop {
        let b_done = std::fs::read_to_string(&b_code)
            .ok()
            .map(|value| value.trim() == "0")
            .unwrap_or(false);
        let c_done = ssh_capture_powershell(
            &options.c_host,
            &format!(
                "if (Test-Path {}) {{ Get-Content {} -Raw }}",
                ps_quote(&c_code),
                ps_quote(&c_code)
            ),
        )
        .ok()
        .map(|value| value.trim() == "0")
        .unwrap_or(false);
        if b_done && c_done {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            let b_log = std::fs::read_to_string(format!(
                "{}/node-b-accept.log",
                parent_path_unix(&options.b_log)
            ))
            .unwrap_or_default();
            let c_log = ssh_capture_powershell(
                &options.c_host,
                &format!(
                    "if (Test-Path {}) {{ Get-Content {} -Raw }}",
                    ps_quote(&format!(
                        "{}\\win-c-accept.log",
                        parent_path_windows(&options.c_log)
                    )),
                    ps_quote(&format!(
                        "{}\\win-c-accept.log",
                        parent_path_windows(&options.c_log)
                    )),
                ),
            )
            .unwrap_or_default();
            anyhow::bail!(
                "timed out waiting for accept-invite completion\nB accept log:\n{}\nC accept log:\n{}",
                trim_remote_output(&b_log, 2000),
                trim_remote_output(&c_log, 2000)
            );
        }
        std::thread::sleep(Duration::from_secs(options.poll_secs.max(1)));
    }
}

fn remote_fresh_start_joiners(
    options: &LabRemoteFreshRunOptions,
    root: &FreshRootSetup,
) -> Result<(), Error> {
    println!("remote-fresh-run: starting B/C daemons");
    std::fs::create_dir_all(parent_path_unix(&options.b_log))?;
    let b_script = format!(
        "set -e\n\
         rm -f {log}\n\
         export XDG_CONFIG_HOME={xdg}\n\
         cd {bin}\n\
         setsid -f ./pactmesh-core --network-name {net} --network-local-id {net} --rpc-portal 127.0.0.1:{rpc} --listeners tcp://0.0.0.0:{listen} --listeners udp://0.0.0.0:{listen} --peers {seed} --no-tun true --disable-ipv6 true --instance-name node-b --console-log-level debug --need-p2p true --daemon > {log} 2>&1\n",
        log = sh_quote(&options.b_log),
        xdg = sh_quote(&options.b_xdg),
        bin = sh_quote(&options.b_bin_dir),
        net = sh_quote(&options.network_local_id),
        rpc = options.b_rpc,
        listen = options.b_listen,
        seed = sh_quote(&options.seed),
    );
    run_local_sh(&b_script)?;
    wait_for_local_rpc(&options.b_bin_dir, options.b_rpc, 20)?;

    start_windows_c_daemon(
        &options.c_host,
        &options.c_bin_dir,
        &options.c_xdg,
        &options.c_log,
        &parent_path_unix(&options.b_log),
        &options.network_local_id,
        options.c_rpc,
        options.c_listen,
        &options.seed,
        options.c_bind_device_name.trim(),
    )?;
    wait_for_windows_rpc(&options.c_host, &options.c_bin_dir, options.c_rpc, 30)?;

    let _ = root;
    Ok(())
}

fn remote_fresh_wait_for_peers(
    options: &LabRemoteFreshRunOptions,
    _root: &FreshRootSetup,
) -> Result<(), Error> {
    if options.require_bc_direct {
        println!(
            "remote-fresh-run: waiting up to {}s for peer visibility and B/C direct route",
            options.wait_secs
        );
    } else {
        println!(
            "remote-fresh-run: waiting up to {}s for peer visibility",
            options.wait_secs
        );
    }
    let overlay_cidrs = parse_overlay_cidrs(&options.overlay_cidr);
    let deadline = std::time::Instant::now() + Duration::from_secs(options.wait_secs);
    let mut last_direct_error: Option<String> = None;
    loop {
        let b =
            remote_run_collect_linux("B", None, &options.b_bin_dir, options.b_rpc, &options.b_log)?;
        let c = remote_fresh_collect_windows(options)?;
        let last_b = b.explain;
        let last_c = c.explain;
        // B's OS hostname is environment-dependent (host migrations rename it),
        // so derive it from B's own "Local peer: ... host=<name>" line instead of
        // hardcoding; C-sees-B then matches whatever hostname B currently reports.
        let b_hostname = last_b
            .lines()
            .find(|l| l.contains("Local peer:"))
            .and_then(|l| l.split("host=").nth(1))
            .and_then(|r| r.split_whitespace().next())
            .unwrap_or("")
            .to_ascii_lowercase();
        let b_sees_c = b.peer_json.to_ascii_lowercase().contains("laptop")
            || b.peer_json.to_ascii_lowercase().contains("win-c");
        let c_sees_b = c.peer_json.to_ascii_lowercase().contains("node-b")
            || (!b_hostname.is_empty()
                && c.peer_json.to_ascii_lowercase().contains(b_hostname.as_str()));
        let b_direct = remote_run_assert_direct_quiet("B", &b.peer_json, "LAPTOP")
            .or_else(|_| remote_run_assert_direct_quiet("B", &b.peer_json, "win-c"));
        let c_direct = (if b_hostname.is_empty() {
            Err(anyhow::anyhow!("C: B hostname unknown"))
        } else {
            remote_run_assert_direct_quiet("C", &c.peer_json, &b_hostname)
        })
        .or_else(|_| remote_run_assert_direct_quiet("C", &c.peer_json, "node-b"));
        if b_sees_c && c_sees_b {
            if options.require_bc_direct {
                if b_direct.is_ok() && c_direct.is_ok() {
                    let physical = if overlay_cidrs.is_empty() {
                        Ok(())
                    } else {
                        verify_bc_physical_direct(
                            options,
                            &b.peer_json,
                            &c.peer_json,
                            &overlay_cidrs,
                        )
                    };
                    match physical {
                        Ok(()) => {
                            println!("\n== B ==\n{}", trim_remote_output(&last_b, 4000));
                            println!("\n== C ==\n{}", trim_remote_output(&last_c, 4000));
                            if !overlay_cidrs.is_empty() {
                                println!(
                                    "remote-fresh-run: verified B/C physical direct (remote_addr outside overlay {})",
                                    options.overlay_cidr
                                );
                            }
                            return Ok(());
                        }
                        Err(err) => {
                            last_direct_error =
                                Some(format!("B/C p2p ok but physical-direct unmet: {err:#}"));
                        }
                    }
                } else {
                    last_direct_error = Some(format!(
                        "B direct: {}; C direct: {}",
                        b_direct
                            .as_ref()
                            .map(|_| "ok".to_owned())
                            .unwrap_or_else(|err| err.to_string()),
                        c_direct
                            .as_ref()
                            .map(|_| "ok".to_owned())
                            .unwrap_or_else(|err| err.to_string())
                    ));
                }
            } else if b_direct.is_err() || c_direct.is_err() {
                println!("\n== B ==\n{}", trim_remote_output(&last_b, 4000));
                println!("\n== C ==\n{}", trim_remote_output(&last_c, 4000));
                println!(
                    "remote-fresh-run: B/C visible but not direct; continuing because --require-bc-direct=false"
                );
                return Ok(());
            } else {
                println!("\n== B ==\n{}", trim_remote_output(&last_b, 4000));
                println!("\n== C ==\n{}", trim_remote_output(&last_c, 4000));
                return Ok(());
            }
        }

        if std::time::Instant::now() >= deadline {
            if options.require_bc_direct && b_sees_c && c_sees_b {
                anyhow::bail!(
                    "timed out waiting for B/C direct route\nlast direct check: {}\nlast B:\n{}\nlast C:\n{}",
                    last_direct_error
                        .unwrap_or_else(|| "B/C direct route was not established".to_owned()),
                    trim_remote_output(&last_b, 4000),
                    trim_remote_output(&last_c, 4000)
                );
            }
            anyhow::bail!(
                "timed out waiting for B/C peer visibility\nlast B:\n{}\nlast C:\n{}",
                trim_remote_output(&last_b, 4000),
                trim_remote_output(&last_c, 4000)
            );
        }
        std::thread::sleep(Duration::from_secs(options.poll_secs.max(1)));
    }
}

fn remote_fresh_collect_windows(
    options: &LabRemoteFreshRunOptions,
) -> Result<RemoteNodeReport, Error> {
    let compat = LabRemoteRunOptions {
        a_host: options.a_host.clone(),
        c_host: options.c_host.clone(),
        trust_domain_id: String::new(),
        network_local_id: options.network_local_id.clone(),
        seed: options.seed.clone(),
        linux_bin_dir: options.linux_bin_dir.clone(),
        windows_bin_dir: options.windows_bin_dir.clone(),
        a_bin_dir: options.a_bin_dir.clone(),
        b_bin_dir: options.b_bin_dir.clone(),
        c_bin_dir: options.c_bin_dir.clone(),
        a_xdg: options.a_xdg.clone(),
        b_xdg: options.b_xdg.clone(),
        c_xdg: options.c_xdg.clone(),
        a_log: options.a_log.clone(),
        b_log: options.b_log.clone(),
        c_log: options.c_log.clone(),
        a_rpc: options.a_rpc,
        b_rpc: options.b_rpc,
        c_rpc: options.c_rpc,
        a_listen: options.a_listen,
        b_listen: options.b_listen,
        c_listen: options.c_listen,
        wait_secs: options.wait_secs,
        poll_secs: options.poll_secs,
        no_deploy: options.no_deploy,
        keep_running: options.keep_running,
        b_expect_peer: "LAPTOP".to_owned(),
        c_expect_peer: "user".to_owned(),
    };
    remote_run_collect_windows(&compat)
}

fn remote_fresh_c_members(
    options: &LabRemoteFreshRunOptions,
    root: &FreshRootSetup,
) -> Result<Vec<serde_json::Value>, Error> {
    let script = format!(
        "$env:XDG_CONFIG_HOME={xdg}; Set-Location {bin}; & .\\pactmesh.exe --rpc-portal 127.0.0.1:{rpc} trust list-members {td} {net} --include all --json",
        xdg = ps_quote(&options.c_xdg),
        bin = ps_quote(&options.c_bin_dir),
        rpc = options.c_rpc,
        td = ps_quote(&root.trust_domain_id),
        net = ps_quote(&options.network_local_id),
    );
    let output = ssh_capture_powershell(&options.c_host, &script)?;
    let value: serde_json::Value = serde_json::from_str(output.trim())
        .with_context(|| format!("failed to parse C members JSON: {output}"))?;
    Ok(value.as_array().cloned().unwrap_or_default())
}

fn remote_fresh_wait_for_c_member_status(
    options: &LabRemoteFreshRunOptions,
    root: &FreshRootSetup,
    label: &str,
    status: &str,
) -> Result<(), Error> {
    let deadline = std::time::Instant::now() + Duration::from_secs(options.wait_secs);
    loop {
        let rows = remote_fresh_c_members(options, root)?;
        if rows.iter().any(|row| {
            row.get("device_label").and_then(|value| value.as_str()) == Some(label)
                && row.get("status").and_then(|value| value.as_str()) == Some(status)
        }) {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for C to see {label} as {status}; last rows={}",
                serde_json::to_string(&rows).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_secs(options.poll_secs.max(1)));
    }
}

fn remote_fresh_verify_config_sync(
    options: &LabRemoteFreshRunOptions,
    root: &FreshRootSetup,
) -> Result<(), Error> {
    println!("remote-fresh-run: verifying disable/enable config-sync to C");
    let b_fp = remote_fresh_c_members(options, root)?
        .into_iter()
        .find(|row| row.get("device_label").and_then(|value| value.as_str()) == Some("node-b"))
        .and_then(|row| {
            row.get("fingerprint")
                .and_then(|value| value.as_str())
                .map(str::to_owned)
        })
        .ok_or_else(|| anyhow::anyhow!("C member list does not contain node-b"))?;
    let disable = format!(
        "set -e\nexport XDG_CONFIG_HOME={xdg}\ncd {bin}\n./pactmesh --rpc-portal 127.0.0.1:{rpc} trust disable {td} {net} {fp} --note remote-fresh-run --passphrase-file {pass_file} --json\n",
        xdg = sh_quote(&options.a_xdg),
        bin = sh_quote(&options.a_bin_dir),
        rpc = options.a_rpc,
        td = sh_quote(&root.trust_domain_id),
        net = sh_quote(&options.network_local_id),
        fp = sh_quote(&b_fp),
        pass_file = sh_quote(&root.root_passphrase_file),
    );
    let out = ssh_capture_sh(&options.a_host, &disable)?;
    println!("remote-fresh-run: disable node-b: {}", out.trim());
    remote_fresh_wait_for_c_member_status(options, root, "node-b", "disabled")?;

    let enable = format!(
        "set -e\nexport XDG_CONFIG_HOME={xdg}\ncd {bin}\n./pactmesh --rpc-portal 127.0.0.1:{rpc} trust enable {td} {net} {fp} --passphrase-file {pass_file} --json\n",
        xdg = sh_quote(&options.a_xdg),
        bin = sh_quote(&options.a_bin_dir),
        rpc = options.a_rpc,
        td = sh_quote(&root.trust_domain_id),
        net = sh_quote(&options.network_local_id),
        fp = sh_quote(&b_fp),
        pass_file = sh_quote(&root.root_passphrase_file),
    );
    let out = ssh_capture_sh(&options.a_host, &enable)?;
    println!("remote-fresh-run: enable node-b: {}", out.trim());
    remote_fresh_wait_for_c_member_status(options, root, "node-b", "active")
}

// 取 node-b 当前在 C 同步到的成员行（fingerprint/status）。
fn remote_fresh_node_b_member(
    options: &LabRemoteFreshRunOptions,
    root: &FreshRootSetup,
) -> Result<serde_json::Value, Error> {
    remote_fresh_c_members(options, root)?
        .into_iter()
        .find(|row| row.get("device_label").and_then(|v| v.as_str()) == Some("node-b"))
        .ok_or_else(|| anyhow::anyhow!("C member list does not contain node-b"))
}

// 读本地 node-b daemon 上报的虚拟 IPv4（ShowNodeInfo.ipv4_addr）。空串 = 未指派/未分配。
fn remote_fresh_node_b_reported_ipv4(options: &LabRemoteFreshRunOptions) -> Result<String, Error> {
    let cmd = format!(
        "cd {bin} && ./pactmesh --rpc-portal 127.0.0.1:{rpc} -o json node",
        bin = sh_quote(&options.b_bin_dir),
        rpc = options.b_rpc,
    );
    let output = local_capture(&cmd)?;
    let value: serde_json::Value = serde_json::from_str(output.trim())
        .with_context(|| format!("failed to parse node-b node JSON: {output}"))?;
    Ok(value
        .get("ipv4_addr")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned())
}

fn remote_fresh_wait_for_node_b_ipv4(
    options: &LabRemoteFreshRunOptions,
    want: &str,
) -> Result<(), Error> {
    let deadline = std::time::Instant::now() + Duration::from_secs(options.wait_secs);
    let mut last = String::new();
    loop {
        last = remote_fresh_node_b_reported_ipv4(options).unwrap_or(last);
        if last == want {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for node-b reported ipv4 to become {:?}; last={:?}",
                want,
                last
            );
        }
        std::thread::sleep(Duration::from_secs(options.poll_secs.max(1)));
    }
}

// 主控指派 IP 回归：root 在 A 给 node-b 派固定 IP（root-signed network_state，不重签证书）→
// config-sync 到 node-b → node-b 运行时应用、上报该 IP，且证书指纹不变（不掉线/不踢）→ 清除回退空。
fn remote_fresh_verify_assignment(
    options: &LabRemoteFreshRunOptions,
    root: &FreshRootSetup,
) -> Result<(), Error> {
    println!("remote-fresh-run: verifying root-assigned IP config-sync to node-b");
    let before = remote_fresh_node_b_member(options, root)?;
    let b_fp = before
        .get("fingerprint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("node-b member row missing fingerprint"))?
        .to_owned();
    let assigned_cidr = "10.18.222.5/16";

    let assign = format!(
        "set -e\nexport XDG_CONFIG_HOME={xdg}\ncd {bin}\n./pactmesh --rpc-portal 127.0.0.1:{rpc} trust assigned-ipv4 {td} {net} {fp} --ipv4 {cidr} --passphrase-file {pass_file} --json\n",
        xdg = sh_quote(&options.a_xdg),
        bin = sh_quote(&options.a_bin_dir),
        rpc = options.a_rpc,
        td = sh_quote(&root.trust_domain_id),
        net = sh_quote(&options.network_local_id),
        fp = sh_quote(&b_fp),
        cidr = sh_quote(assigned_cidr),
        pass_file = sh_quote(&root.root_passphrase_file),
    );
    let out = ssh_capture_sh(&options.a_host, &assign)?;
    println!("remote-fresh-run: assign node-b {assigned_cidr}: {}", out.trim());

    remote_fresh_wait_for_node_b_ipv4(options, assigned_cidr)?;
    println!("remote-fresh-run: node-b reports assigned IP {assigned_cidr}");

    // 不踢断言：指派后 node-b 仍在网、状态 active、证书指纹不变（network_state 路线不重签证书）。
    let after = remote_fresh_node_b_member(options, root)?;
    let after_fp = after.get("fingerprint").and_then(|v| v.as_str()).unwrap_or_default();
    let after_status = after.get("status").and_then(|v| v.as_str()).unwrap_or_default();
    anyhow::ensure!(
        after_fp == b_fp,
        "assignment must not reissue node-b cert: fingerprint changed {b_fp} -> {after_fp}"
    );
    anyhow::ensure!(
        after_status == "active",
        "node-b must stay active after assignment, got status={after_status}"
    );
    println!("remote-fresh-run: node-b stayed active, fingerprint unchanged (not kicked)");

    // 清除指派 → node-b 回退（--no-tun 无 DHCP/静态 → 上报空）。
    let clear = format!(
        "set -e\nexport XDG_CONFIG_HOME={xdg}\ncd {bin}\n./pactmesh --rpc-portal 127.0.0.1:{rpc} trust assigned-ipv4 {td} {net} {fp} --clear --passphrase-file {pass_file} --json\n",
        xdg = sh_quote(&options.a_xdg),
        bin = sh_quote(&options.a_bin_dir),
        rpc = options.a_rpc,
        td = sh_quote(&root.trust_domain_id),
        net = sh_quote(&options.network_local_id),
        fp = sh_quote(&b_fp),
        pass_file = sh_quote(&root.root_passphrase_file),
    );
    let out = ssh_capture_sh(&options.a_host, &clear)?;
    println!("remote-fresh-run: clear node-b assignment: {}", out.trim());
    remote_fresh_wait_for_node_b_ipv4(options, "")?;
    println!("remote-fresh-run: node-b reverted to unassigned after clear");
    Ok(())
}

fn remote_run_start(options: &LabRemoteRunOptions) -> Result<(), Error> {
    println!("remote-run: starting A/B/C daemons");
    let a_trust_dir = format!(
        "{}/privateNetwork/trust-domains/{}",
        options.a_xdg, options.trust_domain_id
    );
    let a_log_dir = parent_path_unix(&options.a_log);
    let a_script = format!(
        r#"#!/bin/sh
cd {a_bin}
export XDG_CONFIG_HOME={a_xdg}
exec ./pactmesh-core --network-name {net} --trust-domain-dir {trust} --network-local-id {net} --rpc-portal 127.0.0.1:{rpc} --listeners tcp://0.0.0.0:{listen} --listeners udp://0.0.0.0:{listen} --no-tun true --disable-ipv6 true --instance-name root-a --console-log-level debug --daemon
"#,
        a_bin = sh_quote(&options.a_bin_dir),
        a_xdg = sh_quote(&options.a_xdg),
        net = sh_quote(&options.network_local_id),
        trust = sh_quote(&a_trust_dir),
        rpc = options.a_rpc,
        listen = options.a_listen,
    );
    let a_script_b64 = BASE64_STANDARD.encode(a_script.as_bytes());
    let a_script_path = format!("{}/remote-run-root-a.sh", a_log_dir);
    ssh_capture(
        &options.a_host,
        &format!(
            "mkdir -p {a_log_dir} && rm -f {a_log} && printf %s {script_b64} | base64 -d > {script_path} && chmod +x {script_path} && (setsid -f sh {script_path} </dev/null > {a_log} 2>&1 &) && echo started",
            a_log_dir = sh_quote(&a_log_dir),
            a_log = sh_quote(&options.a_log),
            script_b64 = sh_quote(&a_script_b64),
            script_path = sh_quote(&a_script_path),
        ),
    )?;

    std::fs::create_dir_all(parent_path_unix(&options.b_log))?;
    let b_script = format!(
        r#"#!/bin/sh
cd {b_bin}
export XDG_CONFIG_HOME={b_xdg}
exec ./pactmesh-core --network-name {net} --network-local-id {net} --rpc-portal 127.0.0.1:{rpc} --listeners tcp://0.0.0.0:{listen} --listeners udp://0.0.0.0:{listen} --peers {seed} --no-tun true --disable-ipv6 true --instance-name node-b --console-log-level debug --need-p2p true --daemon
"#,
        b_bin = sh_quote(&options.b_bin_dir),
        b_xdg = sh_quote(&options.b_xdg),
        net = sh_quote(&options.network_local_id),
        rpc = options.b_rpc,
        listen = options.b_listen,
        seed = sh_quote(&options.seed),
    );
    let b_script_path = format!("{}/remote-run-node-b.sh", parent_path_unix(&options.b_log));
    std::fs::write(&b_script_path, b_script)
        .with_context(|| format!("failed to write {b_script_path}"))?;
    let b_cmd = format!(
        "rm -f {b_log} && setsid -f sh {script_path} </dev/null > {b_log} 2>&1 && echo started",
        b_log = sh_quote(&options.b_log),
        script_path = sh_quote(&b_script_path),
    );
    run_status("start B daemon", "sh", &["-c".into(), b_cmd])?;

    start_windows_c_daemon(
        &options.c_host,
        &options.c_bin_dir,
        &options.c_xdg,
        &options.c_log,
        &parent_path_unix(&options.b_log),
        &options.network_local_id,
        options.c_rpc,
        options.c_listen,
        &options.seed,
        "",
    )?;
    wait_for_windows_rpc(&options.c_host, &options.c_bin_dir, options.c_rpc, 30)?;
    Ok(())
}

fn remote_run_collect_linux(
    label: &str,
    host: Option<&str>,
    bin_dir: &str,
    rpc: u16,
    log_path: &str,
) -> Result<RemoteNodeReport, Error> {
    let peer_cmd = format!(
        "cd {bin} && ./pactmesh --rpc-portal 127.0.0.1:{rpc} -o json peer list",
        bin = sh_quote(bin_dir),
    );
    let explain_cmd = format!(
        "cd {bin} && ./pactmesh --rpc-portal 127.0.0.1:{rpc} lab peers explain",
        bin = sh_quote(bin_dir),
    );
    let logs_cmd = format!(
        "grep -Ei 'p2p|relay|hole punch|symmetric|direct|failed|error|warn' {log} | tail -120 || tail -120 {log}",
        log = sh_quote(log_path),
    );
    let run = |cmd: &str| -> Result<String, Error> {
        match host {
            Some(h) => ssh_capture(h, cmd),
            None => local_capture(cmd),
        }
    };
    let peer_json =
        run(&peer_cmd).with_context(|| format!("failed to collect {label} peer json"))?;
    let explain =
        run(&explain_cmd).with_context(|| format!("failed to collect {label} peer explain"))?;
    let logs = run(&logs_cmd).unwrap_or_else(|err| format!("log collection failed: {err:#}"));
    Ok(RemoteNodeReport {
        peer_json,
        explain,
        logs,
    })
}

#[allow(clippy::too_many_arguments)]
fn start_windows_c_daemon(
    host: &str,
    bin_dir: &str,
    xdg: &str,
    log: &str,
    local_log_dir: &str,
    network: &str,
    rpc: u16,
    listen: u16,
    seed: &str,
    bind_device_name: &str,
) -> Result<(), Error> {
    let bind_args = if bind_device_name.is_empty() {
        String::new()
    } else {
        format!(
            " --bind-device true --bind-device-public true --bind-device-name {}",
            cmd_quote(bind_device_name)
        )
    };
    let cmd_line = format!(
        ".\\pactmesh-core.exe --network-name {net} --network-local-id {net} --rpc-portal 127.0.0.1:{rpc} --listeners tcp://0.0.0.0:{listen} --listeners udp://0.0.0.0:{listen} --peers {seed} --no-tun true --disable-ipv6 true --instance-name win-c --console-log-level debug --need-p2p true{bind_args} --daemon >> {log} 2>&1",
        net = cmd_quote(network),
        rpc = rpc,
        listen = listen,
        seed = cmd_quote(seed),
        log = cmd_quote(log),
    );
    let script = format!(
        "$ErrorActionPreference='Stop'\nNew-Item -ItemType Directory -Force {log_dir} | Out-Null\nRemove-Item -Force {log} -ErrorAction SilentlyContinue\n$env:XDG_CONFIG_HOME={xdg}\nSet-Location {bin}\n'win-c daemon started ' + (Get-Date -Format o) | Set-Content -Path {log}\n$cmd = {cmd_line}\ncmd.exe /d /s /c $cmd\n$code=$LASTEXITCODE\n'win-c daemon exited code=' + $code + ' ' + (Get-Date -Format o) | Add-Content -Path {log}\nexit $code\n",
        log_dir = ps_quote(&parent_path_windows(log)),
        log = ps_quote(log),
        xdg = ps_quote(xdg),
        bin = ps_quote(bin_dir),
        cmd_line = ps_quote(&cmd_line),
    );
    let command = powershell_encoded_command(&script);
    let ssh_log = windows_c_daemon_ssh_log(local_log_dir);
    let ssh_pid = windows_c_daemon_ssh_pid(local_log_dir);
    let local_script = format!(
        "mkdir -p {log_dir}\nrm -f {ssh_log} {ssh_pid}\nnohup ssh -o BatchMode=yes -o ConnectTimeout=8 {host} {command} > {ssh_log} 2>&1 < /dev/null &\necho $! > {ssh_pid}\n",
        log_dir = sh_quote(local_log_dir),
        ssh_log = sh_quote(&ssh_log),
        ssh_pid = sh_quote(&ssh_pid),
        host = sh_quote(host),
        command = sh_quote(&command),
    );
    run_local_sh(&local_script)?;
    Ok(())
}

fn remote_windows_node_diagnostics(host: &str, log_path: &str) -> String {
    let script = format!(
        r#"$log={log}; '--- pactmesh-core processes ---'; $procs=Get-CimInstance Win32_Process -Filter "name = 'pactmesh-core.exe'" -ErrorAction SilentlyContinue; if ($procs) {{ $procs | Select-Object ProcessId,ParentProcessId,CreationDate,CommandLine | Format-List | Out-String }} else {{ 'none' }}; '--- key logs ---'; if (Test-Path $log) {{ Select-String -Path $log -Pattern 'p2p|relay|hole punch|symmetric|direct|failed|error|warn|panic|panicked|CORE::INSTANCE::CONNECTION|PeerConn|daemon exited' | Select-Object -Last 160 | ForEach-Object {{ $_.Line }} }} else {{ 'missing log: ' + $log }}"#,
        log = ps_quote(log_path),
    );
    ssh_capture_powershell(host, &script)
        .unwrap_or_else(|err| format!("diagnostics collection failed: {err:#}"))
}

fn remote_run_collect_windows(options: &LabRemoteRunOptions) -> Result<RemoteNodeReport, Error> {
    let peer_script = format!(
        "Set-Location {}; & .\\pactmesh.exe --rpc-portal 127.0.0.1:{} -o json peer list",
        ps_quote(&options.c_bin_dir),
        options.c_rpc,
    );
    let explain_script = format!(
        "Set-Location {}; & .\\pactmesh.exe --rpc-portal 127.0.0.1:{} lab peers explain",
        ps_quote(&options.c_bin_dir),
        options.c_rpc,
    );
    let peer_json = ssh_capture_powershell(&options.c_host, &peer_script).with_context(|| {
        format!(
            "failed to collect C peer json\n{}",
            trim_remote_output(
                &remote_windows_node_diagnostics(&options.c_host, &options.c_log),
                4000
            )
        )
    })?;
    let explain = ssh_capture_powershell(&options.c_host, &explain_script).with_context(|| {
        format!(
            "failed to collect C peer explain\n{}",
            trim_remote_output(
                &remote_windows_node_diagnostics(&options.c_host, &options.c_log),
                4000
            )
        )
    })?;
    let logs = remote_windows_node_diagnostics(&options.c_host, &options.c_log);
    Ok(RemoteNodeReport {
        peer_json,
        explain,
        logs,
    })
}

fn remote_run_assert_direct(node: &str, peer_json: &str, expect_peer: &str) -> Result<(), Error> {
    remote_run_assert_direct_quiet(node, peer_json, expect_peer)
}

fn remote_run_assert_direct_quiet(
    node: &str,
    peer_json: &str,
    expect_peer: &str,
) -> Result<(), Error> {
    let peers: serde_json::Value = serde_json::from_str(peer_json)
        .with_context(|| format!("{node} peer list did not return JSON"))?;
    let rows = peers
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("{node} peer JSON is not an array"))?;
    for row in rows {
        let text = row.to_string().to_ascii_lowercase();
        if !text.contains(&expect_peer.to_ascii_lowercase()) {
            continue;
        }
        let cost = row.get("cost").and_then(|v| v.as_str()).unwrap_or_default();
        let tunnel = row
            .get("tunnel_proto")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let route = format!("{cost} {tunnel}").to_ascii_lowercase();
        anyhow::ensure!(
            route.contains("p2p") || route.contains("direct"),
            "{node} sees {expect_peer}, but route is not direct/p2p: {route}"
        );
        anyhow::ensure!(
            !route.contains("relay"),
            "{node} sees {expect_peer}, but route still uses relay: {route}"
        );
        return Ok(());
    }
    anyhow::bail!("{node} did not find expected peer substring '{expect_peer}'")
}

/// Parse a comma-separated list of IPv4 CIDRs into (network, mask) u32 pairs.
fn parse_overlay_cidrs(spec: &str) -> Vec<(u32, u32)> {
    spec.split(',')
        .filter_map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() {
                return None;
            }
            let (ip, prefix) = entry.split_once('/')?;
            let base: std::net::Ipv4Addr = ip.trim().parse().ok()?;
            let prefix: u32 = prefix.trim().parse().ok()?;
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix.min(32))
            };
            Some((u32::from(base) & mask, mask))
        })
        .collect()
}

fn ipv4_in_overlay(ip: std::net::Ipv4Addr, cidrs: &[(u32, u32)]) -> bool {
    let value = u32::from(ip);
    cidrs.iter().any(|(net, mask)| (value & mask) == *net)
}

/// Resolve the numeric peer_id from `peer list -o json` for a hostname substring.
fn peer_id_for(peer_json: &str, expect_peer: &str) -> Option<String> {
    let peers: serde_json::Value = serde_json::from_str(peer_json).ok()?;
    for row in peers.as_array()? {
        if row
            .to_string()
            .to_ascii_lowercase()
            .contains(&expect_peer.to_ascii_lowercase())
            && let Some(id) = row.get("id").and_then(|v| v.as_str())
        {
            return Some(id.to_owned());
        }
    }
    None
}

/// Extract the numeric `dst_peer_id` from a `new peer connection added` log line.
fn line_dst_peer_id(line: &str) -> Option<&str> {
    let start = line.find("dst_peer_id: ")? + "dst_peer_id: ".len();
    let rest = &line[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    (end > 0).then(|| &rest[..end])
}

/// Extract the remote_addr IPv4 from a conn-added log line (ignores local_addr).
fn line_remote_ipv4(line: &str) -> Option<std::net::Ipv4Addr> {
    let key = "remote_addr: Some(Url { url: \"";
    let start = line.find(key)? + key.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    let host = rest[..end].split("://").nth(1)?;
    let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    host.parse().ok()
}

/// Assert the node has at least one direct conn to `expect_peer` whose remote_addr
/// is a physical (non-overlay, non-loopback) address.
fn assert_physical_direct(
    node: &str,
    peer_json: &str,
    conn_log: &str,
    expect_peer: &str,
    overlay_cidrs: &[(u32, u32)],
) -> Result<(), Error> {
    let id = peer_id_for(peer_json, expect_peer)
        .ok_or_else(|| anyhow::anyhow!("{node}: could not resolve peer_id for '{expect_peer}'"))?;
    let mut saw_direct = false;
    for line in conn_log.lines() {
        if line_dst_peer_id(line) != Some(id.as_str()) {
            continue;
        }
        let Some(ip) = line_remote_ipv4(line) else {
            continue;
        };
        saw_direct = true;
        if !ip.is_loopback() && !ip.is_unspecified() && !ipv4_in_overlay(ip, overlay_cidrs) {
            return Ok(());
        }
    }
    if saw_direct {
        anyhow::bail!(
            "{node}: only overlay/loopback direct conns to '{expect_peer}' (peer_id {id}); no physical-NIC path"
        );
    }
    anyhow::bail!("{node}: no peer-connection record to '{expect_peer}' (peer_id {id})")
}

fn assert_physical_direct_any(
    node: &str,
    peer_json: &str,
    conn_log: &str,
    candidates: &[&str],
    overlay_cidrs: &[(u32, u32)],
) -> Result<(), Error> {
    // Candidates are alternate names for the SAME peer. Once any name resolves
    // to a peer_id we have found it; its physical verdict is final and must not
    // be masked by a later name that simply fails to resolve.
    let mut last: Option<Error> = None;
    for candidate in candidates {
        if peer_id_for(peer_json, candidate).is_some() {
            return assert_physical_direct(node, peer_json, conn_log, candidate, overlay_cidrs);
        }
        last = Some(anyhow::anyhow!(
            "{node}: could not resolve peer_id for '{candidate}'"
        ));
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("{node}: no candidate peer matched")))
}

fn collect_conn_events_local(log: &str) -> Result<String, Error> {
    run_local_sh(&format!(
        "grep -a 'new peer connection added' {} 2>/dev/null | tail -n 200 || true",
        sh_quote(log)
    ))
}

fn collect_conn_events_windows(host: &str, log: &str) -> Result<String, Error> {
    let script = format!(
        "if (Test-Path {log}) {{ Select-String -Path {log} -Pattern 'new peer connection added' -SimpleMatch | Select-Object -Last 200 | ForEach-Object {{ $_.Line }} }}",
        log = ps_quote(log)
    );
    ssh_capture_powershell(host, &script)
}

/// Both B and C must carry a physical (non-overlay) direct conn to the other.
fn verify_bc_physical_direct(
    options: &LabRemoteFreshRunOptions,
    b_peer_json: &str,
    c_peer_json: &str,
    overlay_cidrs: &[(u32, u32)],
) -> Result<(), Error> {
    let b_events = collect_conn_events_local(&options.b_log)?;
    let c_events = collect_conn_events_windows(&options.c_host, &options.c_log)?;
    assert_physical_direct_any("B", b_peer_json, &b_events, &["LAPTOP", "win-c"], overlay_cidrs)?;
    assert_physical_direct_any("C", c_peer_json, &c_events, &["user", "node-b"], overlay_cidrs)?;
    Ok(())
}

fn ssh_capture_powershell(host: &str, script: &str) -> Result<String, Error> {
    ssh_capture(host, &powershell_encoded_command(script))
}

fn powershell_encoded_command(script: &str) -> String {
    let script = format!(
        "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop'; {}",
        script
    );
    let mut bytes = Vec::with_capacity(script.len() * 2);
    for unit in script.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let encoded = BASE64_STANDARD.encode(bytes);
    format!("powershell -NoProfile -EncodedCommand {encoded}")
}

fn ssh_capture_sh(host: &str, script: &str) -> Result<String, Error> {
    let encoded = BASE64_STANDARD.encode(script.as_bytes());
    ssh_capture(
        host,
        &format!("printf %s {} | base64 -d | sh", sh_quote(&encoded)),
    )
}

fn run_local_sh(script: &str) -> Result<String, Error> {
    let encoded = BASE64_STANDARD.encode(script.as_bytes());
    local_capture(&format!(
        "printf %s {} | base64 -d | sh",
        sh_quote(&encoded)
    ))
}

fn parse_json_field(output: &str, field: &str) -> Result<String, Error> {
    for line in output.lines().rev() {
        let trimmed = line.trim();
        if !trimmed.starts_with('{') {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(trimmed)
            .with_context(|| format!("failed to parse JSON line: {trimmed}"))?;
        if let Some(text) = value.get(field).and_then(|value| value.as_str()) {
            return Ok(text.to_owned());
        }
    }
    anyhow::bail!("field '{field}' not found in JSON output: {output}")
}

fn local_capture(command: &str) -> Result<String, Error> {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .with_context(|| format!("failed to run local command: {command}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "local command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_status(label: &str, program: &str, args: &[String]) -> Result<(), Error> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {label}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "{label} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn trim_remote_output(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.trim().to_string();
    }
    let mut tail: String = value.chars().rev().take(max_chars).collect();
    tail = tail.chars().rev().collect();
    format!("...\n{}", tail.trim())
}

fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn cmd_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\\\""))
}

fn parent_path_unix(path: &str) -> String {
    path.rsplit_once('/')
        .map(|(parent, _)| parent)
        .unwrap_or(".")
        .to_string()
}

fn parent_path_windows(path: &str) -> String {
    path.rsplit_once('\\')
        .map(|(parent, _)| parent)
        .unwrap_or(".")
        .to_string()
}

fn common_parent_path_windows(left: &str, right: &str) -> String {
    let left_parts = left.split('\\').collect::<Vec<_>>();
    let right_parts = right.split('\\').collect::<Vec<_>>();
    let mut common = Vec::new();
    for (left, right) in left_parts.iter().zip(right_parts.iter()) {
        if left.eq_ignore_ascii_case(right) {
            common.push(*left);
        } else {
            break;
        }
    }
    if common.is_empty() {
        parent_path_windows(left)
    } else {
        common.join("\\")
    }
}

fn ssh_capture(host: &str, command: &str) -> Result<String, Error> {
    let output = std::process::Command::new("timeout")
        .args([
            "30",
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=8",
            host,
            command,
        ])
        .output()
        .with_context(|| format!("failed to run ssh for {host}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "ssh {host} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[allow(clippy::too_many_arguments)]
async fn handle_lab_member_toggle(
    handler: &CommandHandler<'_>,
    trust_domain_id: String,
    network_local_id: String,
    device: Option<String>,
    disable: bool,
    until: Option<String>,
    note: Option<String>,
    json: bool,
    passphrase_file: Option<PathBuf>,
) -> Result<(), Error> {
    let (network_dir, _pem, state) =
        load_network_state_for_edit(&trust_domain_id, &network_local_id)?;
    let rows = collect_member_list_rows(&network_dir, &state, &network_local_id)
        .into_iter()
        .filter(|row| row.status.as_str() != "revoked")
        .collect::<Vec<_>>();
    let selector = if let Some(device) = device {
        device
    } else {
        if rows.is_empty() {
            anyhow::bail!("no members found");
        }
        for (idx, row) in rows.iter().enumerate() {
            println!(
                "{}. {} label={} status={} fingerprint={}",
                idx + 1,
                shorten_id(&row.device_id),
                row.device_label,
                row.status.as_str(),
                row.fingerprint.chars().take(8).collect::<String>()
            );
        }
        if !std::io::stdin().is_terminal() {
            anyhow::bail!(
                "pass --device <device-id-or-fingerprint-prefix> in non-interactive mode"
            );
        }
        let answer = prompt_required(if disable {
            "Disable which number/device"
        } else {
            "Enable which number/device"
        })?;
        if let Ok(index) = answer.parse::<usize>() {
            if index == 0 || index > rows.len() {
                anyhow::bail!("selection out of range");
            }
            rows[index - 1].device_id.clone()
        } else {
            answer
        }
    };
    let row = resolve_device_or_fingerprint(rows, &selector)?;
    if disable {
        handle_trust_disable(
            Some(handler),
            trust_domain_id,
            network_local_id,
            row.fingerprint,
            until,
            note,
            json,
            passphrase_file,
        )
        .await
    } else {
        handle_trust_enable(
            Some(handler),
            trust_domain_id,
            network_local_id,
            row.fingerprint,
            json,
            passphrase_file,
        )
        .await
    }
}

fn resolve_device_or_fingerprint(
    rows: Vec<pactmesh::trust::DeviceView>,
    selector: &str,
) -> Result<pactmesh::trust::DeviceView, Error> {
    let matches = rows
        .into_iter()
        .filter(|row| row.device_id.starts_with(selector) || row.fingerprint.starts_with(selector))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => anyhow::bail!("device/fingerprint not found: {selector}"),
        [row] => Ok(row.clone()),
        _ => anyhow::bail!("device/fingerprint selector is ambiguous: {selector}"),
    }
}

async fn handle_lab_approve(
    handler: &CommandHandler<'_>,
    trust_domain_id: String,
    network_local_id: String,
    device: Option<String>,
    json: bool,
    passphrase_file: Option<PathBuf>,
) -> Result<(), Error> {
    let td_id_bytes = parse_url_safe_b64_32(&trust_domain_id, "trust_domain_id")?;
    let client = handler.get_trust_join_manage_client().await?;
    let response = client
        .list_pending_join_requests(
            BaseController::default(),
            ListPendingJoinRequestsRequest {
                instance: Some(handler.instance_selector.clone()),
                trust_domain_id: td_id_bytes.to_vec(),
                network_local_id: network_local_id.clone(),
            },
        )
        .await
        .context("daemon refused to list pending join requests")?;

    let requests = response.requests;
    if requests.is_empty() {
        println!("No pending join requests for {trust_domain_id}/{network_local_id}.");
        return Ok(());
    }

    println!("Pending join requests:");
    for (idx, request) in requests.iter().enumerate() {
        let device_id = encode_device_id(&request.applicant_pk);
        println!(
            "  {}. {} label={} hint={}",
            idx + 1,
            shorten_id(&device_id),
            request.device_label,
            if request.hint.is_empty() {
                "-"
            } else {
                &request.hint
            }
        );
    }

    let selected = if let Some(selector) = device {
        selector
    } else if requests.len() == 1 {
        let device_id = encode_device_id(&requests[0].applicant_pk);
        let answer = prompt_with_default(
            &format!(
                "Approve {} label={}? yes/no",
                shorten_id(&device_id),
                requests[0].device_label
            ),
            "yes",
        )?;
        if !matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("Approval cancelled.");
            return Ok(());
        }
        device_id
    } else {
        if !std::io::stdin().is_terminal() {
            anyhow::bail!("multiple pending requests; pass --device <device-id-prefix>");
        }
        let answer = prompt_required("Approve which number or device id prefix")?;
        if let Ok(index) = answer.parse::<usize>() {
            if index == 0 || index > requests.len() {
                anyhow::bail!("selection out of range");
            }
            encode_device_id(&requests[index - 1].applicant_pk)
        } else {
            answer
        }
    };

    println!("Approving {selected} ...");
    handle_trust_approve(
        handler,
        trust_domain_id,
        network_local_id,
        selected,
        json,
        passphrase_file,
    )
    .await
}

fn shorten_id(id: &str) -> String {
    if id.len() <= 16 {
        id.to_owned()
    } else {
        format!("{}...{}", &id[..10], &id[id.len() - 6..])
    }
}

fn handle_lab_commands(options: LabCommandOptions) -> Result<(), Error> {
    let home_expr = if cfg!(target_os = "windows") {
        format!("$HOME\\{}", options.test_home_name)
    } else {
        format!("$HOME/{}", options.test_home_name)
    };
    println!("# Environment");
    if cfg!(target_os = "windows") {
        println!("$env:PNW_TEST_HOME = \"{home_expr}\"");
        println!("$env:XDG_CONFIG_HOME = \"$env:PNW_TEST_HOME\\xdg\"");
        println!("$env:NETWORK_LOCAL_ID = \"{}\"", options.network_local_id);
        println!("$env:RPC_PORT = \"{}\"", options.rpc_port);
        println!("Remove-Item Env:\\PNW_DEVICE_PASSPHRASE -ErrorAction SilentlyContinue");
        println!("New-Item -ItemType Directory -Force $env:PNW_TEST_HOME | Out-Null");
    } else {
        println!("export PNW_TEST_HOME=\"{home_expr}\"");
        println!("export XDG_CONFIG_HOME=\"$PNW_TEST_HOME/xdg\"");
        println!("export NETWORK_LOCAL_ID=\"{}\"", options.network_local_id);
        println!("export RPC_PORT=\"{}\"", options.rpc_port);
        println!("unset PNW_DEVICE_PASSPHRASE");
        println!("mkdir -p \"$PNW_TEST_HOME\"");
    }
    println!();

    match options.role {
        LabRole::Root => print_lab_root_commands(&options),
        LabRole::Joiner => print_lab_joiner_commands(&options),
    }
}

fn print_lab_root_commands(options: &LabCommandOptions) -> Result<(), Error> {
    let Some(seed) = &options.seed else {
        anyhow::bail!("--seed is required for --role root");
    };
    let td = options
        .trust_domain_id
        .as_deref()
        .unwrap_or("<TRUST_DOMAIN_ID>");
    if cfg!(target_os = "windows") {
        println!("# Root commands are usually run on the public Linux VPS.");
    }
    println!("# Create domain/network when needed, then bootstrap root.");
    println!("./pactmesh trust create-domain --label root-a --json");
    println!(
        "./pactmesh trust create-network \"{td}\" \"{}\" --default-action accept --json",
        options.network_local_id
    );
    println!(
        "./pactmesh trust bootstrap-self \"{td}\" \"{}\" --device-label {} --json",
        options.network_local_id, options.label
    );
    println!(
        "./pactmesh trust invite \"{td}\" \"{}\" --seed \"{seed}\" --format url",
        options.network_local_id
    );
    println!();
    println!("# Start root daemon with TCP+UDP listeners.");
    println!("nohup ./pactmesh-core \\");
    println!("  --network-name \"$NETWORK_LOCAL_ID\" \\");
    println!("  --trust-domain-dir \"$XDG_CONFIG_HOME/privateNetwork/trust-domains/{td}\" \\");
    println!("  --network-local-id \"$NETWORK_LOCAL_ID\" \\");
    println!("  --rpc-portal \"127.0.0.1:$RPC_PORT\" \\");
    println!("  --listeners \"{}\" \\", options.listen_port);
    println!("  --no-tun true \\");
    println!("  --disable-ipv6 true \\");
    println!("  --instance-name {} \\", options.label);
    println!("  --console-log-level info \\");
    println!(
        "  --daemon > \"$PNW_TEST_HOME/{}.log\" 2>&1 &",
        options.label
    );
    Ok(())
}

fn print_lab_joiner_commands(options: &LabCommandOptions) -> Result<(), Error> {
    let Some(invite) = &options.invite else {
        anyhow::bail!("--invite is required for --role joiner");
    };
    if cfg!(target_os = "windows") {
        println!("$INVITE_URL = '{}'", invite.replace('\'', "''"));
        println!(".\\pactmesh.exe trust accept-invite $INVITE_URL `");
        println!("  --device-label {} `", options.label);
        println!("  --online `");
        println!("  --wait-secs 600 `");
        println!("  --poll-secs 2");
        println!();
        print_lab_joiner_daemon_command(options);
        println!();
        println!(".\\pactmesh.exe --rpc-portal \"127.0.0.1:$env:RPC_PORT\" -o json peer list");
    } else {
        println!("INVITE_URL='{}'", invite.replace('\'', "'\\''"));
        println!("./pactmesh trust accept-invite \"$INVITE_URL\" \\");
        println!("  --device-label {} \\", options.label);
        println!("  --online \\");
        println!("  --wait-secs 600 \\");
        println!("  --poll-secs 2");
        println!();
        print_lab_joiner_daemon_command(options);
        println!();
        println!("./pactmesh --rpc-portal \"127.0.0.1:$RPC_PORT\" -o json peer list");
        println!(
            "grep -Ei 'udp hole|tcp hole|syn|sack|stun|relay|listener|error' \"$PNW_TEST_HOME/{}.log\" | tail -200",
            options.label
        );
    }
    Ok(())
}

fn print_lab_joiner_daemon_command(options: &LabCommandOptions) {
    if cfg!(target_os = "windows") {
        println!(".\\pactmesh-core.exe `");
        println!("  --network-name $env:NETWORK_LOCAL_ID `");
        println!("  --network-local-id $env:NETWORK_LOCAL_ID `");
        println!("  --rpc-portal \"127.0.0.1:$env:RPC_PORT\" `");
        println!("  --listeners \"{}\" `", options.listen_port);
        println!("  --no-tun true `");
        println!("  --disable-ipv6 true `");
        println!("  --instance-name {} `", options.label);
        println!("  --console-log-level debug `");
        println!(
            "  --daemon *> \"$env:PNW_TEST_HOME\\{}.log\"",
            options.label
        );
    } else {
        println!("nohup ./pactmesh-core \\");
        println!("  --network-name \"$NETWORK_LOCAL_ID\" \\");
        println!("  --network-local-id \"$NETWORK_LOCAL_ID\" \\");
        println!("  --rpc-portal \"127.0.0.1:$RPC_PORT\" \\");
        println!("  --listeners \"{}\" \\", options.listen_port);
        println!("  --no-tun true \\");
        println!("  --disable-ipv6 true \\");
        println!("  --instance-name {} \\", options.label);
        println!("  --console-log-level debug \\");
        println!(
            "  --daemon > \"$PNW_TEST_HOME/{}.log\" 2>&1 &",
            options.label
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_bootstrap_export(
    domain_dir: PathBuf,
    network_local_id: String,
    format: BootstrapFormat,
    out: Option<PathBuf>,
    bootstrap_seeds: Vec<Url>,
    trust_domain_label: Option<String>,
    network_name: Option<String>,
    description: Option<String>,
) -> Result<(), Error> {
    let network_local_id = NetworkLocalId::try_from_str(&network_local_id)
        .map_err(|err| anyhow::anyhow!("invalid network_local_id: {err}"))?;
    let bootstrap = NetworkBootstrap::export_from_domain_dir(
        &domain_dir,
        network_local_id,
        bootstrap_seeds,
        trust_domain_label,
        network_name,
        description,
    )?;

    match format {
        BootstrapFormat::Url => {
            let url = bootstrap.to_url()?;
            write_or_print_output(out.as_ref(), url.as_str())
        }
        BootstrapFormat::File => {
            let pem = bootstrap.to_pem();
            write_or_print_output(out.as_ref(), &pem)
        }
        BootstrapFormat::Qr => {
            let svg = bootstrap_to_qr_svg(&bootstrap)?;
            write_or_print_output(out.as_ref(), &svg)
        }
    }
}

fn handle_bootstrap_import(domain_dir: PathBuf, source: String) -> Result<(), Error> {
    let bootstrap = parse_bootstrap_source(&source)?;
    bootstrap.import_into_domain_dir(&domain_dir)?;
    println!("wrote {}", domain_dir.join("pk_root.pem").display());
    Ok(())
}

fn handle_trust_invite(
    trust_domain_id: String,
    network_local_id: String,
    seeds: Vec<Url>,
    format: BootstrapFormat,
    out: Option<PathBuf>,
) -> Result<(), Error> {
    if seeds.is_empty() {
        anyhow::bail!("at least one --seed is required");
    }

    let domain_dir = pnw_trust_domains_dir()?.join(&trust_domain_id);
    if !domain_dir.is_dir() {
        anyhow::bail!("trust domain not found: {trust_domain_id}");
    }
    let network_dir = domain_dir.join("networks").join(&network_local_id);
    let state_path = network_dir.join("network_state.cbor.pem");
    let state = std::fs::read_to_string(&state_path)
        .with_context(|| format!("failed to read {}", state_path.display()))?;
    let state = pactmesh::trust::SignedNetworkState::from_pem(&state)
        .with_context(|| format!("failed to parse {}", state_path.display()))?;
    if state.details.trust_domain_id.to_string() != trust_domain_id {
        anyhow::bail!("trust_domain_id does not match network_state");
    }
    if state.details.network_local_id.to_string() != network_local_id {
        anyhow::bail!("network_local_id does not match network_state");
    }

    let bootstrap = NetworkBootstrap::export_from_domain_dir(
        &domain_dir,
        state.details.network_local_id,
        seeds,
        Some(parse_meta_value(
            &std::fs::read_to_string(domain_dir.join("meta.toml")).unwrap_or_default(),
            "label",
        )),
        Some(network_local_id),
        None,
    )?;

    match format {
        BootstrapFormat::Url => {
            let url = bootstrap.to_url()?;
            write_or_print_output(out.as_ref(), url.as_str())
        }
        BootstrapFormat::File => {
            let pem = bootstrap.to_pem();
            write_or_print_output(out.as_ref(), &pem)
        }
        BootstrapFormat::Qr => {
            let svg = bootstrap_to_qr_svg(&bootstrap)?;
            write_or_print_output(out.as_ref(), &svg)
        }
    }
}

fn parse_member_cert_fingerprint(
    value: &str,
) -> Result<pactmesh::trust::MemberCertFingerprint, Error> {
    pactmesh::control::parse_member_cert_fingerprint(value)
}

fn revoke_reason_value(reason: RevokeReasonArg) -> RevocationReason {
    match reason {
        RevokeReasonArg::KeyCompromise => RevocationReason::KeyCompromise,
        RevokeReasonArg::DeviceLost => RevocationReason::DeviceLost,
        RevokeReasonArg::Removed => RevocationReason::Removed,
        RevokeReasonArg::Superseded => RevocationReason::Superseded,
        RevokeReasonArg::Unspecified => RevocationReason::Unspecified,
    }
}

fn handle_trust_revoke(
    trust_domain_id: String,
    network_local_id: String,
    fingerprint: String,
    reason: RevokeReasonArg,
    note: Option<String>,
    passphrase_file: Option<PathBuf>,
) -> Result<(), Error> {
    let domain_dir = pnw_trust_domains_dir()?.join(&trust_domain_id);
    if !domain_dir.is_dir() {
        anyhow::bail!("trust domain not found: {trust_domain_id}");
    }
    let network_dir = domain_dir.join("networks").join(&network_local_id);
    let state_path = network_dir.join("network_state.cbor.pem");
    let original_pem = std::fs::read_to_string(&state_path)
        .with_context(|| format!("failed to read {}", state_path.display()))?;
    let original_state = pactmesh::trust::SignedNetworkState::from_pem(&original_pem)
        .with_context(|| format!("failed to parse {}", state_path.display()))?;
    let fingerprint = parse_member_cert_fingerprint(&fingerprint)?;
    let live = original_state
        .details
        .payload
        .member_cert_index
        .iter()
        .any(|entry| entry.fingerprint == fingerprint);
    if !live {
        anyhow::bail!("fingerprint not found in member_cert_index");
    }

    let passphrase = read_root_passphrase(passphrase_file.as_ref())?;
    let root = TrustDomainRoot::load_from_file(&domain_dir.join("sk_root.age"), &passphrase)
        .with_context(|| {
            format!(
                "failed to unlock {}",
                domain_dir.join("sk_root.age").display()
            )
        })?;
    if root.id().to_string() != trust_domain_id {
        anyhow::bail!("trust_domain_id does not match sk_root.age");
    }

    let revoked_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();
    let next_version = pactmesh::control::commit_signed(
        &network_dir,
        &state_path,
        &original_pem,
        &original_state,
        &root,
        |next, _root| {
            next.payload.revoked_certs.push(pactmesh::trust::RevokedCert {
                cert_fingerprint: fingerprint,
                revoked_at,
                reason_code: revoke_reason_value(reason),
                reason_note: note,
            });
            Ok(())
        },
    )?;

    println!(
        "revoked {}: version {} -> {}",
        fingerprint,
        original_state.details.version,
        next_version
    );
    Ok(())
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

fn member_status(
    fingerprint: &pactmesh::trust::MemberCertFingerprint,
    state: &pactmesh::trust::SignedNetworkState,
) -> &'static str {
    pactmesh::control::member_status(fingerprint, state)
}

fn include_member_status(include: &MemberIncludeArg, status: &str) -> bool {
    match include {
        MemberIncludeArg::Active => status == "active",
        MemberIncludeArg::Disabled => status == "disabled",
        MemberIncludeArg::Revoked => status == "revoked",
        MemberIncludeArg::Expired => status == "expired",
        MemberIncludeArg::All => true,
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct ExternalTrustRow {
    foreign_root_pk_hex: String,
    role: &'static str,
    can_relay_data: bool,
    can_assist_holepunch: bool,
    data_relay_enforcement: &'static str,
    holepunch_assist_enforcement: &'static str,
    expires_at: u64,
    foreign_trust_domain_meta_pem: String,
    foreign_network_state_pem: String,
    foreign_bootstrap_cbor: String,
}

fn handle_trust_list_external(config: PathBuf, json: bool, explain: bool) -> Result<(), Error> {
    let cfg = TomlConfigLoader::new(&config)?;
    let Some(trust_domain) = cfg.get_trust_domain() else {
        if json {
            println!("[]");
        } else {
            println!("(no trust_domain configured)");
        }
        return Ok(());
    };

    let rows = trust_domain
        .relay_serving
        .into_iter()
        .map(|entry| ExternalTrustRow {
            foreign_root_pk_hex: entry.foreign_root_pk_hex,
            role: "external",
            can_relay_data: entry.can_relay_data,
            can_assist_holepunch: entry.can_assist_holepunch,
            data_relay_enforcement: "enforced for borrowed relay sessions",
            holepunch_assist_enforcement: "grant parsed; no cross-trust holepunch assist path currently uses it",
            expires_at: entry.expires_at,
            foreign_trust_domain_meta_pem: entry
                .foreign_trust_domain_meta_pem
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            foreign_network_state_pem: entry
                .foreign_network_state_pem
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            foreign_bootstrap_cbor: entry
                .foreign_bootstrap_cbor
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
        })
        .collect::<Vec<_>>();

    if json {
        println!("{}", serde_json::to_string(&rows)?);
        return Ok(());
    }
    if rows.is_empty() {
        println!("(no external trust domains)");
        return Ok(());
    }
    if explain {
        println!(
            "foreign_root_pk	role	relay_data	assist_holepunch	data_relay_enforcement	holepunch_assist_enforcement	expires_at	meta_pem	network_state_pem	bootstrap"
        );
    } else {
        println!(
            "foreign_root_pk	role	relay_data	assist_holepunch	expires_at	meta_pem	network_state_pem	bootstrap"
        );
    }
    for row in rows {
        let root_prefix = row.foreign_root_pk_hex.chars().take(12).collect::<String>();
        if explain {
            println!(
                "{}	{}	{}	{}	{}	{}	{}	{}	{}	{}",
                root_prefix,
                row.role,
                row.can_relay_data,
                row.can_assist_holepunch,
                row.data_relay_enforcement,
                row.holepunch_assist_enforcement,
                row.expires_at,
                row.foreign_trust_domain_meta_pem,
                row.foreign_network_state_pem,
                row.foreign_bootstrap_cbor
            );
        } else {
            println!(
                "{}	{}	{}	{}	{}	{}	{}	{}",
                root_prefix,
                row.role,
                row.can_relay_data,
                row.can_assist_holepunch,
                row.expires_at,
                row.foreign_trust_domain_meta_pem,
                row.foreign_network_state_pem,
                row.foreign_bootstrap_cbor
            );
        }
    }
    Ok(())
}

fn handle_trust_list_members(
    trust_domain_id: String,
    network_local_id: String,
    include: MemberIncludeArg,
    json: bool,
) -> Result<(), Error> {
    let (network_dir, _pem, state) =
        load_network_state_for_edit(&trust_domain_id, &network_local_id)?;
    let rows = collect_member_list_rows(&network_dir, &state, &network_local_id);
    let rows = rows
        .into_iter()
        .filter(|row| include_member_status(&include, row.status.as_str()))
        .collect::<Vec<_>>();

    if json {
        println!("{}", serde_json::to_string(&rows)?);
        return Ok(());
    }
    if rows.is_empty() {
        println!("(no members)");
        return Ok(());
    }
    println!(
        "device_id\tfingerprint\tdevice_label\trole\tnetwork_local_id\tissued_at\texpires_at\tstatus\tcapabilities\thostname\ttags"
    );
    for row in rows {
        let prefix = row.fingerprint.chars().take(8).collect::<String>();
        let device_id = if row.device_id == "unknown" {
            row.device_id.clone()
        } else {
            row.device_id.chars().take(12).collect::<String>()
        };
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            device_id,
            prefix,
            row.device_label,
            row.role.as_str(),
            row.network_local_id,
            row.issued_at,
            row.expires_at,
            row.status.as_str(),
            row.capabilities.render_compact(),
            row.hostname,
            row.tags.join(",")
        );
    }
    Ok(())
}

fn acl_policy_from_state(state: &pactmesh::trust::SignedNetworkState) -> Result<AclPolicy, Error> {
    from_cbor(&state.details.payload.acl).context("failed to decode network_state ACL policy")
}

fn cert_fingerprint_to_device_fingerprint(
    fingerprint: pactmesh::trust::MemberCertFingerprint,
) -> DeviceFingerprint {
    DeviceFingerprint(fingerprint.0)
}

fn member_fingerprints_for_acl(
    state: &pactmesh::trust::SignedNetworkState,
) -> Vec<DeviceFingerprint> {
    state
        .details
        .payload
        .member_cert_index
        .iter()
        .map(|entry| cert_fingerprint_to_device_fingerprint(entry.fingerprint))
        .collect()
}

fn proxy_cidrs_for_acl(
    network_dir: &std::path::Path,
    state: &pactmesh::trust::SignedNetworkState,
) -> Vec<pactmesh::trust::Cidr> {
    let certs = read_member_cert_bodies(network_dir);
    state
        .details
        .payload
        .member_cert_index
        .iter()
        .filter_map(|entry| certs.get(&entry.fingerprint))
        .flat_map(|cert| cert.details.capabilities.can_proxy_subnet.iter())
        .map(|net| pactmesh::trust::Cidr::new(net.ip(), net.prefix()))
        .collect()
}

fn proxy_cidr_pairs_for_acl(
    network_dir: &std::path::Path,
    state: &pactmesh::trust::SignedNetworkState,
) -> Vec<(DeviceFingerprint, pactmesh::trust::Cidr)> {
    let certs = read_member_cert_bodies(network_dir);
    state
        .details
        .payload
        .member_cert_index
        .iter()
        .filter_map(|entry| {
            let cert = certs.get(&entry.fingerprint)?;
            Some((entry.fingerprint, cert))
        })
        .flat_map(|(fingerprint, cert)| {
            cert.details
                .capabilities
                .can_proxy_subnet
                .iter()
                .map(move |net| {
                    (
                        cert_fingerprint_to_device_fingerprint(fingerprint),
                        pactmesh::trust::Cidr::new(net.ip(), net.prefix()),
                    )
                })
        })
        .collect()
}

fn collect_member_list_rows(
    network_dir: &std::path::Path,
    state: &pactmesh::trust::SignedNetworkState,
    network_local_id: &str,
) -> Vec<pactmesh::trust::DeviceView> {
    pactmesh::control::list_member_views(network_dir, state, network_local_id)
}

fn handle_trust_show_device(
    trust_domain_id: String,
    network_local_id: String,
    device_id: String,
    json: bool,
) -> Result<(), Error> {
    let (network_dir, _pem, state) =
        load_network_state_for_edit(&trust_domain_id, &network_local_id)?;
    let rows = collect_member_list_rows(&network_dir, &state, &network_local_id);
    let row = resolve_device_view(rows, &device_id)?;
    if json {
        println!("{}", serde_json::to_string(&row)?);
    } else {
        println!("device_id: {}", row.device_id);
        println!("fingerprint: {}", row.fingerprint);
        println!("device_label: {}", row.device_label);
        println!("role: {}", row.role.as_str());
        println!("network_local_id: {}", row.network_local_id);
        println!("issued_at: {}", row.issued_at);
        println!("expires_at: {}", row.expires_at);
        println!("status: {}", row.status.as_str());
        println!("capabilities: {}", row.capabilities.render_compact());
        println!("hostname: {}", row.hostname);
    }
    Ok(())
}

fn resolve_device_view(
    rows: Vec<pactmesh::trust::DeviceView>,
    device_id: &str,
) -> Result<pactmesh::trust::DeviceView, Error> {
    let matches = rows
        .into_iter()
        .filter(|row| row.device_id != "unknown" && row.device_id.starts_with(device_id))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => anyhow::bail!("device_id not found: {}", device_id),
        [row] => Ok(row.clone()),
        _ => {
            let candidates = matches
                .iter()
                .map(|row| row.device_id.chars().take(12).collect::<String>())
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "device_id prefix is ambiguous: {} (candidates: {})",
                device_id,
                candidates
            )
        }
    }
}

fn handle_trust_rename_device(
    trust_domain_id: String,
    network_local_id: String,
    device_id: String,
    label: String,
    note: Option<String>,
    json: bool,
    passphrase_file: Option<PathBuf>,
) -> Result<(), Error> {
    if label.trim().is_empty() {
        anyhow::bail!("device label cannot be empty");
    }
    let (network_dir, original_pem, mut state) =
        load_network_state_for_edit(&trust_domain_id, &network_local_id)?;
    let rows = collect_member_list_rows(&network_dir, &state, &network_local_id);
    let row = resolve_device_view(rows, &device_id)?;
    let old_fp = parse_member_cert_fingerprint(&row.fingerprint)?;
    if member_status(&old_fp, &state) == "revoked" {
        anyhow::bail!("fingerprint is revoked");
    }

    let certs = read_member_cert_bodies(&network_dir);
    let old_cert = certs
        .get(&old_fp)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("member cert body not found; cannot rename device"))?;
    if old_cert.details.device_label == label {
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "device_id": row.device_id,
                    "device_label": label,
                    "fingerprint": old_fp.to_string(),
                    "old_version": state.details.version,
                    "new_version": state.details.version,
                    "status": "unchanged",
                })
            );
        } else {
            println!(
                "device label unchanged for {}",
                old_fp.to_string().chars().take(8).collect::<String>()
            );
        }
        return Ok(());
    }

    let root = unlock_domain_root(&trust_domain_id, passphrase_file)?;
    let mut new_details = old_cert.details.clone();
    new_details.device_label = label.clone();
    new_details.network_state_version_ref = state.details.version.saturating_add(1);
    let new_cert = new_details.sign(&root);
    state
        .details
        .payload
        .revoked_certs
        .push(pactmesh::trust::RevokedCert {
            cert_fingerprint: old_fp,
            revoked_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .context("system clock before unix epoch")?
                .as_secs(),
            reason_code: RevocationReason::Superseded,
            reason_note: note,
        });
    replace_member_index_entry(&mut state, old_fp, &new_cert);

    write_reissued_member_cert(&network_dir, &new_cert)?;

    let old_version = state.details.version;
    let new_version = write_signed_network_state(&network_dir, &state, original_pem, &root)?;
    let new_fp = new_cert.fingerprint();
    if json {
        println!(
            "{}",
            serde_json::json!({
                "device_id": row.device_id,
                "device_label": label,
                "old_fingerprint": old_fp.to_string(),
                "new_fingerprint": new_fp.to_string(),
                "old_version": old_version,
                "new_version": new_version,
                "status": "renamed",
            })
        );
    } else {
        println!(
            "Renamed {} to '{}'; old cert revoked as superseded. version {} -> {}",
            old_fp.to_string().chars().take(8).collect::<String>(),
            label,
            old_version,
            new_version
        );
    }
    Ok(())
}

fn write_reissued_member_cert(
    network_dir: &std::path::Path,
    cert: &pactmesh::trust::MemberCert,
) -> Result<(), Error> {
    pactmesh::control::write_reissued_member_cert(network_dir, cert)
}

fn handle_trust_capability_set(options: TrustCapabilitySetOptions) -> Result<(), Error> {
    let (network_dir, original_pem, mut state) =
        load_network_state_for_edit(&options.trust_domain_id, &options.network_local_id)?;
    let old_fp = parse_member_cert_fingerprint(&options.fingerprint)?;
    if !state
        .details
        .payload
        .member_cert_index
        .iter()
        .any(|entry| entry.fingerprint == old_fp)
    {
        anyhow::bail!("fingerprint not found in member_cert_index");
    }
    if member_status(&old_fp, &state) == "revoked" {
        anyhow::bail!("fingerprint is revoked");
    }
    if options.clear_proxy_subnet && !options.proxy_subnet.is_empty() {
        anyhow::bail!("--clear-proxy-subnet cannot be combined with --proxy-subnet");
    }
    let no_change_requested = options.relay_data.is_none()
        && options.relay_control.is_none()
        && !options.clear_proxy_subnet
        && options.proxy_subnet.is_empty();
    if no_change_requested {
        anyhow::bail!("no capability change requested");
    }

    let certs = read_member_cert_bodies(&network_dir);
    let old_cert = certs
        .get(&old_fp)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("member cert body not found; cannot update capabilities"))?;

    let mut capabilities = old_cert.details.capabilities.clone();
    if let Some(relay_data) = options.relay_data {
        capabilities.can_relay_data = relay_data;
    }
    if let Some(relay_control) = options.relay_control {
        capabilities.can_relay_control = relay_control;
    }
    if options.clear_proxy_subnet {
        capabilities.can_proxy_subnet.clear();
    } else if !options.proxy_subnet.is_empty() {
        capabilities.can_proxy_subnet = options.proxy_subnet;
        capabilities
            .can_proxy_subnet
            .sort_by_key(|net| net.to_string());
        capabilities.can_proxy_subnet.dedup();
    }

    if capabilities == old_cert.details.capabilities {
        if options.json {
            println!(
                "{}",
                serde_json::json!({
                    "fingerprint": old_fp.to_string(),
                    "old_version": state.details.version,
                    "new_version": state.details.version,
                    "status": "unchanged",
                })
            );
        } else {
            println!(
                "capabilities unchanged for {}",
                old_fp.to_string().chars().take(8).collect::<String>()
            );
        }
        return Ok(());
    }

    let root = unlock_domain_root(&options.trust_domain_id, options.passphrase_file)?;
    let mut new_details = old_cert.details.clone();
    new_details.capabilities = capabilities;
    new_details.network_state_version_ref = state.details.version.saturating_add(1);
    let new_cert = new_details.sign(&root);
    let new_fp = new_cert.fingerprint();
    state
        .details
        .payload
        .revoked_certs
        .push(pactmesh::trust::RevokedCert {
            cert_fingerprint: old_fp,
            revoked_at: now_unix_secs(),
            reason_code: RevocationReason::Superseded,
            reason_note: options.note,
        });
    replace_member_index_entry(&mut state, old_fp, &new_cert);
    write_reissued_member_cert(&network_dir, &new_cert)?;

    let old_version = state.details.version;
    let new_version = write_signed_network_state(&network_dir, &state, original_pem, &root)?;
    if options.json {
        println!(
            "{}",
            serde_json::json!({
                "old_fingerprint": old_fp.to_string(),
                "new_fingerprint": new_fp.to_string(),
                "old_version": old_version,
                "new_version": new_version,
                "status": "capability-updated",
                "capabilities": {
                    "relay_data": new_cert.details.capabilities.can_relay_data,
                    "relay_control": new_cert.details.capabilities.can_relay_control,
                    "proxy_subnet": new_cert.details.capabilities.can_proxy_subnet.iter().map(|net| net.to_string()).collect::<Vec<_>>(),
                }
            })
        );
    } else {
        println!(
            "Updated capabilities for {}; old cert revoked as superseded. version {} -> {}",
            old_fp.to_string().chars().take(8).collect::<String>(),
            old_version,
            new_version
        );
    }
    Ok(())
}

#[derive(Debug)]
struct TrustCapabilitySetOptions {
    trust_domain_id: String,
    network_local_id: String,
    fingerprint: String,
    relay_data: Option<bool>,
    relay_control: Option<bool>,
    proxy_subnet: Vec<IpNet>,
    clear_proxy_subnet: bool,
    note: Option<String>,
    json: bool,
    passphrase_file: Option<PathBuf>,
}

fn handle_trust_tag_list(
    trust_domain_id: String,
    network_local_id: String,
    json: bool,
) -> Result<(), Error> {
    let (_network_dir, _pem, state) =
        load_network_state_for_edit(&trust_domain_id, &network_local_id)?;
    let policy = acl_policy_from_state(&state)?;
    if json {
        let rows = policy
            .tags
            .iter()
            .map(|(tag, members)| {
                serde_json::json!({
                    "tag": tag.as_str(),
                    "members": members.iter().map(|member| pactmesh::trust::MemberCertFingerprint(member.0).to_string()).collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>();
        println!("{}", serde_json::to_string(&rows)?);
    } else if policy.tags.is_empty() {
        println!("(no tags)");
    } else {
        println!("tag\tmembers");
        for (tag, members) in policy.tags {
            let members = members
                .into_iter()
                .map(|member| pactmesh::trust::MemberCertFingerprint(member.0).to_string())
                .collect::<Vec<_>>()
                .join(",");
            println!("{}\t{}", tag.as_str(), members);
        }
    }
    Ok(())
}

fn handle_trust_tag_update(
    trust_domain_id: String,
    network_local_id: String,
    device_id: String,
    tag: String,
    add: bool,
    json: bool,
    passphrase_file: Option<PathBuf>,
) -> Result<(), Error> {
    let tag = TagName::try_from_str(&tag)?;
    let (network_dir, original_pem, mut state) =
        load_network_state_for_edit(&trust_domain_id, &network_local_id)?;
    let rows = collect_member_list_rows(&network_dir, &state, &network_local_id);
    let row = resolve_device_view(rows, &device_id)?;
    let member_fp = parse_member_cert_fingerprint(&row.fingerprint)?;
    if member_status(&member_fp, &state) == "revoked" {
        anyhow::bail!("fingerprint is revoked");
    }
    let member = cert_fingerprint_to_device_fingerprint(member_fp);
    let mut policy = acl_policy_from_state(&state)?;
    let changed = if add {
        let members = policy.tags.entry(tag.clone()).or_default();
        if members.contains(&member) {
            false
        } else {
            members.push(member);
            members.sort_unstable();
            true
        }
    } else if let Some(members) = policy.tags.get_mut(&tag) {
        let old_len = members.len();
        members.retain(|existing| *existing != member);
        let changed = members.len() != old_len;
        if members.is_empty() {
            policy.tags.remove(&tag);
        }
        changed
    } else {
        false
    };

    if !changed {
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "device_id": row.device_id,
                    "fingerprint": member_fp.to_string(),
                    "tag": tag.as_str(),
                    "old_version": state.details.version,
                    "new_version": state.details.version,
                    "status": "unchanged",
                })
            );
        } else {
            println!("tag unchanged: {}", tag.as_str());
        }
        return Ok(());
    }

    pactmesh::trust::validate_for_signing(
        &policy,
        &member_fingerprints_for_acl(&state),
        &proxy_cidrs_for_acl(&network_dir, &state),
    )?;
    state.details.payload.acl = to_canonical_cbor(&policy);
    let root = unlock_domain_root(&trust_domain_id, passphrase_file)?;
    let old_version = state.details.version;
    let new_version = write_signed_network_state(&network_dir, &state, original_pem, &root)?;
    let status = if add { "tag-added" } else { "tag-removed" };
    if json {
        println!(
            "{}",
            serde_json::json!({
                "device_id": row.device_id,
                "fingerprint": member_fp.to_string(),
                "tag": tag.as_str(),
                "old_version": old_version,
                "new_version": new_version,
                "status": status,
            })
        );
    } else {
        println!(
            "{} {} for {}; version {} -> {}",
            if add { "Added" } else { "Removed" },
            tag.as_str(),
            row.device_id.chars().take(12).collect::<String>(),
            old_version,
            new_version
        );
    }
    Ok(())
}

fn normalize_peer_hint_capabilities(mut capabilities: Vec<String>) -> Vec<String> {
    for capability in &mut capabilities {
        *capability = capability.trim().to_ascii_lowercase();
    }
    capabilities.retain(|capability| !capability.is_empty());
    capabilities.sort();
    capabilities.dedup();
    capabilities
}

fn handle_trust_peer_hint_list(
    trust_domain_id: String,
    network_local_id: String,
    json: bool,
) -> Result<(), Error> {
    let (_network_dir, _pem, state) =
        load_network_state_for_edit(&trust_domain_id, &network_local_id)?;
    let mut hints = state.details.payload.peer_hints;
    hints.sort_by(|left, right| left.url.cmp(&right.url));
    if json {
        let rows = hints
            .into_iter()
            .map(|hint| {
                serde_json::json!({
                    "url": hint.url,
                    "label": hint.label,
                    "capabilities": hint.capabilities,
                    "updated_at": hint.updated_at,
                    "expires_at": hint.expires_at,
                })
            })
            .collect::<Vec<_>>();
        println!("{}", serde_json::to_string(&rows)?);
    } else if hints.is_empty() {
        println!("(no peer hints)");
    } else {
        println!("url\tlabel\tcapabilities\tupdated_at\texpires_at");
        for hint in hints {
            println!(
                "{}\t{}\t{}\t{}\t{}",
                hint.url,
                hint.label.unwrap_or_default(),
                hint.capabilities.join(","),
                hint.updated_at,
                hint.expires_at
                    .map(|value| value.to_string())
                    .unwrap_or_default()
            );
        }
    }
    Ok(())
}

struct PeerHintUpdateOptions {
    trust_domain_id: String,
    network_local_id: String,
    url: Url,
    label: Option<String>,
    capabilities: Vec<String>,
    expires_at: Option<u64>,
    add: bool,
    json: bool,
    passphrase_file: Option<PathBuf>,
}

fn handle_trust_peer_hint_update(options: PeerHintUpdateOptions) -> Result<(), Error> {
    let (network_dir, original_pem, mut state) =
        load_network_state_for_edit(&options.trust_domain_id, &options.network_local_id)?;
    let url = options.url.to_string();
    let old_version = state.details.version;

    let changed = if options.add {
        let hint = PeerHint {
            url: url.clone(),
            label: options.label,
            capabilities: normalize_peer_hint_capabilities(options.capabilities),
            updated_at: now_unix_secs(),
            expires_at: options.expires_at,
        };
        match state
            .details
            .payload
            .peer_hints
            .iter_mut()
            .find(|existing| existing.url == url)
        {
            Some(existing) if *existing == hint => false,
            Some(existing) => {
                *existing = hint;
                true
            }
            None => {
                state.details.payload.peer_hints.push(hint);
                true
            }
        }
    } else {
        let old_len = state.details.payload.peer_hints.len();
        state
            .details
            .payload
            .peer_hints
            .retain(|existing| existing.url != url);
        state.details.payload.peer_hints.len() != old_len
    };

    if !changed {
        if options.json {
            println!(
                "{}",
                serde_json::json!({
                    "url": url,
                    "old_version": old_version,
                    "new_version": old_version,
                    "status": "unchanged",
                })
            );
        } else {
            println!("peer hint unchanged: {url}");
        }
        return Ok(());
    }

    state
        .details
        .payload
        .peer_hints
        .sort_by(|left, right| left.url.cmp(&right.url));
    let root = unlock_domain_root(&options.trust_domain_id, options.passphrase_file)?;
    let new_version = write_signed_network_state(&network_dir, &state, original_pem, &root)?;
    let status = if options.add {
        "peer-hint-added"
    } else {
        "peer-hint-removed"
    };
    if options.json {
        println!(
            "{}",
            serde_json::json!({
                "url": url,
                "old_version": old_version,
                "new_version": new_version,
                "status": status,
            })
        );
    } else {
        println!("{status}: {url}; version {old_version} -> {new_version}");
    }
    Ok(())
}

struct TrustAclExplainOptions {
    trust_domain_id: String,
    network_local_id: String,
    src_device_id: String,
    dst_device_id: String,
    proto: String,
    port: Option<u16>,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    json: bool,
}

fn handle_trust_acl_explain(options: TrustAclExplainOptions) -> Result<(), Error> {
    let (network_dir, _pem, state) =
        load_network_state_for_edit(&options.trust_domain_id, &options.network_local_id)?;
    let policy = acl_policy_from_state(&state)?;
    let rows = collect_member_list_rows(&network_dir, &state, &options.network_local_id);
    let src = resolve_device_view(rows.clone(), &options.src_device_id)?;
    let dst = resolve_device_view(rows, &options.dst_device_id)?;
    let src_fp =
        cert_fingerprint_to_device_fingerprint(parse_member_cert_fingerprint(&src.fingerprint)?);
    let dst_fp =
        cert_fingerprint_to_device_fingerprint(parse_member_cert_fingerprint(&dst.fingerprint)?);
    let packet = PacketTuple {
        src_ip: options.src_ip,
        dst_ip: options.dst_ip,
        proto: parse_acl_proto(&options.proto)?,
        src_port: 0,
        dst_port: options.port.unwrap_or(0),
    };
    let proxy_cidrs = proxy_cidr_pairs_for_acl(&network_dir, &state);
    let src_ctx = PeerMatchContext {
        peer_fp: &src_fp,
        tags: &policy.tags,
        proxy_cidrs: &proxy_cidrs,
    };
    let dst_ctx = PeerMatchContext {
        peer_fp: &dst_fp,
        tags: &policy.tags,
        proxy_cidrs: &proxy_cidrs,
    };
    let decision = decide(&policy, &packet, src_ctx, dst_ctx);
    let explanation = first_matching_acl_rule(&policy, &packet, src_ctx, dst_ctx);
    if options.json {
        println!(
            "{}",
            serde_json::json!({
                "action": acl_action_name(decision),
                "matched_rule": explanation.as_ref().map(|item| item.0),
                "reason": explanation.as_ref().map(|item| item.1.clone()).unwrap_or_else(|| "default policy".to_owned()),
                "default_action": acl_action_name(policy.default_action),
                "src_device_id": src.device_id,
                "dst_device_id": dst.device_id,
                "src_tags": src.tags,
                "dst_tags": dst.tags,
                "proto": options.proto,
                "port": options.port,
            })
        );
    } else {
        println!("action: {}", acl_action_name(decision));
        match explanation {
            Some((idx, reason)) => {
                println!("matched_rule: {}", idx);
                println!("reason: {}", reason);
            }
            None => {
                println!("matched_rule: default");
                println!("reason: no ACL rule matched; default policy applies");
            }
        }
        println!("src: {} tags={}", src.device_id, src.tags.join(","));
        println!("dst: {} tags={}", dst.device_id, dst.tags.join(","));
        println!("proto: {}", options.proto);
        if let Some(port) = options.port {
            println!("port: {}", port);
        }
    }
    Ok(())
}

fn parse_acl_proto(value: &str) -> Result<u8, Error> {
    match value.to_ascii_lowercase().as_str() {
        "icmp" => Ok(1),
        "tcp" => Ok(6),
        "udp" => Ok(17),
        "any" | "*" => Ok(0),
        other => anyhow::bail!("unsupported proto '{other}', expected tcp, udp, icmp, or any"),
    }
}

fn first_matching_acl_rule(
    policy: &AclPolicy,
    packet: &PacketTuple,
    src_ctx: PeerMatchContext<'_>,
    dst_ctx: PeerMatchContext<'_>,
) -> Option<(usize, String)> {
    policy.rules.iter().enumerate().find_map(|(idx, rule)| {
        if acl_rule_matches(rule, packet, src_ctx, dst_ctx) {
            Some((idx, render_acl_rule_reason(rule)))
        } else {
            None
        }
    })
}

fn acl_rule_matches(
    rule: &AclRule,
    packet: &PacketTuple,
    src_ctx: PeerMatchContext<'_>,
    dst_ctx: PeerMatchContext<'_>,
) -> bool {
    let match_src = rule.src.iter().any(|selector| {
        selector_match(
            selector,
            src_ctx.peer_fp,
            packet.src_ip,
            src_ctx.tags,
            src_ctx.proxy_cidrs,
        )
    });
    let match_dst = rule.dst.iter().any(|selector| {
        selector_match(
            selector,
            dst_ctx.peer_fp,
            packet.dst_ip,
            dst_ctx.tags,
            dst_ctx.proxy_cidrs,
        )
    });
    let match_proto = match rule.proto {
        Proto::Wildcard => true,
        Proto::Icmp => packet.proto == 1,
        Proto::Tcp => packet.proto == 6,
        Proto::Udp => packet.proto == 17,
    };
    let match_port = rule.ports.as_ref().is_none_or(|ports| {
        ports.iter().any(|port| match port {
            PortSpec::Single(expected) => *expected == packet.dst_port,
            PortSpec::Range(low, high) => (*low..=*high).contains(&packet.dst_port),
        })
    });
    match_src && match_dst && match_proto && match_port
}

fn render_acl_rule_reason(rule: &AclRule) -> String {
    format!(
        "rule action={} src={} dst={} proto={} ports={}",
        acl_action_name(rule.action),
        render_acl_selectors(&rule.src),
        render_acl_selectors(&rule.dst),
        render_acl_proto(rule.proto),
        render_acl_ports(rule.ports.as_deref())
    )
}

fn render_acl_selectors(selectors: &[AclSelector]) -> String {
    selectors
        .iter()
        .map(render_acl_selector)
        .collect::<Vec<_>>()
        .join("|")
}

fn render_acl_selector(selector: &AclSelector) -> String {
    match selector {
        AclSelector::Wildcard => "*".to_owned(),
        AclSelector::Tag(tag) => format!("tag:{}", tag.as_str()),
        AclSelector::Device(fp) => {
            format!("device:{}", pactmesh::trust::MemberCertFingerprint(fp.0))
        }
        AclSelector::Subnet(cidr) => format!("subnet:{}/{}", cidr.addr, cidr.prefix_len),
        AclSelector::Hostname(hostname) => format!("hostname:{}", hostname.as_str()),
    }
}

fn render_acl_proto(proto: Proto) -> &'static str {
    match proto {
        Proto::Wildcard => "*",
        Proto::Icmp => "icmp",
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    }
}

fn render_acl_ports(ports: Option<&[PortSpec]>) -> String {
    ports
        .map(|ports| {
            ports
                .iter()
                .map(|port| match port {
                    PortSpec::Single(port) => port.to_string(),
                    PortSpec::Range(low, high) => format!("{low}-{high}"),
                })
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_else(|| "*".to_owned())
}

fn read_member_cert_bodies(
    network_dir: &std::path::Path,
) -> BTreeMap<pactmesh::trust::MemberCertFingerprint, pactmesh::trust::MemberCert> {
    pactmesh::control::read_member_cert_bodies(network_dir)
}

fn live_hostname_entries(
    state: &pactmesh::trust::SignedNetworkState,
    certs: &BTreeMap<pactmesh::trust::MemberCertFingerprint, pactmesh::trust::MemberCert>,
    target: pactmesh::trust::MemberCertFingerprint,
) -> Vec<(
    pactmesh::trust::MemberCertFingerprint,
    Option<HostnameLabel>,
)> {
    pactmesh::control::live_hostname_entries(state, certs, target)
}

fn replace_member_index_entry(
    state: &mut pactmesh::trust::SignedNetworkState,
    old_fp: pactmesh::trust::MemberCertFingerprint,
    cert: &pactmesh::trust::MemberCert,
) {
    pactmesh::control::replace_member_index_entry(
        &mut state.details.payload.member_cert_index,
        old_fp,
        cert,
    );
}

fn handle_trust_hostname_update(
    trust_domain_id: String,
    network_local_id: String,
    fingerprint: String,
    hostname: Option<String>,
    note: Option<String>,
    passphrase_file: Option<PathBuf>,
) -> Result<(), Error> {
    let (network_dir, original_pem, mut state) =
        load_network_state_for_edit(&trust_domain_id, &network_local_id)?;
    let old_fp = parse_member_cert_fingerprint(&fingerprint)?;
    if !state
        .details
        .payload
        .member_cert_index
        .iter()
        .any(|entry| entry.fingerprint == old_fp)
    {
        anyhow::bail!("fingerprint not found in member_cert_index");
    }
    if member_status(&old_fp, &state) == "revoked" {
        anyhow::bail!("fingerprint is revoked");
    }

    let certs = read_member_cert_bodies(&network_dir);
    let old_cert = certs
        .get(&old_fp)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("member cert body not found; cannot reissue hostname"))?;
    let new_hostname = hostname
        .map(|hostname| HostnameLabel::try_from_str(&hostname))
        .transpose()?;
    if old_cert.details.hostname == new_hostname {
        println!(
            "hostname unchanged for {}",
            old_fp.to_string().chars().take(8).collect::<String>()
        );
        return Ok(());
    }
    if let Some(hostname) = new_hostname.as_ref() {
        check_hostname_unique(hostname, &live_hostname_entries(&state, &certs, old_fp))?;
    }

    let root = unlock_domain_root(&trust_domain_id, passphrase_file)?;
    let mut new_details = old_cert.details.clone();
    new_details.hostname = new_hostname.clone();
    new_details.network_state_version_ref = state.details.version.saturating_add(1);
    let new_cert = new_details.sign(&root);
    state
        .details
        .payload
        .revoked_certs
        .push(pactmesh::trust::RevokedCert {
            cert_fingerprint: old_fp,
            revoked_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .context("system clock before unix epoch")?
                .as_secs(),
            reason_code: RevocationReason::Superseded,
            reason_note: note,
        });
    replace_member_index_entry(&mut state, old_fp, &new_cert);

    write_reissued_member_cert(&network_dir, &new_cert)?;

    let old_version = state.details.version;
    let new_version = write_signed_network_state(&network_dir, &state, original_pem, &root)?;
    match new_hostname {
        Some(hostname) => println!(
            "Hostname '{}' assigned to {}; old cert revoked as superseded. version {} -> {}",
            hostname,
            old_fp.to_string().chars().take(8).collect::<String>(),
            old_version,
            new_version
        ),
        None => println!(
            "Hostname removed from {}; old cert revoked as superseded. version {} -> {}",
            old_fp.to_string().chars().take(8).collect::<String>(),
            old_version,
            new_version
        ),
    }
    Ok(())
}

fn parse_disable_until(value: Option<String>) -> Result<Option<u64>, Error> {
    value
        .map(|value| {
            let timestamp = chrono::DateTime::parse_from_rfc3339(&value)
                .with_context(|| format!("invalid --until '{value}', expected RFC3339"))?
                .timestamp();
            u64::try_from(timestamp)
                .map_err(|_| anyhow::anyhow!("--until must be after unix epoch"))
        })
        .transpose()
}

fn write_signed_network_state(
    network_dir: &std::path::Path,
    original_state: &pactmesh::trust::SignedNetworkState,
    original_pem: String,
    root: &TrustDomainRoot,
) -> Result<u64, Error> {
    let next_state = sign_next_network_state(original_state, root);
    write_pre_signed_network_state(
        network_dir,
        original_state.details.version,
        original_pem,
        &next_state,
    )
}

fn sign_next_network_state(
    original_state: &pactmesh::trust::SignedNetworkState,
    root: &TrustDomainRoot,
) -> pactmesh::trust::SignedNetworkState {
    let mut next_state = original_state.details.clone();
    next_state.version = next_state.version.saturating_add(1);
    next_state.sign(root)
}

fn write_pre_signed_network_state(
    network_dir: &std::path::Path,
    previous_version: u64,
    original_pem: String,
    next_state: &pactmesh::trust::SignedNetworkState,
) -> Result<u64, Error> {
    let state_path = network_dir.join("network_state.cbor.pem");
    pactmesh::control::write_state_with_backup(
        network_dir,
        &state_path,
        previous_version,
        &original_pem,
        next_state,
    )
}

fn load_network_state_for_edit(
    trust_domain_id: &str,
    network_local_id: &str,
) -> Result<(PathBuf, String, pactmesh::trust::SignedNetworkState), Error> {
    pactmesh::control::read_network_state(trust_domain_id, network_local_id)
}

fn unlock_domain_root(
    trust_domain_id: &str,
    passphrase_file: Option<PathBuf>,
) -> Result<TrustDomainRoot, Error> {
    let domain_dir = pnw_trust_domains_dir()?.join(trust_domain_id);
    let passphrase = read_root_passphrase(passphrase_file.as_ref())?;
    let root = TrustDomainRoot::load_from_file(&domain_dir.join("sk_root.age"), &passphrase)
        .with_context(|| {
            format!(
                "failed to unlock {}",
                domain_dir.join("sk_root.age").display()
            )
        })?;
    if root.id().to_string() != trust_domain_id {
        anyhow::bail!("trust_domain_id does not match sk_root.age");
    }
    Ok(root)
}

#[allow(clippy::too_many_arguments)]
async fn handle_trust_disable(
    handler: Option<&CommandHandler<'_>>,
    trust_domain_id: String,
    network_local_id: String,
    fingerprint: String,
    until: Option<String>,
    note: Option<String>,
    json: bool,
    passphrase_file: Option<PathBuf>,
) -> Result<(), Error> {
    let (network_dir, original_pem, mut original_state) =
        load_network_state_for_edit(&trust_domain_id, &network_local_id)?;
    let fingerprint = parse_member_cert_fingerprint(&fingerprint)?;
    if original_state
        .details
        .payload
        .revoked_certs
        .iter()
        .any(|revoked| revoked.cert_fingerprint == fingerprint)
    {
        anyhow::bail!("fingerprint is permanently revoked; use revoke instead");
    }
    if !original_state
        .details
        .payload
        .member_cert_index
        .iter()
        .any(|entry| entry.fingerprint == fingerprint)
    {
        anyhow::bail!("fingerprint not found in member_cert_index");
    }

    let root = unlock_domain_root(&trust_domain_id, passphrase_file)?;
    let disabled_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();
    original_state
        .details
        .payload
        .disabled_certs
        .retain(|disabled| disabled.cert_fingerprint != fingerprint);
    original_state
        .details
        .payload
        .disabled_certs
        .push(pactmesh::trust::DisabledCert {
            cert_fingerprint: fingerprint,
            disabled_at,
            expected_until: parse_disable_until(until)?,
            reason_note: note,
        });
    let old_version = original_state.details.version;
    let next_state = sign_next_network_state(&original_state, &root);
    let new_version =
        write_pre_signed_network_state(&network_dir, old_version, original_pem, &next_state)?;
    if let Some(handler) = handler
        && let Err(err) = handler.apply_network_state_to_daemon(&next_state).await
    {
        eprintln!(
            "warning: network_state written to disk but not hot-loaded into running daemon: {err:#}"
        );
    }

    if json {
        println!(
            "{}",
            serde_json::json!({
                "fingerprint": fingerprint.to_string(),
                "old_version": old_version,
                "new_version": new_version,
                "status": "disabled",
            })
        );
    } else {
        println!(
            "disabled {}: version {} -> {}",
            fingerprint, old_version, new_version
        );
    }
    Ok(())
}

async fn handle_trust_enable(
    handler: Option<&CommandHandler<'_>>,
    trust_domain_id: String,
    network_local_id: String,
    fingerprint: String,
    json: bool,
    passphrase_file: Option<PathBuf>,
) -> Result<(), Error> {
    let (network_dir, original_pem, mut original_state) =
        load_network_state_for_edit(&trust_domain_id, &network_local_id)?;
    let fingerprint = parse_member_cert_fingerprint(&fingerprint)?;
    if original_state
        .details
        .payload
        .revoked_certs
        .iter()
        .any(|revoked| revoked.cert_fingerprint == fingerprint)
    {
        anyhow::bail!("fingerprint is permanently revoked and cannot be enabled");
    }
    let old_len = original_state.details.payload.disabled_certs.len();
    original_state
        .details
        .payload
        .disabled_certs
        .retain(|disabled| disabled.cert_fingerprint != fingerprint);
    if original_state.details.payload.disabled_certs.len() == old_len {
        anyhow::bail!("fingerprint is not disabled");
    }

    let root = unlock_domain_root(&trust_domain_id, passphrase_file)?;
    let old_version = original_state.details.version;
    let next_state = sign_next_network_state(&original_state, &root);
    let new_version =
        write_pre_signed_network_state(&network_dir, old_version, original_pem, &next_state)?;
    if let Some(handler) = handler
        && let Err(err) = handler.apply_network_state_to_daemon(&next_state).await
    {
        eprintln!(
            "warning: network_state written to disk but not hot-loaded into running daemon: {err:#}"
        );
    }

    if json {
        println!(
            "{}",
            serde_json::json!({
                "fingerprint": fingerprint.to_string(),
                "old_version": old_version,
                "new_version": new_version,
                "status": "active",
            })
        );
    } else {
        println!(
            "enabled {}: version {} -> {}",
            fingerprint, old_version, new_version
        );
    }
    Ok(())
}

// 主控指派/清除设备固定虚拟 IPv4：写入 root 签名的 network_state.ip_assignments
// （键=稳定 device_id，不重签证书），与控制器 /api/assigned-ipv4 同源。ipv4=None 清除。
async fn handle_trust_assigned_ipv4(
    handler: Option<&CommandHandler<'_>>,
    trust_domain_id: String,
    network_local_id: String,
    fingerprint: String,
    ipv4: Option<String>,
    json: bool,
    passphrase_file: Option<PathBuf>,
) -> Result<(), Error> {
    let (network_dir, original_pem, mut original_state) =
        load_network_state_for_edit(&trust_domain_id, &network_local_id)?;
    let fingerprint = parse_member_cert_fingerprint(&fingerprint)?;
    if !original_state
        .details
        .payload
        .member_cert_index
        .iter()
        .any(|entry| entry.fingerprint == fingerprint)
    {
        anyhow::bail!("fingerprint not found in member_cert_index");
    }
    let cert = pactmesh::control::read_member_cert_bodies(&network_dir)
        .get(&fingerprint)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("member cert body not found; cannot resolve device id"))?;
    let device_id = pactmesh::trust::encode_device_id(cert.details.device_pk.as_bytes());

    let assign = match ipv4.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(cidr) => {
            let inet = Ipv4Inet::from_str(cidr)
                .with_context(|| format!("invalid ipv4 cidr '{cidr}'"))?;
            Some(pactmesh::trust::AssignedIpv4 {
                addr: u32::from(inet.address()),
                prefix: inet.network_length(),
            })
        }
        None => None,
    };

    let current = original_state
        .details
        .payload
        .ip_assignments
        .iter()
        .find(|a| a.device_id == device_id)
        .map(|a| a.ipv4);
    let old_version = original_state.details.version;
    if current == assign {
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "device_id": device_id,
                    "old_version": old_version,
                    "new_version": old_version,
                    "assigned_ipv4": assign.map(|a| format!("{}/{}", a.ipv4_addr(), a.prefix)),
                    "changed": false,
                })
            );
        } else {
            println!("assigned-ipv4 unchanged for {device_id}: version {old_version}");
        }
        return Ok(());
    }

    original_state
        .details
        .payload
        .ip_assignments
        .retain(|a| a.device_id != device_id);
    if let Some(ipv4) = assign {
        original_state
            .details
            .payload
            .ip_assignments
            .push(pactmesh::trust::IpAssignment {
                device_id: device_id.clone(),
                ipv4,
            });
    }

    let root = unlock_domain_root(&trust_domain_id, passphrase_file)?;
    let next_state = sign_next_network_state(&original_state, &root);
    let new_version =
        write_pre_signed_network_state(&network_dir, old_version, original_pem, &next_state)?;
    if let Some(handler) = handler
        && let Err(err) = handler.apply_network_state_to_daemon(&next_state).await
    {
        eprintln!(
            "warning: network_state written to disk but not hot-loaded into running daemon: {err:#}"
        );
    }

    let assigned_str = assign.map(|a| format!("{}/{}", a.ipv4_addr(), a.prefix));
    if json {
        println!(
            "{}",
            serde_json::json!({
                "device_id": device_id,
                "old_version": old_version,
                "new_version": new_version,
                "assigned_ipv4": assigned_str,
                "changed": true,
            })
        );
    } else {
        match assigned_str {
            Some(ip) => println!(
                "assigned {ip} to {device_id}: version {old_version} -> {new_version}"
            ),
            None => println!(
                "cleared assignment for {device_id}: version {old_version} -> {new_version}"
            ),
        }
    }
    Ok(())
}

struct AcceptInviteOptions {
    source: String,
    device_label: Option<String>,
    hint: String,
    passphrase_file: Option<PathBuf>,
    online: bool,
    wait_secs: u64,
    poll_secs: u64,
}

fn read_optional_device_passphrase(
    passphrase_file: Option<&PathBuf>,
) -> Result<Option<String>, Error> {
    let Some(passphrase) = (if let Some(path) = passphrase_file {
        Some(
            std::fs::read_to_string(path)
                .with_context(|| format!("failed to read passphrase file {}", path.display()))?,
        )
    } else {
        std::env::var("PNW_DEVICE_PASSPHRASE").ok()
    }) else {
        return Ok(None);
    };
    let passphrase = passphrase.trim_end_matches(['\r', '\n']).to_owned();
    if passphrase.len() < 8 {
        anyhow::bail!("device key passphrase must be at least 8 characters");
    }
    Ok(Some(passphrase))
}

fn seal_device_sign_key(sk_self: &SignKey, password: &str) -> Result<Vec<u8>, Error> {
    let mut recipient =
        age::scrypt::Recipient::new(age::secrecy::SecretString::from(password.to_owned()));
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

fn load_device_sign_key(path: &std::path::Path, password: &str) -> Result<SignKey, Error> {
    let blob = std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let decryptor =
        age::Decryptor::new(&blob[..]).context("failed to parse device key age file")?;
    let identity =
        age::scrypt::Identity::new(age::secrecy::SecretString::from(password.to_owned()));
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

fn load_or_create_global_device_identity(
    password: Option<&str>,
) -> Result<(SignKey, String, PathBuf, &'static str), Error> {
    let device_dir = pnw_config_dir()?.join("devices/default");
    let age_path = device_dir.join(SK_SELF_AGE_FILE);
    if age_path.exists() {
        let password = password.ok_or_else(|| {
            anyhow::anyhow!(
                "PNW_DEVICE_PASSPHRASE or --passphrase-file is required for existing sk_self.age"
            )
        })?;
        let sk_self = load_device_sign_key(&age_path, password)?;
        let device_pk = sk_self.verify_key();
        let pk_path = device_dir.join("pk_self.pem");
        if pk_path.exists() {
            let pem = std::fs::read_to_string(&pk_path)
                .with_context(|| format!("failed to read {}", pk_path.display()))?;
            let stored = pactmesh::trust::unwrap_armored(&pem, "PNW-PK-SELF")
                .with_context(|| format!("failed to parse {}", pk_path.display()))?;
            if stored.as_slice() != device_pk.0 {
                anyhow::bail!("global device pk_self.pem does not match sk_self.age");
            }
        }
        let device_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(device_pk.0);
        return Ok((sk_self, device_id, device_dir, SK_SELF_AGE_FILE));
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
        let device_pk = sk_self.verify_key();
        let device_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(device_pk.0);
        return Ok((sk_self, device_id, device_dir, SK_SELF_RAW_FILE));
    }

    std::fs::create_dir_all(&device_dir)
        .with_context(|| format!("failed to create {}", device_dir.display()))?;
    let sk_self = SignKey::generate();
    let device_pk = sk_self.verify_key();
    let device_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(device_pk.0);
    let key_file = if let Some(password) = password {
        std::fs::write(&age_path, seal_device_sign_key(&sk_self, password)?)
            .with_context(|| format!("failed to write {}", age_path.display()))?;
        SK_SELF_AGE_FILE
    } else {
        write_raw_sk_self(&raw_path, &sk_self)
            .with_context(|| format!("failed to write {}", raw_path.display()))?;
        SK_SELF_RAW_FILE
    };
    std::fs::write(
        device_dir.join("pk_self.pem"),
        wrap_armored("PNW-PK-SELF", &device_pk.0),
    )
    .with_context(|| {
        format!(
            "failed to write {}",
            device_dir.join("pk_self.pem").display()
        )
    })?;
    Ok((sk_self, device_id, device_dir, key_file))
}

fn copy_device_key_to_network(
    device_dir: &std::path::Path,
    network_dir: &std::path::Path,
    key_file: &str,
) -> Result<(), Error> {
    std::fs::copy(device_dir.join(key_file), network_dir.join(key_file))
        .with_context(|| format!("failed to write {}", network_dir.join(key_file).display()))?;
    Ok(())
}

fn ensure_bootstrap_root(
    domain_dir: &std::path::Path,
    bootstrap: &NetworkBootstrap,
) -> Result<(), Error> {
    std::fs::create_dir_all(domain_dir)
        .with_context(|| format!("failed to create {}", domain_dir.display()))?;
    let pk_root_path = domain_dir.join("pk_root.pem");
    if pk_root_path.exists() {
        let existing_pem = std::fs::read_to_string(&pk_root_path)
            .with_context(|| format!("failed to read {}", pk_root_path.display()))?;
        let existing_bytes = pactmesh::trust::unwrap_armored(&existing_pem, "PNW-PK-ROOT")
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
    std::fs::write(
        &pk_root_path,
        wrap_armored("PNW-PK-ROOT", bootstrap.pk_root.as_bytes()),
    )
    .with_context(|| format!("failed to write {}", pk_root_path.display()))
}

async fn handle_trust_accept_invite(
    handler: &CommandHandler<'_>,
    options: AcceptInviteOptions,
) -> Result<(), Error> {
    let bootstrap = parse_bootstrap_source(&options.source)?;
    bootstrap.verify_self_consistency()?;
    let domain_dir = pnw_trust_domains_dir()?.join(bootstrap.trust_domain_id.to_string());
    ensure_bootstrap_root(&domain_dir, &bootstrap)?;

    let passphrase = read_optional_device_passphrase(options.passphrase_file.as_ref())?;
    let (sk_self, device_id, device_dir, key_file) =
        load_or_create_global_device_identity(passphrase.as_deref())?;

    let network_dir = domain_dir
        .join("networks")
        .join(bootstrap.network_local_id.to_string());
    std::fs::create_dir_all(&network_dir)
        .with_context(|| format!("failed to create {}", network_dir.display()))?;
    std::fs::write(network_dir.join("device_id"), format!("{}\n", device_id)).with_context(
        || {
            format!(
                "failed to write {}",
                network_dir.join("device_id").display()
            )
        },
    )?;
    copy_device_key_to_network(&device_dir, &network_dir, key_file)?;
    std::fs::write(
        network_dir.join("network_bootstrap.cbor.pem"),
        bootstrap.to_pem(),
    )
    .with_context(|| {
        format!(
            "failed to write {}",
            network_dir.join("network_bootstrap.cbor.pem").display()
        )
    })?;
    let jr = JoinRequest::new_signed(
        bootstrap.trust_domain_id,
        bootstrap.network_local_id.clone(),
        &sk_self,
        options
            .device_label
            .unwrap_or_else(|| gethostname::gethostname().to_string_lossy().to_string()),
        options.hint,
    );
    let join_path = network_dir.join("pending_join_request.cbor.pem");
    std::fs::write(
        &join_path,
        wrap_armored("PNW-JOIN-REQUEST", &to_canonical_cbor(&jr)),
    )
    .with_context(|| format!("failed to write {}", join_path.display()))?;

    if options.online {
        submit_join_request_online(
            handler,
            &bootstrap,
            &network_dir,
            &jr,
            options.wait_secs,
            options.poll_secs,
        )
        .await?;
        println!("Device key stored at {}", device_dir.display());
        return Ok(());
    }

    println!("Prepared offline join request at {}", join_path.display());
    println!("Device key stored at {}", device_dir.display());
    println!(
        "Offline mode: transfer this file to a root operator for approval, then import the returned member cert. Omit --offline to submit automatically."
    );
    Ok(())
}

fn derive_join_admission_url(seed: &Url) -> Option<Url> {
    if seed.scheme() != "tcp" {
        return None;
    }
    let port = seed.port()?;
    let admission_port = port.checked_add(1)?;
    let mut admission = seed.clone();
    admission.set_port(Some(admission_port)).ok()?;
    Some(admission)
}

async fn connect_join_admission_client(
    bootstrap: &NetworkBootstrap,
) -> Result<StandAloneClient<TcpTunnelConnector>, Error> {
    let mut last_error = None;
    for seed in &bootstrap.bootstrap_seeds {
        let Some(admission_url) = derive_join_admission_url(seed) else {
            continue;
        };
        let connector = TcpTunnelConnector::new(admission_url.clone());
        let mut client = StandAloneClient::new(connector);
        match client
            .scoped_client::<TrustJoinManageRpcClientFactory<BaseController>>(String::new())
            .await
        {
            Ok(_) => return Ok(client),
            Err(err) => {
                last_error = Some(format!("{admission_url}: {err}"));
            }
        }
    }

    anyhow::bail!(
        "failed to connect to join admission endpoint from invite peer hints{}",
        last_error.map(|err| format!(": {err}")).unwrap_or_default()
    )
}

async fn submit_join_request_online(
    _handler: &CommandHandler<'_>,
    bootstrap: &NetworkBootstrap,
    network_dir: &std::path::Path,
    jr: &JoinRequest,
    wait_secs: u64,
    poll_secs: u64,
) -> Result<(), Error> {
    if poll_secs == 0 {
        anyhow::bail!("--poll-secs must be greater than 0");
    }

    let mut admission_rpc = connect_join_admission_client(bootstrap).await?;
    println!("Connecting to join admission endpoint...");
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

    println!("Waiting for approval...");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait_secs);
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
            let cert_path = network_dir.join("member_cert.pem");
            let cert: pactmesh::trust::MemberCert = from_cbor(&response.member_cert_cbor)
                .context("daemon returned invalid member cert CBOR")?;
            std::fs::write(&cert_path, cert.to_pem())
                .with_context(|| format!("failed to write {}", cert_path.display()))?;
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
            let state_path = network_dir.join("network_state.cbor.pem");
            std::fs::write(&state_path, state.to_pem())
                .with_context(|| format!("failed to write {}", state_path.display()))?;
            println!("Got member cert: {}", cert_path.display());
            return Ok(());
        }

        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for approval");
        }
        tokio::time::sleep(std::time::Duration::from_secs(poll_secs)).await;
    }
}

fn parse_url_safe_b64_32(value: &str, kind: &str) -> Result<[u8; 32], Error> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(value))
        .with_context(|| format!("invalid {kind}: '{value}'"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{kind} must decode to exactly 32 bytes"))
}

fn encode_device_id(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

async fn resolve_pending_applicant_pk(
    handler: &CommandHandler<'_>,
    trust_domain_id: &str,
    network_local_id: &str,
    applicant_selector: &str,
) -> Result<[u8; 32], Error> {
    if let Ok(bytes) = parse_url_safe_b64_32(applicant_selector, "applicant_pk") {
        return Ok(bytes);
    }

    let td_id_bytes = parse_url_safe_b64_32(trust_domain_id, "trust_domain_id")?;
    let client = handler.get_trust_join_manage_client().await?;
    let response = client
        .list_pending_join_requests(
            BaseController::default(),
            ListPendingJoinRequestsRequest {
                instance: Some(handler.instance_selector.clone()),
                trust_domain_id: td_id_bytes.to_vec(),
                network_local_id: network_local_id.to_owned(),
            },
        )
        .await
        .context("daemon refused to list pending join requests")?;

    let matches = response
        .requests
        .iter()
        .filter_map(|request| {
            let device_id = encode_device_id(&request.applicant_pk);
            if device_id.starts_with(applicant_selector) {
                Some((device_id, request.applicant_pk.clone()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    match matches.len() {
        1 => matches[0]
            .1
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("pending applicant_pk must be 32 bytes")),
        0 => anyhow::bail!(
            "no pending device id starts with '{applicant_selector}'; run trust list-pending first"
        ),
        _ => {
            let ids = matches
                .iter()
                .map(|(id, _)| id.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "device id prefix '{applicant_selector}' is ambiguous; matching pending ids: {ids}"
            );
        }
    }
}

async fn resolve_pending_join_summary(
    handler: &CommandHandler<'_>,
    trust_domain_id: &str,
    network_local_id: &str,
    applicant_selector: &str,
) -> Result<pactmesh::proto::api::config::PendingJoinRequestSummary, Error> {
    let td_id_bytes = parse_url_safe_b64_32(trust_domain_id, "trust_domain_id")?;
    let client = handler.get_trust_join_manage_client().await?;
    let response = client
        .list_pending_join_requests(
            BaseController::default(),
            ListPendingJoinRequestsRequest {
                instance: Some(handler.instance_selector.clone()),
                trust_domain_id: td_id_bytes.to_vec(),
                network_local_id: network_local_id.to_owned(),
            },
        )
        .await
        .context("daemon refused to list pending join requests")?;

    let matches = response
        .requests
        .into_iter()
        .filter(|request| {
            let device_id = encode_device_id(&request.applicant_pk);
            device_id.starts_with(applicant_selector)
                || parse_url_safe_b64_32(applicant_selector, "applicant_pk")
                    .map(|bytes| request.applicant_pk.as_slice() == bytes)
                    .unwrap_or(false)
        })
        .collect::<Vec<_>>();

    match matches.len() {
        1 => Ok(matches.into_iter().next().expect("one match")),
        0 => anyhow::bail!(
            "no pending device id starts with '{applicant_selector}'; run trust list-pending first"
        ),
        _ => {
            let ids = matches
                .iter()
                .map(|request| encode_device_id(&request.applicant_pk))
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "device id prefix '{applicant_selector}' is ambiguous; matching pending ids: {ids}"
            );
        }
    }
}

async fn handle_trust_approve(
    handler: &CommandHandler<'_>,
    trust_domain_id: String,
    network_local_id: String,
    applicant_pk_str: String,
    json: bool,
    passphrase_file: Option<PathBuf>,
) -> Result<(), Error> {
    let td_id_bytes = parse_url_safe_b64_32(&trust_domain_id, "trust_domain_id")?;
    let pending = resolve_pending_join_summary(
        handler,
        &trust_domain_id,
        &network_local_id,
        &applicant_pk_str,
    )
    .await?;
    let applicant_pk_bytes: [u8; 32] = pending
        .applicant_pk
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("pending applicant_pk must be 32 bytes"))?;

    let (network_dir, original_pem, mut state) =
        load_network_state_for_edit(&trust_domain_id, &network_local_id)?;
    let root = unlock_domain_root(&trust_domain_id, passphrase_file)?;
    let now = now_unix_secs();
    let cert = pactmesh::trust::UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: NetworkLocalId::try_from_str(&network_local_id)?,
        device_pk: VerifyingKey::from_bytes(&applicant_pk_bytes)
            .context("pending applicant_pk is not a valid ed25519 key")?,
        device_label: pending.device_label,
        not_before: now.saturating_sub(1),
        expires_at: now.saturating_add(365 * 24 * 60 * 60),
        capabilities: pactmesh::trust::Capabilities {
            can_relay_data: false,
            can_relay_control: false,
            can_proxy_subnet: Vec::new(),
            can_be_exit_node: false,
        },
        network_state_version_ref: state.details.version,
        hostname: None,
    }
    .sign(&root);

    let fingerprint = cert.fingerprint();
    let already_indexed = state
        .details
        .payload
        .member_cert_index
        .iter()
        .any(|entry| entry.fingerprint == fingerprint);
    let next_state = if already_indexed {
        None
    } else {
        state
            .details
            .payload
            .member_cert_index
            .push(MemberCertIndexEntry {
                fingerprint,
                device_label: cert.details.device_label.clone(),
                issued_at: cert.details.not_before,
                expires_at: cert.details.expires_at,
            });
        Some(sign_next_network_state(&state, &root))
    };

    let client = handler.get_trust_join_manage_client().await?;
    let response = client
        .approve_join_request(
            BaseController::default(),
            ApproveJoinRequestRequest {
                instance: Some(handler.instance_selector.clone()),
                trust_domain_id: td_id_bytes.to_vec(),
                network_local_id: network_local_id.clone(),
                applicant_pk: applicant_pk_bytes.to_vec(),
                member_cert_cbor: Some(to_canonical_cbor(&cert)),
                network_state_cbor: next_state.as_ref().map(to_canonical_cbor),
            },
        )
        .await
        .context("daemon refused to approve join request")?;

    let cert: pactmesh::trust::MemberCert = from_cbor(&response.member_cert_cbor)
        .context("daemon returned invalid member cert CBOR")?;
    if cert.fingerprint() != fingerprint {
        anyhow::bail!("daemon returned a different member cert than the signed approval");
    }

    let new_version = if let Some(next_state) = next_state {
        write_pre_signed_network_state(
            &network_dir,
            state.details.version,
            original_pem,
            &next_state,
        )?
    } else {
        state.details.version
    };

    let cert_dir = network_dir.join("member_certs");
    std::fs::create_dir_all(&cert_dir)
        .with_context(|| format!("failed to create {}", cert_dir.display()))?;
    let cert_path = cert_dir.join(format!("{fingerprint}.pem"));
    std::fs::write(&cert_path, cert.to_pem())
        .with_context(|| format!("failed to write {}", cert_path.display()))?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "fingerprint": fingerprint.to_string(),
                "device_label": cert.details.device_label,
                "expires_at": cert.details.expires_at,
                "network_state_version": new_version,
                "status": "approved",
            })
        );
    } else {
        let short_fp: String = fingerprint.to_string().chars().take(8).collect();
        println!(
            "approved {} device_label={} expires_at={} network_state version={}",
            short_fp, cert.details.device_label, cert.details.expires_at, new_version
        );
    }
    Ok(())
}

async fn handle_trust_reject(
    handler: &CommandHandler<'_>,
    trust_domain_id: String,
    network_local_id: String,
    applicant_pk_str: String,
) -> Result<(), Error> {
    let td_id_bytes = parse_url_safe_b64_32(&trust_domain_id, "trust_domain_id")?;
    let applicant_pk_bytes = resolve_pending_applicant_pk(
        handler,
        &trust_domain_id,
        &network_local_id,
        &applicant_pk_str,
    )
    .await?;

    let client = handler.get_trust_join_manage_client().await?;
    client
        .reject_join_request(
            BaseController::default(),
            RejectJoinRequestRequest {
                instance: Some(handler.instance_selector.clone()),
                trust_domain_id: td_id_bytes.to_vec(),
                network_local_id,
                applicant_pk: applicant_pk_bytes.to_vec(),
            },
        )
        .await
        .context("daemon refused to reject join request")?;
    println!("rejected applicant_pk={}", applicant_pk_str);
    Ok(())
}

async fn handle_trust_upgrade_peer_to_root(
    handler: &CommandHandler<'_>,
    trust_domain_id: String,
    network_local_id: String,
    peer_id: u32,
    json: bool,
    passphrase_file: Option<PathBuf>,
) -> Result<(), Error> {
    let td_id_bytes = parse_url_safe_b64_32(&trust_domain_id, "trust_domain_id")?;
    let root = unlock_domain_root(&trust_domain_id, passphrase_file)?;
    let client = handler.get_trust_join_manage_client().await?;
    let response = client
        .upgrade_peer_to_root(
            BaseController::default(),
            UpgradePeerToRootRequest {
                instance: Some(handler.instance_selector.clone()),
                trust_domain_id: td_id_bytes.to_vec(),
                network_local_id: network_local_id.clone(),
                peer_id,
                sk_root_payload: root.export_secret_for_root_upgrade().to_vec(),
            },
        )
        .await
        .context("daemon refused to upgrade peer to root")?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "ack": response.ack,
                "peer_id": peer_id,
                "trust_domain_id": trust_domain_id,
                "network_local_id": network_local_id,
            })
        );
    } else {
        println!(
            "upgraded peer_id={} to root holder for trust_domain_id={} network_local_id={}",
            peer_id, trust_domain_id, network_local_id
        );
    }
    Ok(())
}

async fn handle_trust_list_pending(
    handler: &CommandHandler<'_>,
    trust_domain_id: String,
    network_local_id: Option<String>,
    json: bool,
) -> Result<(), Error> {
    let td_id_bytes = parse_url_safe_b64_32(&trust_domain_id, "trust_domain_id")?;
    let nlid = network_local_id.unwrap_or_default();

    let client = handler.get_trust_join_manage_client().await?;
    let response = client
        .list_pending_join_requests(
            BaseController::default(),
            ListPendingJoinRequestsRequest {
                instance: Some(handler.instance_selector.clone()),
                trust_domain_id: td_id_bytes.to_vec(),
                network_local_id: nlid,
            },
        )
        .await
        .context("daemon refused to list pending join requests")?;

    if json {
        let rows: Vec<_> = response
            .requests
            .iter()
            .map(|r| {
                serde_json::json!({
                    "device_id": encode_device_id(&r.applicant_pk),
                    "applicant_pk": encode_device_id(&r.applicant_pk),
                    "trust_domain_id": encode_device_id(&r.trust_domain_id),
                    "network_local_id": r.network_local_id,
                    "device_label": r.device_label,
                    "hint": r.hint,
                })
            })
            .collect();
        println!("{}", serde_json::to_string(&rows)?);
        return Ok(());
    }
    if response.requests.is_empty() {
        println!("(no pending join requests)");
        return Ok(());
    }
    println!("device_id\tdevice_label\thint\tnetwork_local_id");
    for r in &response.requests {
        let device_id = encode_device_id(&r.applicant_pk);
        println!(
            "{}\t{}\t{}\t{}",
            device_id, r.device_label, r.hint, r.network_local_id
        );
    }
    Ok(())
}

fn read_root_passphrase(passphrase_file: Option<&PathBuf>) -> Result<String, Error> {
    let passphrase = match root_passphrase_source(passphrase_file)? {
        RootPassphraseSource::File(path) => std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read passphrase file {}", path.display()))?,
        RootPassphraseSource::Env(value) => value,
        RootPassphraseSource::Prompt => prompt_root_passphrase()?,
    };
    validate_root_passphrase(passphrase)
}

enum RootPassphraseSource {
    File(PathBuf),
    Env(String),
    Prompt,
}

fn root_passphrase_source(
    passphrase_file: Option<&PathBuf>,
) -> Result<RootPassphraseSource, Error> {
    if let Some(path) = passphrase_file {
        return Ok(RootPassphraseSource::File(path.clone()));
    }
    if let Ok(value) = std::env::var("PNW_ROOT_PASSPHRASE") {
        return Ok(RootPassphraseSource::Env(value));
    }
    if std::io::stdin().is_terminal() {
        return Ok(RootPassphraseSource::Prompt);
    }
    anyhow::bail!(
        "PNW_ROOT_PASSPHRASE (root key passphrase/management password) is required unless --passphrase-file is provided; interactive prompt is only available on a TTY"
    )
}

fn prompt_root_passphrase() -> Result<String, Error> {
    let first = prompt_line("Management password (root key passphrase): ")?;
    let second = prompt_line("Confirm management password: ")?;
    if first != second {
        anyhow::bail!("management password confirmation does not match");
    }
    Ok(first)
}

fn prompt_line(prompt: &str) -> Result<String, Error> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    Ok(rpassword::read_password()?)
}

fn validate_root_passphrase(passphrase: String) -> Result<String, Error> {
    let passphrase = passphrase.trim_end_matches(['\r', '\n']).to_owned();
    if passphrase.len() < 8 {
        anyhow::bail!("root key passphrase must be at least 8 characters");
    }
    Ok(passphrase)
}

#[derive(Debug, serde::Serialize)]
struct TrustDomainListRow {
    trust_domain_id: String,
    label: String,
    created_at: String,
    network_count: usize,
    is_root_holder: bool,
}

fn parse_meta_value(meta: &str, key: &str) -> String {
    meta.lines()
        .find_map(|line| {
            let (left, right) = line.split_once('=')?;
            if left.trim() == key {
                Some(right.trim().trim_matches('"').to_owned())
            } else {
                None
            }
        })
        .unwrap_or_default()
}

fn list_trust_domains(base_dir: &std::path::Path) -> Result<Vec<TrustDomainListRow>, Error> {
    if !base_dir.exists() {
        return Ok(Vec::new());
    }
    let mut rows = Vec::new();
    for entry in std::fs::read_dir(base_dir)
        .with_context(|| format!("failed to read {}", base_dir.display()))?
    {
        let path = entry?.path();
        if !path.is_dir() {
            continue;
        }
        let trust_domain_id = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let meta = std::fs::read_to_string(path.join("meta.toml")).unwrap_or_default();
        let network_count = std::fs::read_dir(path.join("networks"))
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter(|entry| entry.path().is_dir())
                    .count()
            })
            .unwrap_or(0);
        rows.push(TrustDomainListRow {
            trust_domain_id,
            label: parse_meta_value(&meta, "label"),
            created_at: parse_meta_value(&meta, "created_at"),
            network_count,
            is_root_holder: path.join("sk_root.age").is_file(),
        });
    }
    rows.sort_by(|left, right| left.trust_domain_id.cmp(&right.trust_domain_id));
    Ok(rows)
}

fn handle_trust_list_domains(json: bool) -> Result<(), Error> {
    let rows = list_trust_domains(&pnw_trust_domains_dir()?)?;
    if json {
        println!("{}", serde_json::to_string(&rows)?);
        return Ok(());
    }
    if rows.is_empty() {
        println!("(no trust domains)");
        return Ok(());
    }
    println!("trust_domain_id\tlabel\tcreated_at\tnetwork_count\tis_root_holder");
    for row in rows {
        let prefix = row.trust_domain_id.chars().take(8).collect::<String>();
        println!(
            "{}\t{}\t{}\t{}\t{}",
            prefix, row.label, row.created_at, row.network_count, row.is_root_holder
        );
    }
    Ok(())
}

fn parse_default_acl_action(value: &str) -> Result<Action, Error> {
    match value {
        "accept" => Ok(Action::Accept),
        "drop" => Ok(Action::Drop),
        _ => anyhow::bail!("unsupported default action '{value}', expected accept or drop"),
    }
}

fn acl_action_name(action: Action) -> &'static str {
    match action {
        Action::Accept => "accept",
        Action::Drop => "drop",
    }
}

fn handle_trust_create_network(
    trust_domain_id: String,
    network_local_id: String,
    default_action: String,
    json: bool,
    passphrase_file: Option<PathBuf>,
) -> Result<(), Error> {
    let domain_dir = pnw_trust_domains_dir()?.join(&trust_domain_id);
    if !domain_dir.is_dir() {
        anyhow::bail!("trust domain not found: {trust_domain_id}");
    }

    let network_local_id = NetworkLocalId::try_from_str(&network_local_id)
        .with_context(|| format!("invalid network_local_id '{network_local_id}'"))?;
    let network_dir = domain_dir
        .join("networks")
        .join(network_local_id.to_string());
    if network_dir.exists() {
        anyhow::bail!("network already exists: {}", network_dir.display());
    }

    let passphrase = read_root_passphrase(passphrase_file.as_ref())?;
    let root = TrustDomainRoot::load_from_file(&domain_dir.join("sk_root.age"), &passphrase)
        .with_context(|| {
            format!(
                "failed to unlock {}",
                domain_dir.join("sk_root.age").display()
            )
        })?;
    if root.id().to_string() != trust_domain_id {
        anyhow::bail!("trust_domain_id does not match sk_root.age");
    }

    let default_action = parse_default_acl_action(&default_action)?;
    let acl = AclPolicy {
        tags: BTreeMap::new(),
        rules: Vec::new(),
        default_action,
        schema_version: ACL_SCHEMA_VERSION,
    };
    let state = UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: network_local_id.clone(),
        version: 1,
        payload: NetworkStatePayload {
            member_cert_index: Vec::new(),
            revoked_certs: Vec::new(),
            disabled_certs: Vec::new(),
            acl: to_canonical_cbor(&acl),
            routes: Vec::new(),
            peer_hints: Vec::new(),
            ip_assignments: Vec::new(),
        },
    }
    .sign(&root);

    std::fs::create_dir_all(&network_dir)
        .with_context(|| format!("failed to create {}", network_dir.display()))?;
    let state_path = network_dir.join("network_state.cbor.pem");
    std::fs::write(&state_path, state.to_pem())
        .with_context(|| format!("failed to write {}", state_path.display()))?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "trust_domain_id": trust_domain_id,
                "network_local_id": network_local_id.to_string(),
                "path": network_dir,
                "version": 1,
                "default_action": acl_action_name(default_action),
            })
        );
    } else {
        println!(
            "Created network {} at {} (version 1, default_action {})",
            network_local_id,
            network_dir.display(),
            acl_action_name(default_action)
        );
    }
    Ok(())
}

struct BootstrapSelfOptions {
    trust_domain_id: String,
    network_local_id: String,
    device_label: Option<String>,
    json: bool,
    passphrase_file: Option<PathBuf>,
    device_passphrase_file: Option<PathBuf>,
}

fn handle_trust_bootstrap_self(options: BootstrapSelfOptions) -> Result<(), Error> {
    let (network_dir, original_pem, mut state) =
        load_network_state_for_edit(&options.trust_domain_id, &options.network_local_id)?;
    let root = unlock_domain_root(&options.trust_domain_id, options.passphrase_file)?;
    if state.details.trust_domain_id != root.id() {
        anyhow::bail!("network_state trust_domain_id does not match sk_root.age");
    }

    let device_passphrase =
        read_optional_device_passphrase(options.device_passphrase_file.as_ref())?;
    let (sk_self, device_id, device_dir, key_file) =
        load_or_create_global_device_identity(device_passphrase.as_deref())?;
    let device_pk = sk_self.verify_key();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();
    let expires_at = now.saturating_add(3650 * 24 * 60 * 60);
    let label = options
        .device_label
        .unwrap_or_else(|| gethostname::gethostname().to_string_lossy().to_string());
    let cert_path = network_dir.join("member_cert.pem");

    let (cert, wrote_cert) = if cert_path.exists() {
        let pem = std::fs::read_to_string(&cert_path)
            .with_context(|| format!("failed to read {}", cert_path.display()))?;
        let cert = pactmesh::trust::MemberCert::from_pem(&pem)
            .with_context(|| format!("failed to parse {}", cert_path.display()))?;
        if cert.details.trust_domain_id != root.id() {
            anyhow::bail!("existing member_cert.pem trust_domain_id does not match sk_root.age");
        }
        if cert.details.network_local_id != state.details.network_local_id {
            anyhow::bail!("existing member_cert.pem network_local_id does not match network_state");
        }
        if cert.details.device_pk.to_bytes() != device_pk.0 {
            anyhow::bail!("existing member_cert.pem belongs to a different device key");
        }
        cert.verify(&root.public_key())
            .with_context(|| format!("failed to verify {}", cert_path.display()))?;
        (cert, false)
    } else {
        let cert = pactmesh::trust::UnsignedMemberCert {
            trust_domain_id: root.id(),
            network_local_id: state.details.network_local_id.clone(),
            device_pk: VerifyingKey::from_bytes(&device_pk.0)
                .expect("device public key must be valid"),
            device_label: label,
            not_before: now,
            expires_at,
            capabilities: pactmesh::trust::Capabilities {
                can_relay_data: true,
                can_relay_control: true,
                can_proxy_subnet: Vec::new(),
                can_be_exit_node: false,
            },
            network_state_version_ref: state.details.version.saturating_add(1),
            hostname: None,
        }
        .sign(&root);
        std::fs::write(&cert_path, cert.to_pem())
            .with_context(|| format!("failed to write {}", cert_path.display()))?;
        (cert, true)
    };

    std::fs::write(network_dir.join("device_id"), format!("{}\n", device_id)).with_context(
        || {
            format!(
                "failed to write {}",
                network_dir.join("device_id").display()
            )
        },
    )?;
    copy_device_key_to_network(&device_dir, &network_dir, key_file)?;

    let fingerprint = cert.fingerprint();
    let already_indexed = state
        .details
        .payload
        .member_cert_index
        .iter()
        .any(|entry| entry.fingerprint == fingerprint);
    let old_version = state.details.version;
    let new_version = if already_indexed {
        old_version
    } else {
        state
            .details
            .payload
            .member_cert_index
            .push(MemberCertIndexEntry {
                fingerprint,
                device_label: cert.details.device_label.clone(),
                issued_at: cert.details.not_before,
                expires_at: cert.details.expires_at,
            });
        write_signed_network_state(&network_dir, &state, original_pem, &root)?
    };

    if options.json {
        println!(
            "{}",
            serde_json::json!({
                "trust_domain_id": root.id().to_string(),
                "network_local_id": state.details.network_local_id.to_string(),
                "fingerprint": fingerprint.to_string(),
                "member_cert": cert_path,
                "device_dir": device_dir,
                "old_version": old_version,
                "new_version": new_version,
                "wrote_cert": wrote_cert,
            })
        );
    } else {
        println!(
            "Bootstrapped local member {} at {} (network_state version {} -> {})",
            fingerprint,
            cert_path.display(),
            old_version,
            new_version
        );
        println!("Device key stored at {}", device_dir.display());
    }
    Ok(())
}

fn handle_trust_create_domain(
    label: String,
    out_dir: Option<PathBuf>,
    curve: String,
    json: bool,
    passphrase_file: Option<PathBuf>,
) -> Result<(), Error> {
    if curve != "ed25519" {
        anyhow::bail!("unsupported curve '{curve}', expected ed25519");
    }

    let passphrase = read_root_passphrase(passphrase_file.as_ref())?;
    let root = TrustDomainRoot::generate();
    let trust_domain_id = root.id();
    let base_dir = out_dir.map(Ok).unwrap_or_else(pnw_trust_domains_dir)?;
    let domain_dir = base_dir.join(trust_domain_id.to_string());
    if domain_dir.exists() {
        anyhow::bail!(
            "trust domain directory already exists: {}",
            domain_dir.display()
        );
    }

    std::fs::create_dir_all(&domain_dir)
        .with_context(|| format!("failed to create {}", domain_dir.display()))?;
    root.save_to_file(&domain_dir.join("sk_root.age"), &passphrase)
        .with_context(|| {
            format!(
                "failed to write {}",
                domain_dir.join("sk_root.age").display()
            )
        })?;
    std::fs::write(
        domain_dir.join("pk_root.pem"),
        wrap_armored("PNW-PK-ROOT", root.public_key().as_bytes()),
    )
    .with_context(|| {
        format!(
            "failed to write {}",
            domain_dir.join("pk_root.pem").display()
        )
    })?;
    std::fs::write(
        domain_dir.join("meta.toml"),
        format!(
            "label = {:?}\ncreated_at = {}\ncurve = {:?}\n",
            label,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .context("system clock before unix epoch")?
                .as_secs(),
            curve
        ),
    )
    .with_context(|| format!("failed to write {}", domain_dir.join("meta.toml").display()))?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "trust_domain_id": trust_domain_id.to_string(),
                "path": domain_dir,
            })
        );
    } else {
        println!(
            "Created trust domain {} at {}",
            trust_domain_id,
            domain_dir.display()
        );
        println!(
            "Backup required: keep {} and remember the management password. Either one alone cannot recover or unlock root management authority.",
            domain_dir.join("sk_root.age").display()
        );
    }
    Ok(())
}

fn print_output<T>(
    items: &[T],
    format: &OutputFormat,
    optional_columns: &[&str],
    drop_columns: &[&str],
    no_trunc: bool,
) -> Result<(), Error>
where
    T: tabled::Tabled + serde::Serialize,
{
    match format {
        OutputFormat::Table => {
            let mut table = tabled::Table::new(items);
            table.with(Style::markdown());
            if no_trunc {
                println!("{}", table);
                return Ok(());
            }
            let headers = T::headers()
                .iter()
                .map(|header| header.as_ref().to_string())
                .collect::<Vec<_>>();
            let col_widths = compute_column_widths(items);
            let terminal_width = terminal_table_width();
            let drop_indices = header_indices(&headers, drop_columns);
            let optional_indices = header_indices(&headers, optional_columns);
            let (active, drop_indices, total_width) =
                select_columns_to_drop(terminal_width, &drop_indices, &col_widths);
            apply_column_drops(&mut table, &drop_indices);
            apply_optional_column_truncation(
                &mut table,
                terminal_width,
                &headers,
                &optional_indices,
                &col_widths,
                &active,
                total_width,
            );
            println!("{}", table);
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(items)?);
        }
    }
    Ok(())
}

fn terminal_table_width() -> Option<usize> {
    let (TerminalWidth(width), _) = terminal_size()?;
    let width = width as usize;
    // Avoid wrapping at the last column which can still trigger a hard line break.
    width.checked_sub(1)
}

fn apply_optional_column_truncation(
    table: &mut tabled::Table,
    terminal_width: Option<usize>,
    headers: &[String],
    optional_indices: &[usize],
    col_widths: &[usize],
    active: &[bool],
    total_width: usize,
) {
    let Some(terminal_width) = terminal_width else {
        return;
    };
    if optional_indices.is_empty() || total_width <= terminal_width {
        return;
    }

    let targets = optional_column_targets(terminal_width, optional_indices, col_widths, active);
    for (index, width) in targets {
        if let Some(name) = headers.get(index) {
            table.with(
                Modify::new(ByColumnName::new(name)).with(Width::truncate(width).suffix("...")),
            );
        }
    }
}

fn apply_column_drops(table: &mut tabled::Table, drop_indices: &[usize]) {
    let mut indices = drop_indices.to_vec();
    indices.sort_unstable_by(|a, b| b.cmp(a));
    for index in indices {
        table.with(Disable::column(Columns::single(index)));
    }
}

fn compute_column_widths<T>(items: &[T]) -> Vec<usize>
where
    T: tabled::Tabled,
{
    let mut widths = vec![0usize; T::LENGTH];
    for (idx, header) in T::headers().iter().enumerate() {
        widths[idx] = widths[idx].max(text_width(header.as_ref()));
    }
    for item in items {
        for (idx, field) in item.fields().iter().enumerate() {
            widths[idx] = widths[idx].max(text_width(field.as_ref()));
        }
    }
    widths
}

fn text_width(text: &str) -> usize {
    text.split('\n')
        .map(UnicodeWidthStr::width)
        .max()
        .unwrap_or(0)
}

fn header_indices(headers: &[String], names: &[&str]) -> Vec<usize> {
    let mut indices = Vec::new();
    for name in names {
        if let Some(index) = headers
            .iter()
            .position(|header| header.eq_ignore_ascii_case(name))
            && !indices.contains(&index)
        {
            indices.push(index);
        }
    }
    indices
}

fn select_columns_to_drop(
    terminal_width: Option<usize>,
    drop_indices: &[usize],
    col_widths: &[usize],
) -> (Vec<bool>, Vec<usize>, usize) {
    let mut active = vec![true; col_widths.len()];
    let Some(terminal_width) = terminal_width else {
        let total = table_total_width(col_widths, &active);
        return (active, vec![], total);
    };

    let mut total = table_total_width(col_widths, &active);
    if total <= terminal_width {
        return (active, vec![], total);
    }

    let mut dropped = vec![];
    for &index in drop_indices {
        if total <= terminal_width {
            break;
        }
        if active[index] {
            active[index] = false;
            dropped.push(index);
            total = table_total_width(col_widths, &active);
        }
    }

    (active, dropped, total)
}

fn table_total_width(col_widths: &[usize], active: &[bool]) -> usize {
    let col_count = active.iter().filter(|value| **value).count();
    if col_count == 0 {
        return 0;
    }
    let content_width = col_widths
        .iter()
        .zip(active.iter())
        .filter_map(|(width, keep)| keep.then_some(*width))
        .sum::<usize>();
    content_width + 3 * col_count + 1
}

fn optional_column_targets(
    terminal_width: usize,
    optional_indices: &[usize],
    col_widths: &[usize],
    active: &[bool],
) -> Vec<(usize, usize)> {
    if optional_indices.is_empty() {
        return vec![];
    }

    let mut is_optional = vec![false; col_widths.len()];
    for &index in optional_indices {
        if let Some(flag) = is_optional.get_mut(index) {
            *flag = true;
        }
    }

    let optional_indices = optional_indices
        .iter()
        .copied()
        .filter(|idx| active.get(*idx).copied().unwrap_or(false))
        .collect::<Vec<_>>();
    if optional_indices.is_empty() {
        return vec![];
    }

    let col_count = active.iter().filter(|value| **value).count();
    let overhead = 3 * col_count + 1;
    let mut required_width = overhead;
    for (idx, width) in col_widths.iter().enumerate() {
        if active.get(idx).copied().unwrap_or(false) && !is_optional[idx] {
            required_width += *width;
        }
    }

    let remaining = terminal_width.saturating_sub(required_width);
    let min_width = 6usize;
    let per_column = if remaining == 0 {
        min_width
    } else {
        (remaining / optional_indices.len()).clamp(min_width, 24)
    };

    optional_indices
        .into_iter()
        .map(|idx| (idx, col_widths[idx].min(per_column)))
        .collect()
}

#[tokio::main]
#[tracing::instrument]
async fn main() -> Result<(), Error> {
    let locale = sys_locale::get_locale().unwrap_or_else(|| String::from("en-US"));
    rust_i18n::set_locale(&locale);
    let cli = Cli::parse();

    let client = RpcClient::new(TcpTunnelConnector::new(
        format!("tcp://{}:{}", cli.rpc_portal.ip(), cli.rpc_portal.port())
            .parse()
            .unwrap(),
    ));
    let handler = CommandHandler {
        client: Arc::new(tokio::sync::Mutex::new(client)),
        verbose: cli.verbose,
        output_format: &cli.output_format,
        no_trunc: cli.no_trunc,
        instance_select: &cli.instance_select,
        instance_selector: (&cli.instance_select).into(),
        resolved_target: None,
    };

    match cli.sub_command {
        SubCommand::Peer(peer_args) => match &peer_args.sub_command {
            Some(PeerSubCommand::List) => {
                handler.handle_peer_list().await?;
            }
            Some(PeerSubCommand::ListForeign { trusted_keys }) => {
                handler.handle_foreign_network_list(*trusted_keys).await?;
            }
            Some(PeerSubCommand::ListGlobalForeign) => {
                handler.handle_global_foreign_network_list().await?;
            }
            None => {
                handler.handle_peer_list().await?;
            }
        },
        SubCommand::Connector(conn_args) => match conn_args.sub_command {
            Some(ConnectorSubCommand::Add { url }) => {
                handler
                    .handle_connector_modify(&url, ConfigPatchAction::Add)
                    .await?;
                println!("connector add applied to selected instance(s): {url}");
            }
            Some(ConnectorSubCommand::Remove { url }) => {
                handler
                    .handle_connector_modify(&url, ConfigPatchAction::Remove)
                    .await?;
                println!("connector remove applied to selected instance(s): {url}");
            }
            Some(ConnectorSubCommand::List) => {
                handler.handle_connector_list().await?;
            }
            None => {
                handler.handle_connector_list().await?;
            }
        },
        SubCommand::MappedListener(mapped_listener_args) => {
            match mapped_listener_args.sub_command {
                Some(MappedListenerSubCommand::Add { url }) => {
                    handler
                        .handle_mapped_listener_modify(&url, ConfigPatchAction::Add)
                        .await?;
                    println!("add mapped listener: {url}");
                }
                Some(MappedListenerSubCommand::Remove { url }) => {
                    handler
                        .handle_mapped_listener_modify(&url, ConfigPatchAction::Remove)
                        .await?;
                    println!("remove mapped listener: {url}");
                }
                Some(MappedListenerSubCommand::List) | None => {
                    handler.handle_mapped_listener_list().await?;
                }
            }
        }
        SubCommand::Route(route_args) => match route_args.sub_command {
            Some(RouteSubCommand::List) | None => handler.handle_route_list().await?,
            Some(RouteSubCommand::Dump) => handler.handle_route_dump().await?,
        },
        SubCommand::Stun => {
            timeout(Duration::from_secs(25), async move {
                let collector = StunInfoCollector::new_with_default_servers();
                loop {
                    let ret = collector.get_stun_info();
                    if ret.udp_nat_type != NatType::Unknown as i32
                        && ret.tcp_nat_type != NatType::Unknown as i32
                    {
                        if cli.output_format == OutputFormat::Json {
                            match serde_json::to_string_pretty(&ret) {
                                Ok(json) => println!("{}", json),
                                Err(e) => eprintln!("Error serializing to JSON: {}", e),
                            }
                        } else {
                            println!("stun info: {:#?}", ret);
                        }
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            })
            .await
            .unwrap();
        }
        SubCommand::VpnPortal => {
            handler.handle_vpn_portal().await?;
        }
        SubCommand::Node(sub_cmd) => {
            handler.handle_node(sub_cmd.sub_command.as_ref()).await?;
        }
        SubCommand::Service(service_args) => {
            let service = Service::new(service_args.name)?;
            match service_args.sub_command {
                ServiceSubCommand::Install(install_args) => {
                    let default_bin = if install_args.serve {
                        // Supervisor entry: this very pactmesh binary runs `serve run`.
                        let mut exe = std::env::current_exe().unwrap();
                        if cfg!(target_os = "windows") {
                            exe.set_extension("exe");
                        }
                        exe
                    } else {
                        let mut ret = std::env::current_exe()
                            .unwrap()
                            .parent()
                            .unwrap()
                            .join("pactmesh-core");
                        if cfg!(target_os = "windows") {
                            ret.set_extension("exe");
                        }
                        ret
                    };
                    let bin_path = install_args.core_path.unwrap_or(default_bin);
                    let bin_path = std::fs::canonicalize(bin_path)
                        .map_err(|e| anyhow::anyhow!("failed to get service program: {}", e))?;
                    let bin_args = if install_args.serve {
                        // Empty-start supervisor: `pactmesh serve` brings up a
                        // network-less daemon + persistent console at boot. No
                        // sealed network/passphrase required (legacy `serve run`
                        // remains available for pinned-network installs).
                        let mut a = vec![OsString::from("serve")];
                        a.extend(install_args.core_args.unwrap_or_default());
                        a
                    } else {
                        install_args.core_args.unwrap_or_default()
                    };
                    let work_dir = install_args.service_work_dir.unwrap_or_else(|| {
                        if cfg!(target_os = "windows") {
                            bin_path.parent().unwrap().to_path_buf()
                        } else {
                            std::env::temp_dir()
                        }
                    });

                    let work_dir = std::fs::canonicalize(&work_dir).map_err(|e| {
                        anyhow::anyhow!(
                            "failed to get service work directory[{}]: {}",
                            work_dir.display(),
                            e
                        )
                    })?;

                    if !work_dir.is_dir() {
                        return Err(anyhow::anyhow!("work directory is not a directory"));
                    }

                    let install_options = ServiceInstallOptions {
                        program: bin_path,
                        args: bin_args,
                        work_directory: work_dir,
                        disable_autostart: install_args.disable_autostart.unwrap_or(false),
                        description: Some(install_args.description),
                        display_name: install_args.display_name,
                        disable_restart_on_failure: install_args
                            .disable_restart_on_failure
                            .unwrap_or(false),
                    };
                    println!("install_options: {:#?}", install_options);
                    service.install(&install_options)?;
                }
                ServiceSubCommand::Uninstall => {
                    service.uninstall()?;
                }
                ServiceSubCommand::Status => {
                    let status = service.status()?;
                    match status {
                        ServiceStatus::Running => println!("Service is running"),
                        ServiceStatus::Stopped(_) => println!("Service is stopped"),
                        ServiceStatus::NotInstalled => println!("Service is not installed"),
                    }
                }
                ServiceSubCommand::Start => {
                    service.start()?;
                }
                ServiceSubCommand::Stop => {
                    service.stop()?;
                }
                ServiceSubCommand::Restart => match service.status()? {
                    ServiceStatus::Running | ServiceStatus::Stopped(_) => {
                        let _ = service.stop();
                        service.start()?;
                    }
                    ServiceStatus::NotInstalled => {
                        anyhow::bail!("Service is not installed");
                    }
                },
            }
        }
        SubCommand::Proxy => {
            let mut entries = vec![];

            for client_type in &["tcp", "kcp_src", "kcp_dst", "quic_src", "quic_dst"] {
                let client = handler.get_tcp_proxy_client(client_type).await?;
                let ret = client
                    .list_tcp_proxy_entry(BaseController::default(), Default::default())
                    .await;
                entries.extend(ret.unwrap_or_default().entries);
            }

            if cli.verbose {
                println!("{}", serde_json::to_string_pretty(&entries)?);
                return Ok(());
            }

            #[derive(tabled::Tabled, serde::Serialize)]
            struct TableItem {
                src: String,
                dst: String,
                start_time: String,
                state: String,
                transport_type: String,
            }

            let table_rows = entries
                .iter()
                .map(|e| TableItem {
                    src: SocketAddr::from(e.src.unwrap_or_default()).to_string(),
                    dst: SocketAddr::from(e.dst.unwrap_or_default()).to_string(),
                    start_time: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
                        (e.start_time * 1000) as i64,
                    )
                    .unwrap()
                    .with_timezone(&chrono::Local)
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string(),
                    state: format!("{:?}", TcpProxyEntryState::try_from(e.state).unwrap()),
                    transport_type: format!(
                        "{:?}",
                        TcpProxyEntryTransportType::try_from(e.transport_type).unwrap()
                    ),
                })
                .collect::<Vec<_>>();

            print_output(
                &table_rows,
                &cli.output_format,
                &["start_time", "state", "transport_type"],
                &["start_time", "state", "transport_type"],
                cli.no_trunc,
            )?;
        }
        SubCommand::Acl(acl_args) => match &acl_args.sub_command {
            Some(AclSubCommand::Stats) | None => {
                handler.handle_acl_stats().await?;
            }
        },
        SubCommand::PortForward(port_forward_args) => match &port_forward_args.sub_command {
            Some(PortForwardSubCommand::Add {
                protocol,
                bind_addr,
                dst_addr,
            }) => {
                handler
                    .handle_port_forward_modify(
                        ConfigPatchAction::Add,
                        protocol,
                        bind_addr,
                        Some(dst_addr),
                    )
                    .await?;
            }
            Some(PortForwardSubCommand::Remove {
                protocol,
                bind_addr,
                dst_addr,
            }) => {
                handler
                    .handle_port_forward_modify(
                        ConfigPatchAction::Remove,
                        protocol,
                        bind_addr,
                        dst_addr.as_deref(),
                    )
                    .await?;
            }
            Some(PortForwardSubCommand::List) | None => {
                handler.handle_port_forward_list().await?;
            }
        },
        SubCommand::Whitelist(whitelist_args) => match &whitelist_args.sub_command {
            Some(WhitelistSubCommand::SetTcp { ports }) => {
                handler.handle_whitelist_set_tcp(ports).await?;
            }
            Some(WhitelistSubCommand::SetUdp { ports }) => {
                handler.handle_whitelist_set_udp(ports).await?;
            }
            Some(WhitelistSubCommand::ClearTcp) => {
                handler.handle_whitelist_clear_tcp().await?;
            }
            Some(WhitelistSubCommand::ClearUdp) => {
                handler.handle_whitelist_clear_udp().await?;
            }
            Some(WhitelistSubCommand::Show) | None => {
                handler.handle_whitelist_show().await?;
            }
        },
        SubCommand::Stats(stats_args) => match &stats_args.sub_command {
            Some(StatsSubCommand::Show) | None => {
                handler.handle_stats_show().await?;
            }
            Some(StatsSubCommand::Prometheus) => {
                handler.handle_stats_prometheus().await?;
            }
        },
        SubCommand::Logger(logger_args) => match &logger_args.sub_command {
            Some(LoggerSubCommand::Get) | None => {
                handler.handle_logger_get().await?;
            }
            Some(LoggerSubCommand::Set { level }) => {
                handler.handle_logger_set(level).await?;
            }
        },
        SubCommand::Credential(credential_args) => match &credential_args.sub_command {
            CredentialSubCommand::Generate {
                ttl,
                credential_id,
                groups,
                allow_relay,
                allowed_proxy_cidrs,
                reusable,
            } => {
                handler
                    .handle_credential_generate(
                        *ttl,
                        credential_id.clone(),
                        groups.clone().unwrap_or_default(),
                        *allow_relay,
                        allowed_proxy_cidrs.clone().unwrap_or_default(),
                        *reusable,
                    )
                    .await?;
            }
            CredentialSubCommand::Revoke { credential_id } => {
                handler.handle_credential_revoke(credential_id).await?;
            }
            CredentialSubCommand::List => {
                handler.handle_credential_list().await?;
            }
        },
        SubCommand::Bootstrap(bootstrap_args) => match bootstrap_args.sub_command {
            BootstrapSubCommand::Export {
                domain_dir,
                network_local_id,
                format,
                out,
                bootstrap_seeds,
                trust_domain_label,
                network_name,
                description,
            } => {
                handle_bootstrap_export(
                    domain_dir,
                    network_local_id,
                    format,
                    out,
                    bootstrap_seeds,
                    trust_domain_label,
                    network_name,
                    description,
                )?;
            }
            BootstrapSubCommand::Import { domain_dir, source } => {
                handle_bootstrap_import(domain_dir, source)?;
            }
        },
        SubCommand::Lab(lab_args) => {
            handle_lab(&handler, lab_args).await?;
        }
        SubCommand::Trust(trust_args) => match trust_args.sub_command {
            TrustSubCommand::CreateDomain {
                label,
                out_dir,
                curve,
                json,
                passphrase_file,
            } => {
                handle_trust_create_domain(label, out_dir, curve, json, passphrase_file)?;
            }
            TrustSubCommand::ListDomains { json } => {
                handle_trust_list_domains(json)?;
            }
            TrustSubCommand::CreateNetwork {
                trust_domain_id,
                network_local_id,
                default_action,
                json,
                passphrase_file,
            } => {
                handle_trust_create_network(
                    trust_domain_id,
                    network_local_id,
                    default_action,
                    json,
                    passphrase_file,
                )?;
            }
            TrustSubCommand::BootstrapSelf {
                trust_domain_id,
                network_local_id,
                device_label,
                json,
                passphrase_file,
                device_passphrase_file,
            } => {
                handle_trust_bootstrap_self(BootstrapSelfOptions {
                    trust_domain_id,
                    network_local_id,
                    device_label,
                    json,
                    passphrase_file,
                    device_passphrase_file,
                })?;
            }
            TrustSubCommand::Invite {
                trust_domain_id,
                network_local_id,
                seeds,
                format,
                out,
            } => {
                handle_trust_invite(trust_domain_id, network_local_id, seeds, format, out)?;
            }
            TrustSubCommand::AcceptInvite {
                source,
                device_label,
                hint,
                passphrase_file,
                online: _,
                offline,
                wait_secs,
                poll_secs,
            } => {
                handle_trust_accept_invite(
                    &handler,
                    AcceptInviteOptions {
                        source,
                        device_label,
                        hint,
                        passphrase_file,
                        online: !offline,
                        wait_secs,
                        poll_secs,
                    },
                )
                .await?;
            }
            TrustSubCommand::Revoke {
                trust_domain_id,
                network_local_id,
                fingerprint,
                reason,
                note,
                passphrase_file,
            } => {
                handle_trust_revoke(
                    trust_domain_id,
                    network_local_id,
                    fingerprint,
                    reason,
                    note,
                    passphrase_file,
                )?;
            }
            TrustSubCommand::Disable {
                trust_domain_id,
                network_local_id,
                fingerprint,
                until,
                note,
                json,
                passphrase_file,
            } => {
                handle_trust_disable(
                    Some(&handler),
                    trust_domain_id,
                    network_local_id,
                    fingerprint,
                    until,
                    note,
                    json,
                    passphrase_file,
                )
                .await?;
            }
            TrustSubCommand::Enable {
                trust_domain_id,
                network_local_id,
                fingerprint,
                json,
                passphrase_file,
            } => {
                handle_trust_enable(
                    Some(&handler),
                    trust_domain_id,
                    network_local_id,
                    fingerprint,
                    json,
                    passphrase_file,
                )
                .await?;
            }
            TrustSubCommand::AssignedIpv4 {
                trust_domain_id,
                network_local_id,
                fingerprint,
                ipv4,
                clear,
                json,
                passphrase_file,
            } => {
                handle_trust_assigned_ipv4(
                    Some(&handler),
                    trust_domain_id,
                    network_local_id,
                    fingerprint,
                    if clear { None } else { ipv4 },
                    json,
                    passphrase_file,
                )
                .await?;
            }
            TrustSubCommand::ListMembers {
                trust_domain_id,
                network_local_id,
                include,
                json,
            } => {
                handle_trust_list_members(trust_domain_id, network_local_id, include, json)?;
            }
            TrustSubCommand::ListExternal {
                config,
                json,
                explain,
            } => {
                handle_trust_list_external(config, json, explain)?;
            }
            TrustSubCommand::ShowDevice {
                trust_domain_id,
                network_local_id,
                device_id,
                json,
            } => {
                handle_trust_show_device(trust_domain_id, network_local_id, device_id, json)?;
            }
            TrustSubCommand::RenameDevice {
                trust_domain_id,
                network_local_id,
                device_id,
                label,
                note,
                json,
                passphrase_file,
            } => handle_trust_rename_device(
                trust_domain_id,
                network_local_id,
                device_id,
                label,
                note,
                json,
                passphrase_file,
            )?,
            TrustSubCommand::Capability { command } => match command {
                TrustCapabilitySubCommand::Set {
                    trust_domain_id,
                    network_local_id,
                    fingerprint,
                    relay_data,
                    relay_control,
                    proxy_subnet,
                    clear_proxy_subnet,
                    note,
                    json,
                    passphrase_file,
                } => handle_trust_capability_set(TrustCapabilitySetOptions {
                    trust_domain_id,
                    network_local_id,
                    fingerprint,
                    relay_data,
                    relay_control,
                    proxy_subnet,
                    clear_proxy_subnet,
                    note,
                    json,
                    passphrase_file,
                })?,
            },
            TrustSubCommand::Tag { command } => match command {
                TrustTagSubCommand::List {
                    trust_domain_id,
                    network_local_id,
                    json,
                } => handle_trust_tag_list(trust_domain_id, network_local_id, json)?,
                TrustTagSubCommand::Add {
                    trust_domain_id,
                    network_local_id,
                    device_id,
                    tag,
                    json,
                    passphrase_file,
                } => handle_trust_tag_update(
                    trust_domain_id,
                    network_local_id,
                    device_id,
                    tag,
                    true,
                    json,
                    passphrase_file,
                )?,
                TrustTagSubCommand::Remove {
                    trust_domain_id,
                    network_local_id,
                    device_id,
                    tag,
                    json,
                    passphrase_file,
                } => handle_trust_tag_update(
                    trust_domain_id,
                    network_local_id,
                    device_id,
                    tag,
                    false,
                    json,
                    passphrase_file,
                )?,
            },
            TrustSubCommand::PeerHint { command } => match command {
                TrustPeerHintSubCommand::List {
                    trust_domain_id,
                    network_local_id,
                    json,
                } => handle_trust_peer_hint_list(trust_domain_id, network_local_id, json)?,
                TrustPeerHintSubCommand::Add {
                    trust_domain_id,
                    network_local_id,
                    url,
                    label,
                    capabilities,
                    expires_at,
                    json,
                    passphrase_file,
                } => handle_trust_peer_hint_update(PeerHintUpdateOptions {
                    trust_domain_id,
                    network_local_id,
                    url,
                    label,
                    capabilities,
                    expires_at,
                    add: true,
                    json,
                    passphrase_file,
                })?,
                TrustPeerHintSubCommand::Remove {
                    trust_domain_id,
                    network_local_id,
                    url,
                    json,
                    passphrase_file,
                } => handle_trust_peer_hint_update(PeerHintUpdateOptions {
                    trust_domain_id,
                    network_local_id,
                    url,
                    label: None,
                    capabilities: Vec::new(),
                    expires_at: None,
                    add: false,
                    json,
                    passphrase_file,
                })?,
            },
            TrustSubCommand::Acl { command } => match command {
                TrustAclSubCommand::Explain {
                    trust_domain_id,
                    network_local_id,
                    src_device_id,
                    dst_device_id,
                    proto,
                    port,
                    src_ip,
                    dst_ip,
                    json,
                } => handle_trust_acl_explain(TrustAclExplainOptions {
                    trust_domain_id,
                    network_local_id,
                    src_device_id,
                    dst_device_id,
                    proto,
                    port,
                    src_ip,
                    dst_ip,
                    json,
                })?,
            },
            TrustSubCommand::SetHostname {
                trust_domain_id,
                network_local_id,
                fingerprint,
                hostname,
                note,
                passphrase_file,
            } => {
                handle_trust_hostname_update(
                    trust_domain_id,
                    network_local_id,
                    fingerprint,
                    Some(hostname),
                    note,
                    passphrase_file,
                )?;
            }
            TrustSubCommand::UnsetHostname {
                trust_domain_id,
                network_local_id,
                fingerprint,
                passphrase_file,
            } => {
                handle_trust_hostname_update(
                    trust_domain_id,
                    network_local_id,
                    fingerprint,
                    None,
                    None,
                    passphrase_file,
                )?;
            }
            TrustSubCommand::Approve {
                trust_domain_id,
                network_local_id,
                applicant_pk,
                json,
                passphrase_file,
            } => {
                handle_trust_approve(
                    &handler,
                    trust_domain_id,
                    network_local_id,
                    applicant_pk,
                    json,
                    passphrase_file,
                )
                .await?;
            }
            TrustSubCommand::Reject {
                trust_domain_id,
                network_local_id,
                applicant_pk,
            } => {
                handle_trust_reject(&handler, trust_domain_id, network_local_id, applicant_pk)
                    .await?;
            }
            TrustSubCommand::UpgradePeerToRoot {
                trust_domain_id,
                network_local_id,
                peer_id,
                json,
                passphrase_file,
            } => {
                handle_trust_upgrade_peer_to_root(
                    &handler,
                    trust_domain_id,
                    network_local_id,
                    peer_id,
                    json,
                    passphrase_file,
                )
                .await?;
            }
            TrustSubCommand::ListPending {
                trust_domain_id,
                network_local_id,
                json,
            } => {
                handle_trust_list_pending(&handler, trust_domain_id, network_local_id, json)
                    .await?;
            }
        },
        SubCommand::Controller(controller_args) => {
            handler.run_controller(&controller_args).await?
        }
        SubCommand::Quickstart(quickstart_args) => {
            handler
                .run_quickstart(cli.rpc_portal, &quickstart_args)
                .await?
        }
        SubCommand::Web => handler.run_web()?,
        SubCommand::Tray => handler.run_tray()?,
        SubCommand::Serve(serve_args) => handler.run_serve(cli.rpc_portal, &serve_args).await?,
        SubCommand::Tui => handler.run_tui().await?,

        SubCommand::GenAutocomplete { shell } => {
            let mut cmd = Cli::command();
            if let Some(shell) = shell.to_shell() {
                pactmesh::print_completions(shell, &mut cmd, "pactmesh");
            } else {
                // Handle Nushell
                pactmesh::print_nushell_completions(&mut cmd, "pactmesh");
            }
        }
    }

    Ok(())
}
