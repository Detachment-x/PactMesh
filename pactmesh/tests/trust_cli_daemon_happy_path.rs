use std::{
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;

const NETWORK_LOCAL_ID: &str = "office-net";
const ROOT_PASSPHRASE: &str = "long-enough-pass";
const DEVICE_PASSPHRASE: &str = "device-passphrase";

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pactmesh"))
}

fn core() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pactmesh-core"))
}

fn config_home(root: &Path) -> PathBuf {
    root.join("xdg")
}

fn trust_domains_dir(root: &Path) -> PathBuf {
    config_home(root).join("privateNetwork/trust-domains")
}

fn network_dir(root: &Path, trust_domain_id: &str) -> PathBuf {
    trust_domains_dir(root)
        .join(trust_domain_id)
        .join("networks")
        .join(NETWORK_LOCAL_ID)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn run_ok(mut cmd: Command) -> std::process::Output {
    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "command failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn create_domain(root: &Path) -> String {
    let mut cmd = cli();
    cmd.env("XDG_CONFIG_HOME", config_home(root))
        .env("PNW_ROOT_PASSPHRASE", ROOT_PASSPHRASE)
        .arg("trust")
        .arg("create-domain")
        .arg("--label")
        .arg("happy")
        .arg("--json");
    let output = run_ok(cmd);
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    value["trust_domain_id"].as_str().unwrap().to_owned()
}

fn create_network(root: &Path, trust_domain_id: &str) {
    let mut cmd = cli();
    cmd.env("XDG_CONFIG_HOME", config_home(root))
        .env("PNW_ROOT_PASSPHRASE", ROOT_PASSPHRASE)
        .arg("trust")
        .arg("create-network")
        .arg(trust_domain_id)
        .arg(NETWORK_LOCAL_ID);
    run_ok(cmd);
}

fn bootstrap_self(root: &Path, trust_domain_id: &str) {
    let mut cmd = cli();
    cmd.env("XDG_CONFIG_HOME", config_home(root))
        .env("PNW_ROOT_PASSPHRASE", ROOT_PASSPHRASE)
        .env("PNW_DEVICE_PASSPHRASE", DEVICE_PASSPHRASE)
        .arg("trust")
        .arg("bootstrap-self")
        .arg(trust_domain_id)
        .arg(NETWORK_LOCAL_ID)
        .arg("--device-label")
        .arg("root-a");
    run_ok(cmd);
}

fn invite(root: &Path, trust_domain_id: &str, listener_port: u16) -> String {
    let mut cmd = cli();
    cmd.env("XDG_CONFIG_HOME", config_home(root))
        .arg("trust")
        .arg("invite")
        .arg(trust_domain_id)
        .arg(NETWORK_LOCAL_ID)
        .arg("--seed")
        .arg(format!("tcp://127.0.0.1:{listener_port}"));
    String::from_utf8(run_ok(cmd).stdout)
        .unwrap()
        .trim()
        .to_owned()
}

fn wait_for_port(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("port {port} did not open");
}

fn spawn_core(
    root: &Path,
    trust_domain_id: &str,
    instance_name: &str,
    rpc_port: u16,
    listener_port: Option<u16>,
    peer_port: Option<u16>,
) -> Child {
    let domain_dir = trust_domains_dir(root).join(trust_domain_id);
    let mut cmd = core();
    cmd.env("PNW_ROOT_PASSPHRASE", ROOT_PASSPHRASE)
        .env("ET_SK_SELF_PASSWORD", DEVICE_PASSPHRASE)
        .arg("--network-name")
        .arg(NETWORK_LOCAL_ID)
        .arg("--trust-domain-dir")
        .arg(domain_dir)
        .arg("--network-local-id")
        .arg(NETWORK_LOCAL_ID)
        .arg("--sk-self-password-env")
        .arg("ET_SK_SELF_PASSWORD")
        .arg("--rpc-portal")
        .arg(rpc_port.to_string())
        .arg("--no-tun")
        .arg("true")
        .arg("--disable-ipv6")
        .arg("true")
        .arg("--instance-name")
        .arg(instance_name)
        .arg("--console-log-level")
        .arg("info")
        .arg("--daemon");
    if let Some(listener_port) = listener_port {
        cmd.arg("--listeners")
            .arg(format!("tcp://127.0.0.1:{listener_port}"));
    } else {
        cmd.arg("--no-listener");
    }
    if let Some(peer_port) = peer_port {
        cmd.arg("--peers")
            .arg(format!("tcp://127.0.0.1:{peer_port}"));
    }
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap()
}

fn spawn_core_auto_trust_dir(
    root: &Path,
    instance_name: &str,
    rpc_port: u16,
    listener_port: Option<u16>,
    peer_port: Option<u16>,
) -> Child {
    let mut cmd = core();
    cmd.env("XDG_CONFIG_HOME", config_home(root))
        .env("PNW_ROOT_PASSPHRASE", ROOT_PASSPHRASE)
        .env("ET_SK_SELF_PASSWORD", DEVICE_PASSPHRASE)
        .arg("--network-name")
        .arg(NETWORK_LOCAL_ID)
        .arg("--network-local-id")
        .arg(NETWORK_LOCAL_ID)
        .arg("--sk-self-password-env")
        .arg("ET_SK_SELF_PASSWORD")
        .arg("--rpc-portal")
        .arg(rpc_port.to_string())
        .arg("--no-tun")
        .arg("true")
        .arg("--disable-ipv6")
        .arg("true")
        .arg("--instance-name")
        .arg(instance_name)
        .arg("--console-log-level")
        .arg("info")
        .arg("--daemon");
    if let Some(listener_port) = listener_port {
        cmd.arg("--listeners")
            .arg(format!("tcp://127.0.0.1:{listener_port}"));
    } else {
        cmd.arg("--no-listener");
    }
    if let Some(peer_port) = peer_port {
        cmd.arg("--peers")
            .arg(format!("tcp://127.0.0.1:{peer_port}"));
    }
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap()
}

fn list_pending(root: &Path, rpc_port: u16, trust_domain_id: &str) -> Vec<Value> {
    let output = cli()
        .env("XDG_CONFIG_HOME", config_home(root))
        .arg("--rpc-portal")
        .arg(format!("127.0.0.1:{rpc_port}"))
        .arg("trust")
        .arg("list-pending")
        .arg(trust_domain_id)
        .arg("--network-local-id")
        .arg(NETWORK_LOCAL_ID)
        .arg("--json")
        .output()
        .unwrap();
    if !output.status.success() {
        return Vec::new();
    }
    serde_json::from_slice(&output.stdout).unwrap()
}

fn approve_first_pending(root: &Path, rpc_port: u16, trust_domain_id: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let pending = list_pending(root, rpc_port, trust_domain_id);
        if let Some(first) = pending.first() {
            let applicant_pk = first["device_id"].as_str().unwrap();
            let applicant_pk = &applicant_pk[..16];
            let mut cmd = cli();
            cmd.env("XDG_CONFIG_HOME", config_home(root))
                .env("PNW_ROOT_PASSPHRASE", ROOT_PASSPHRASE)
                .arg("--rpc-portal")
                .arg(format!("127.0.0.1:{rpc_port}"))
                .arg("trust")
                .arg("approve")
                .arg(trust_domain_id)
                .arg(NETWORK_LOCAL_ID)
                .arg("--")
                .arg(applicant_pk);
            run_ok(cmd);
            return;
        }
        thread::sleep(Duration::from_millis(200));
    }
    panic!("pending join request did not appear");
}

fn accept_invite_online(root: &Path, invite: &str) -> Child {
    let unused_rpc_port = free_port();
    let mut cmd = cli();
    cmd.env("XDG_CONFIG_HOME", config_home(root))
        .env("PNW_DEVICE_PASSPHRASE", DEVICE_PASSPHRASE)
        .arg("--rpc-portal")
        .arg(format!("127.0.0.1:{unused_rpc_port}"))
        .arg("trust")
        .arg("accept-invite")
        .arg(invite)
        .arg("--device-label")
        .arg("node-b")
        .arg("--hint")
        .arg("daemon-e2e")
        .arg("--online")
        .arg("--wait-secs")
        .arg("20")
        .arg("--poll-secs")
        .arg("1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap()
}

fn peer_list_contains_peer(root: &Path, rpc_port: u16) -> bool {
    let output = cli()
        .env("XDG_CONFIG_HOME", config_home(root))
        .arg("--rpc-portal")
        .arg(format!("127.0.0.1:{rpc_port}"))
        .arg("-o")
        .arg("json")
        .arg("peer")
        .arg("list")
        .output()
        .unwrap();
    if !output.status.success() {
        return false;
    }
    let Ok(rows) = serde_json::from_slice::<Vec<Value>>(&output.stdout) else {
        return false;
    };
    rows.iter().any(|row| {
        row.get("cost").and_then(Value::as_str) == Some("p2p")
            && row.get("tunnel_proto").and_then(Value::as_str) == Some("tcp")
    })
}

#[test]
fn test_core_daemon_help_says_no_background_fork() {
    let output = core().arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--daemon"));
    assert!(stdout.contains("does not fork into the background"));
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn test_cli_daemon_online_invite_establishes_peer() {
    let dir = tempfile::tempdir().unwrap();
    let root_a = dir.path().join("a");
    let root_b = dir.path().join("b");
    let listener_port = free_port();
    let root_rpc_port = free_port();
    let member_rpc_port = free_port();

    let trust_domain_id = create_domain(&root_a);
    create_network(&root_a, &trust_domain_id);
    bootstrap_self(&root_a, &trust_domain_id);
    let invite = invite(&root_a, &trust_domain_id, listener_port);

    let _root = ChildGuard(spawn_core(
        &root_a,
        &trust_domain_id,
        "root-a",
        root_rpc_port,
        Some(listener_port),
        None,
    ));
    wait_for_port(listener_port);
    wait_for_port(listener_port + 1);
    wait_for_port(root_rpc_port);

    let mut accept = accept_invite_online(&root_b, &invite);
    approve_first_pending(&root_a, root_rpc_port, &trust_domain_id);
    assert!(accept.wait().unwrap().success());

    let member_network_dir = network_dir(&root_b, &trust_domain_id);
    assert!(member_network_dir.join("member_cert.pem").is_file());
    assert!(member_network_dir.join("sk_self.age").is_file());
    assert!(member_network_dir.join("network_state.cbor.pem").is_file());
    assert!(
        member_network_dir
            .join("network_bootstrap.cbor.pem")
            .is_file()
    );

    let _member = ChildGuard(spawn_core_auto_trust_dir(
        &root_b,
        "node-b",
        member_rpc_port,
        None,
        None,
    ));
    wait_for_port(member_rpc_port);

    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if peer_list_contains_peer(&root_a, root_rpc_port)
            && peer_list_contains_peer(&root_b, member_rpc_port)
        {
            return;
        }
        thread::sleep(Duration::from_millis(300));
    }
    panic!("root and member daemons did not establish a peer connection");
}
