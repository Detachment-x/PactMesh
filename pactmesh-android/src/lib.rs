//! The JNI boundary. Everything above it is Kotlin; everything below is the stock
//! `pactmesh` library, unmodified.
//!
//! Four calls, because that is all Android actually needs that HTTP cannot give it:
//! process lifetime (`init`/`start`/`stop`) and the one thing with no RPC surface —
//! handing `VpnService.establish()`'s file descriptor to the running instance.
//! Everything else (join, peers, stats, ACL) the app does over the console's own
//! `/api/*`, against the axum server this file starts on loopback.

#![cfg(target_os = "android")]

use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{Context, Result, anyhow};
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint};

use pactmesh::common::config_dir::pnw_serve_instances_dir;
use pactmesh::control::embedded::{EmbeddedDaemon, EmbeddedDaemonOptions, start_embedded_daemon};
use pactmesh::controller::{ControllerConfig, RpcClient};
use pactmesh::proto::api::instance::InstanceIdentifier;
use pactmesh::tunnel::tcp::TcpTunnelConnector;

/// Outlives every call: the daemon's instances and the console both hold onto it.
static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static DAEMON: Mutex<Option<EmbeddedDaemon>> = Mutex::new(None);

const UNLOCK_TTL_SECS: u64 = 900;

/// Install the process-wide state the library reads from the environment.
///
/// `config_dir` becomes `XDG_CONFIG_HOME`, which `config_dir.rs` already honours
/// ahead of every other candidate — so all trust material lands in the app's 0700
/// sandbox with no change on the Rust side.
///
/// `device_secret` backs `secret_seal`: Android exposes no app-readable machine id,
/// so the host app keeps a Keystore-wrapped, install-scoped secret and passes it in.
/// It must be byte-identical across restarts or the sealed device key stops opening.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_pactmesh_android_Native_nativeInit(
    mut env: JNIEnv,
    _class: JClass,
    config_dir: JString,
    device_secret: JString,
    log_level: JString,
) {
    guard(&mut env, |env| {
        let config_dir: String = env.get_string(&config_dir)?.into();
        let device_secret: String = env.get_string(&device_secret)?.into();
        let log_level: String = env.get_string(&log_level)?.into();

        // SAFETY: called once from Application.onCreate, before any thread reads it.
        unsafe { std::env::set_var("XDG_CONFIG_HOME", &config_dir) };
        pactmesh::secret_seal::set_device_secret(device_secret);
        logcat::init(&log_level);

        RUNTIME
            .set(tokio::runtime::Runtime::new().context("failed to build the tokio runtime")?)
            .map_err(|_| anyhow!("nativeInit called twice"))?;

        tracing::info!("pactmesh initialised, config dir {config_dir}");
        Ok(())
    });
}

/// Bring up the daemon and the console. Idempotent: a second call is a no-op.
///
/// `token` is minted by Kotlin (`SecureRandom`) rather than returned from here —
/// on Android any app can reach `127.0.0.1`, and the console's bearer token is the
/// only thing standing in front of it. Generating it caller-side keeps it out of a
/// file. The daemon's RPC portal has no auth at all, which is why `rpc_port` should
/// be ephemeral rather than the well-known 15888.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_pactmesh_android_Native_nativeStart(
    mut env: JNIEnv,
    _class: JClass,
    rpc_port: jint,
    web_port: jint,
    token: JString,
) -> jboolean {
    guard_bool(&mut env, |env| {
        let token: String = env.get_string(&token)?.into();
        let runtime = RUNTIME.get().context("nativeInit has not run")?;

        let mut slot = DAEMON.lock().unwrap();
        if slot.is_some() {
            return Ok(true);
        }

        let rpc_portal = format!("127.0.0.1:{rpc_port}");
        let daemon = runtime.block_on(start_embedded_daemon(EmbeddedDaemonOptions {
            rpc_portal: rpc_portal.clone(),
            rpc_portal_whitelist: Some(vec!["127.0.0.1/32".parse()?]),
            instances_dir: pnw_serve_instances_dir()?,
        }))?;

        let client = Arc::new(tokio::sync::Mutex::new(RpcClient::new(
            TcpTunnelConnector::new(format!("tcp://{rpc_portal}").parse()?),
        )));
        let listen: SocketAddr = format!("127.0.0.1:{web_port}").parse()?;
        runtime.spawn(async move {
            if let Err(err) = pactmesh::controller::run(
                client,
                InstanceIdentifier::default(),
                ControllerConfig {
                    listen,
                    token: Some(token),
                    unlock_ttl_secs: UNLOCK_TTL_SECS,
                    attach_primary: None,
                    // No stdout to print a browser URL to, and no endpoint file to
                    // leave behind: the app already knows its own port and token.
                    announce_endpoint: false,
                },
            )
            .await
            {
                tracing::error!("console stopped: {err:#}");
            }
        });

        *slot = Some(daemon);
        tracing::info!("daemon on {rpc_portal}, console on {listen}");
        Ok(true)
    })
}

/// Hand `VpnService.establish()`'s descriptor to a running instance, or `fd <= 0`
/// to detach cleanly.
///
/// Order matters and is not negotiable: the instance must already hold its overlay
/// IPv4 before the fd arrives. Every IP change calls `clear_nic_ctx`, and the
/// rebuild that follows is compiled out on mobile — so an fd handed over too early
/// is torn down by the first address assignment, silently, with the tunnel dead and
/// nothing logged. Poll `/api/node` until `ipv4_addr` is non-empty, then call this.
///
/// The caller keeps the `ParcelFileDescriptor` and passes `getFd()`. Never
/// `detachFd()`: the tun device is created with `close_fd_on_drop(false)`, so Rust
/// never closes it — detaching just leaks one descriptor per reconnect.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_pactmesh_android_Native_nativeSetTunFd(
    mut env: JNIEnv,
    _class: JClass,
    instance_id: JString,
    fd: jint,
) -> jboolean {
    guard_bool(&mut env, |env| {
        let instance_id: String = env.get_string(&instance_id)?.into();
        let uuid = uuid::Uuid::parse_str(&instance_id)
            .with_context(|| format!("not an instance id: {instance_id}"))?;

        let slot = DAEMON.lock().unwrap();
        let daemon = slot.as_ref().context("nativeStart has not run")?;
        daemon.manager.set_tun_fd(&uuid, fd)?;
        Ok(true)
    })
}

/// Stop the daemon and every instance it owns. The runtime stays up so a later
/// `nativeStart` can bring things back without re-initialising the process.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_pactmesh_android_Native_nativeStop(
    mut env: JNIEnv,
    _class: JClass,
) {
    guard(&mut env, |_env| {
        // Dropping the daemon tears down the RPC portal and stops the instances;
        // the console task dies with the client it can no longer reach.
        drop(DAEMON.lock().unwrap().take());
        tracing::info!("pactmesh stopped");
        Ok(())
    });
}

/// Turn a panic or an `Err` into a Java exception. Without this a panic crossing the
/// JNI boundary is undefined behaviour — hence `panic = "unwind"` in the
/// `release-android` profile; `abort` would make this whole guard a decoration.
fn guard(env: &mut JNIEnv, body: impl FnOnce(&mut JNIEnv) -> Result<()>) {
    let result = catch_unwind(AssertUnwindSafe(|| body(env)));
    report(env, result.map(|inner| inner.map(|()| false)));
}

fn guard_bool(env: &mut JNIEnv, body: impl FnOnce(&mut JNIEnv) -> Result<bool>) -> jboolean {
    let result = catch_unwind(AssertUnwindSafe(|| body(env)));
    u8::from(report(env, result))
}

fn report(
    env: &mut JNIEnv,
    result: std::thread::Result<Result<bool>>,
) -> bool {
    let message = match result {
        Ok(Ok(value)) => return value,
        Ok(Err(err)) => format!("{err:#}"),
        Err(_) => "panicked".to_owned(),
    };
    tracing::error!("{message}");
    let _ = env.throw_new("java/lang/RuntimeException", message);
    false
}

/// A `tracing` sink that writes to logcat, so `adb logcat -s pactmesh` shows the
/// library's own logs. Bionic's liblog is the only way anything is visible on a
/// phone; stdout goes nowhere.
mod logcat {
    use std::io::Write;

    const TAG: &str = "pactmesh\0";
    const PRIO_INFO: i32 = 4;

    unsafe extern "C" {
        fn __android_log_write(prio: i32, tag: *const i8, text: *const i8) -> i32;
    }

    pub fn init(level: &str) {
        let filter = tracing_subscriber::EnvFilter::try_new(level)
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(|| Logcat(Vec::new()))
            .try_init();
    }

    struct Logcat(Vec<u8>);

    impl Write for Logcat {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            // Interior NULs would truncate the line; liblog takes a C string.
            self.0.retain(|byte| *byte != 0);
            self.0.push(0);
            // SAFETY: both pointers are NUL-terminated and live across the call.
            unsafe {
                __android_log_write(PRIO_INFO, TAG.as_ptr().cast(), self.0.as_ptr().cast());
            }
            self.0.clear();
            Ok(())
        }
    }

    impl Drop for Logcat {
        fn drop(&mut self) {
            let _ = self.flush();
        }
    }
}
