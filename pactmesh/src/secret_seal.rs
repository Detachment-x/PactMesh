//! OS-native sealing of small secrets (the device-key passphrase) so an
//! unattended `pactmesh serve` can unlock `sk_self` at boot without a plaintext
//! passphrase on disk.
//!
//! Iron law: unattended auto-start ⟺ the machine holds all unlock material ⟺ a
//! live local root can always unseal (same as ZeroTier/Tailscale/WireGuard).
//! Sealing defends against a stolen disk/backup and accidental plaintext leakage
//! — not a live local root. The trust/governance model is untouched: `sk_self`
//! stays age-encrypted; only its passphrase is OS-sealed here.
//!
//! Blob layout: `[MAGIC b"PMSEAL1"][scheme: u8][payload]`.
//!   1 = Windows DPAPI (`CryptProtectData`, LOCAL_MACHINE scope)
//!   2 = systemd-creds (host/TPM bound; modern Linux)
//!   3 = machine-id-derived age scrypt wrap (fallback for old Linux without TPM)

use anyhow::{Context, Result};

const MAGIC: &[u8] = b"PMSEAL1";
const SCHEME_DPAPI: u8 = 1;
const SCHEME_SYSTEMD_CREDS: u8 = 2;
const SCHEME_MACHINE_ID: u8 = 3;

/// Seal `plaintext` with the strongest scheme available on this host.
pub fn seal(plaintext: &[u8]) -> Result<Vec<u8>> {
    #[cfg(windows)]
    {
        Ok(wrap(SCHEME_DPAPI, dpapi_protect(plaintext)?))
    }
    #[cfg(not(windows))]
    {
        if let Some(out) = systemd_creds_encrypt(plaintext) {
            return Ok(wrap(SCHEME_SYSTEMD_CREDS, out));
        }
        Ok(wrap(SCHEME_MACHINE_ID, machine_id_seal(plaintext)?))
    }
}

/// Inverse of [`seal`]; dispatches on the embedded scheme tag.
pub fn unseal(blob: &[u8]) -> Result<Vec<u8>> {
    let (scheme, payload) = unwrap(blob)?;
    match scheme {
        SCHEME_DPAPI => {
            #[cfg(windows)]
            {
                dpapi_unprotect(payload)
            }
            #[cfg(not(windows))]
            {
                anyhow::bail!("DPAPI-sealed secret cannot be opened on this platform")
            }
        }
        SCHEME_SYSTEMD_CREDS => {
            #[cfg(not(windows))]
            {
                systemd_creds_decrypt(payload)
            }
            #[cfg(windows)]
            {
                anyhow::bail!("systemd-creds-sealed secret cannot be opened on Windows")
            }
        }
        SCHEME_MACHINE_ID => {
            #[cfg(not(windows))]
            {
                machine_id_unseal(payload)
            }
            #[cfg(windows)]
            {
                anyhow::bail!("machine-id-sealed secret cannot be opened on Windows")
            }
        }
        other => anyhow::bail!("unknown seal scheme {other}"),
    }
}

fn wrap(scheme: u8, mut payload: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAGIC.len() + 1 + payload.len());
    out.extend_from_slice(MAGIC);
    out.push(scheme);
    out.append(&mut payload);
    out
}

fn unwrap(blob: &[u8]) -> Result<(u8, &[u8])> {
    if blob.len() < MAGIC.len() + 1 || &blob[..MAGIC.len()] != MAGIC {
        anyhow::bail!("not a pactmesh sealed blob");
    }
    Ok((blob[MAGIC.len()], &blob[MAGIC.len() + 1..]))
}

// ---- Linux / Unix ----------------------------------------------------------

/// Android exposes no app-readable OS machine id, so the host app installs a
/// Keystore-wrapped, install-scoped secret at startup and we key off that instead.
#[cfg(target_os = "android")]
static DEVICE_SECRET: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Install the device-bound secret backing [`seal`]/[`unseal`]. Must be called
/// before either, and must yield the same value across app restarts.
#[cfg(target_os = "android")]
pub fn set_device_secret(secret: String) {
    let _ = DEVICE_SECRET.set(secret);
}

#[cfg(target_os = "android")]
fn device_id() -> Result<String> {
    DEVICE_SECRET
        .get()
        .cloned()
        .context("device secret not installed")
}

#[cfg(all(not(windows), not(target_os = "android")))]
fn device_id() -> Result<String> {
    machine_uid::get().map_err(|e| anyhow::anyhow!("failed to read machine id: {e}"))
}

#[cfg(not(windows))]
fn machine_id_key() -> Result<age::secrecy::SecretString> {
    // Domain-separate so the raw device id is never the literal passphrase.
    Ok(age::secrecy::SecretString::from(format!(
        "pactmesh-serve-seal:{}",
        device_id()?
    )))
}

#[cfg(not(windows))]
fn machine_id_seal(plaintext: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write as _;
    let mut recipient = age::scrypt::Recipient::new(machine_id_key()?);
    // The machine id is already high-entropy; a low work factor keeps boot fast.
    recipient.set_work_factor(2);
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .expect("single scrypt recipient is valid");
    let mut encrypted = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted)?;
    writer.write_all(plaintext)?;
    writer.finish()?;
    Ok(encrypted)
}

#[cfg(not(windows))]
fn machine_id_unseal(blob: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read as _;
    let identity = age::scrypt::Identity::new(machine_id_key()?);
    let decryptor = age::Decryptor::new(blob).context("invalid sealed blob")?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| {
            anyhow::anyhow!("machine-id unseal failed (machine changed or blob corrupt)")
        })?;
    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .context("read decrypted secret")?;
    Ok(plaintext)
}

#[cfg(not(windows))]
fn systemd_creds_encrypt(plaintext: &[u8]) -> Option<Vec<u8>> {
    run_systemd_creds(&["encrypt", "--name=pactmesh-serve", "-", "-"], plaintext)
}

#[cfg(not(windows))]
fn systemd_creds_decrypt(blob: &[u8]) -> Result<Vec<u8>> {
    run_systemd_creds(&["decrypt", "--name=pactmesh-serve", "-", "-"], blob)
        .ok_or_else(|| anyhow::anyhow!("systemd-creds decrypt failed"))
}

#[cfg(not(windows))]
fn run_systemd_creds(args: &[&str], input: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    let mut child = Command::new("systemd-creds")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(input).ok()?;
    let out = child.wait_with_output().ok()?;
    out.status.success().then_some(out.stdout)
}

// ---- Windows ---------------------------------------------------------------

#[cfg(windows)]
fn dpapi_protect(data: &[u8]) -> Result<Vec<u8>> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CryptProtectData,
    };
    use windows::core::PCWSTR;
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptProtectData(
            &in_blob,
            PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut out_blob,
        )
        .map_err(|e| anyhow::anyhow!("CryptProtectData failed: {e}"))?;
        let result = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(out_blob.pbData as *mut core::ffi::c_void)));
        Ok(result)
    }
}

#[cfg(windows)]
fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CryptUnprotectData,
    };
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptUnprotectData(
            &in_blob,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut out_blob,
        )
        .map_err(|e| anyhow::anyhow!("CryptUnprotectData failed: {e}"))?;
        let result = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(out_blob.pbData as *mut core::ffi::c_void)));
        Ok(result)
    }
}
