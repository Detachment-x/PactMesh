use std::io::Write;
use std::iter;
use std::path::Path;
use std::sync::Arc;

use age::secrecy::SecretString;
use age::{Encryptor, scrypt};
use ed25519_dalek::VerifyingKey;
use pactmesh::common::config::TomlConfigLoader;
use pactmesh::common::global_ctx::GlobalCtx;
use pactmesh::launcher::inject_trust_pool_from_config;
use pactmesh::trust::trust_domain_meta::OutboundGrant;
use pactmesh::trust::{
    ActiveRelay, Capabilities, MemberCert, NetworkStatePayload, RelayCapabilities, SignKey,
    SignedNetworkState, SignedTrustDomainMeta, TrustDomainPool, TrustDomainRoot,
    UnsignedMemberCert, UnsignedNetworkState, UnsignedTrustDomainMeta, to_canonical_cbor,
    wrap_armored,
};
use tokio::sync::RwLock;

const TRUST_DOMAIN_META_PEM_LABEL: &str = "PNW-TRUST-DOMAIN-META";
const NETWORK_LOCAL_ID: &str = "office-net";
const PASSWORD: &str = "correct-pass";
const NOW: u64 = 1_715_000_100;

fn sample_unsigned_member_cert(
    root: &TrustDomainRoot,
    sk_self: &SignKey,
    network_local_id: &str,
) -> UnsignedMemberCert {
    let verify_key = sk_self.verify_key();
    let device_pk = VerifyingKey::from_bytes(&verify_key.0).unwrap();

    UnsignedMemberCert {
        trust_domain_id: root.id(),
        network_local_id: network_local_id.parse().unwrap(),
        device_pk,
        device_label: "device-a".to_owned(),
        not_before: 1_715_000_000,
        expires_at: 1_716_000_000,
        capabilities: Capabilities {
            can_relay_data: true,
            can_relay_control: true,
            can_proxy_subnet: Vec::new(),
        },
        network_state_version_ref: 42,
        hostname: None,
    }
}

fn seal_sign_key(sk_self: &SignKey, password: &str) -> Vec<u8> {
    let mut recipient = scrypt::Recipient::new(SecretString::from(password.to_owned()));
    recipient.set_work_factor(2);

    let encryptor = Encryptor::with_recipients(iter::once(&recipient as &dyn age::Recipient))
        .expect("single scrypt recipient is valid");
    let mut encrypted = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
    writer.write_all(&sk_self.to_bytes()).unwrap();
    writer.finish().unwrap();
    encrypted
}

fn sample_network_state(root: &TrustDomainRoot, cert: &MemberCert) -> SignedNetworkState {
    UnsignedNetworkState {
        trust_domain_id: root.id(),
        network_local_id: cert.details.network_local_id.clone(),
        version: 42,
        payload: NetworkStatePayload {
            member_cert_index: Vec::new(),
            revoked_certs: Vec::new(),
            disabled_certs: Vec::new(),
            acl: Vec::new(),
            routes: Vec::new(),
            peer_hints: Vec::new(),
            admin_grants: Vec::new(),
        },
    }
    .sign(root)
}

fn sample_trust_domain_meta(root: &TrustDomainRoot) -> SignedTrustDomainMeta {
    UnsignedTrustDomainMeta {
        trust_domain_id: root.id(),
        version: 7,
        active_relays: vec![ActiveRelay {
            device_pk: VerifyingKey::from_bytes(&SignKey::generate().verify_key().0).unwrap(),
            device_label: "relay-a".to_owned(),
            capabilities: RelayCapabilities {
                can_relay_data: true,
                can_assist_holepunch: true,
            },
            expires_at: 1_800_000_000,
        }],
        outbound_grants: vec![OutboundGrant {
            foreign_root_pk: root.public_key(),
            foreign_trust_domain_id: root.id(),
            capabilities: RelayCapabilities {
                can_relay_data: true,
                can_assist_holepunch: false,
            },
            expires_at: 1_800_000_001,
        }],
    }
    .sign(root)
}

fn write_domain_files(
    domain_dir: &Path,
    network_local_id: &str,
    root: &TrustDomainRoot,
    cert: &MemberCert,
    sk_self: &SignKey,
    password: &str,
) {
    let network_dir = domain_dir.join("networks").join(network_local_id);
    std::fs::create_dir_all(&network_dir).unwrap();
    std::fs::write(
        domain_dir.join("pk_root.pem"),
        wrap_armored("PNW-PK-ROOT", root.public_key().as_bytes()),
    )
    .unwrap();
    std::fs::write(network_dir.join("member_cert.pem"), cert.to_pem()).unwrap();
    std::fs::write(
        network_dir.join("sk_self.age"),
        seal_sign_key(sk_self, password),
    )
    .unwrap();
    std::fs::write(
        network_dir.join("network_state.cbor.pem"),
        sample_network_state(root, cert).to_pem(),
    )
    .unwrap();
}

fn write_trust_domain_meta(path: &Path, meta: &SignedTrustDomainMeta) {
    std::fs::write(
        path,
        wrap_armored(TRUST_DOMAIN_META_PEM_LABEL, &to_canonical_cbor(meta)),
    )
    .unwrap();
}

fn sample_context_parts() -> (TrustDomainRoot, String, MemberCert, SignKey) {
    let root = TrustDomainRoot::generate();
    let sk_self = SignKey::generate();
    let network_local_id = NETWORK_LOCAL_ID.to_owned();
    let cert = sample_unsigned_member_cert(&root, &sk_self, &network_local_id).sign(&root);
    (root, network_local_id, cert, sk_self)
}

fn relay_serving_config_toml(
    domain_dir: &Path,
    network_local_id: &str,
    password_env: &str,
    foreign_root_hex: &str,
    foreign_meta_path: &Path,
    foreign_state_path: &Path,
) -> String {
    format!(
        "[network_identity]\nnetwork_name = \"test-network\"\n\n[trust_domain]\ndomain_dir = \"{}\"\nnetwork_local_id = \"{}\"\nsk_self_password_env = \"{}\"\n\n[[trust_domain.relay_serving]]\nforeign_root_pk_hex = \"{}\"\nforeign_trust_domain_meta_pem = \"{}\"\nforeign_network_state_pem = \"{}\"\ncan_relay_data = true\ncan_assist_holepunch = false\nexpires_at = 1800000000\n",
        domain_dir.display(),
        network_local_id,
        password_env,
        foreign_root_hex,
        foreign_meta_path.display(),
        foreign_state_path.display(),
    )
}

fn no_relay_serving_config_toml(
    domain_dir: &Path,
    network_local_id: &str,
    password_env: &str,
) -> String {
    format!(
        "[network_identity]\nnetwork_name = \"test-network\"\n\n[trust_domain]\ndomain_dir = \"{}\"\nnetwork_local_id = \"{}\"\nsk_self_password_env = \"{}\"\n",
        domain_dir.display(),
        network_local_id,
        password_env,
    )
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{b:02x}").unwrap();
    }
    out
}

async fn load_pool(cfg: &TomlConfigLoader) -> Arc<RwLock<TrustDomainPool>> {
    let global_ctx = Arc::new(GlobalCtx::new(cfg.clone()));
    inject_trust_pool_from_config(cfg, global_ctx)
        .await
        .unwrap()
        .unwrap()
        .0
}

#[tokio::test]
async fn test_foreign_root_injected_into_pool() {
    let local_dir = tempfile::tempdir().unwrap();
    let foreign_dir = tempfile::tempdir().unwrap();
    let (local_root, network_local_id, local_cert, local_sk) = sample_context_parts();
    let (foreign_root, _, foreign_cert, foreign_sk) = sample_context_parts();
    write_domain_files(
        local_dir.path(),
        &network_local_id,
        &local_root,
        &local_cert,
        &local_sk,
        PASSWORD,
    );
    write_domain_files(
        foreign_dir.path(),
        &network_local_id,
        &foreign_root,
        &foreign_cert,
        &foreign_sk,
        PASSWORD,
    );

    let foreign_meta = sample_trust_domain_meta(&foreign_root);
    let foreign_meta_path = foreign_dir.path().join("trust_domain_meta.pem");
    write_trust_domain_meta(&foreign_meta_path, &foreign_meta);
    let foreign_state_path = foreign_dir
        .path()
        .join("networks")
        .join(&network_local_id)
        .join("network_state.cbor.pem");

    let env_name = format!("PNW_TP_FOREIGN_{}", std::process::id());
    unsafe { std::env::set_var(&env_name, PASSWORD) };
    let cfg = TomlConfigLoader::new_from_str(&relay_serving_config_toml(
        local_dir.path(),
        &network_local_id,
        &env_name,
        &encode_hex(foreign_root.public_key().as_bytes()),
        &foreign_meta_path,
        &foreign_state_path,
    ))
    .unwrap();

    let pool = load_pool(&cfg).await;
    let pool = pool.read().await;
    let ids = pool.ids().copied().collect::<Vec<_>>();
    assert!(ids.contains(&local_root.id()));
    assert!(ids.contains(&foreign_root.id()));
    unsafe { std::env::remove_var(env_name) };
}

#[tokio::test]
async fn test_foreign_trust_domain_meta_signature_verifies() {
    let local_dir = tempfile::tempdir().unwrap();
    let foreign_dir = tempfile::tempdir().unwrap();
    let (local_root, network_local_id, local_cert, local_sk) = sample_context_parts();
    let (foreign_root, _, foreign_cert, foreign_sk) = sample_context_parts();
    write_domain_files(
        local_dir.path(),
        &network_local_id,
        &local_root,
        &local_cert,
        &local_sk,
        PASSWORD,
    );
    write_domain_files(
        foreign_dir.path(),
        &network_local_id,
        &foreign_root,
        &foreign_cert,
        &foreign_sk,
        PASSWORD,
    );

    let foreign_meta = sample_trust_domain_meta(&foreign_root);
    let foreign_meta_path = foreign_dir.path().join("trust_domain_meta.pem");
    write_trust_domain_meta(&foreign_meta_path, &foreign_meta);
    let foreign_state_path = foreign_dir
        .path()
        .join("networks")
        .join(&network_local_id)
        .join("network_state.cbor.pem");

    let env_name = format!("PNW_TP_META_{}", std::process::id());
    unsafe { std::env::set_var(&env_name, PASSWORD) };
    let cfg = TomlConfigLoader::new_from_str(&relay_serving_config_toml(
        local_dir.path(),
        &network_local_id,
        &env_name,
        &encode_hex(foreign_root.public_key().as_bytes()),
        &foreign_meta_path,
        &foreign_state_path,
    ))
    .unwrap();

    let pool = load_pool(&cfg).await;
    let pool = pool.read().await;
    let meta = pool.trust_domain_meta(&foreign_root.id()).unwrap();
    meta.verify(&foreign_root.public_key().into()).unwrap();
    assert_eq!(meta, &foreign_meta);
    unsafe { std::env::remove_var(env_name) };
}

#[tokio::test]
async fn test_cross_domain_verify_member_cert_uses_foreign_root() {
    let local_dir = tempfile::tempdir().unwrap();
    let foreign_dir = tempfile::tempdir().unwrap();
    let (local_root, network_local_id, local_cert, local_sk) = sample_context_parts();
    let (foreign_root, _, foreign_cert, foreign_sk) = sample_context_parts();
    write_domain_files(
        local_dir.path(),
        &network_local_id,
        &local_root,
        &local_cert,
        &local_sk,
        PASSWORD,
    );
    write_domain_files(
        foreign_dir.path(),
        &network_local_id,
        &foreign_root,
        &foreign_cert,
        &foreign_sk,
        PASSWORD,
    );

    let foreign_meta = sample_trust_domain_meta(&foreign_root);
    let foreign_meta_path = foreign_dir.path().join("trust_domain_meta.pem");
    write_trust_domain_meta(&foreign_meta_path, &foreign_meta);
    let foreign_state_path = foreign_dir
        .path()
        .join("networks")
        .join(&network_local_id)
        .join("network_state.cbor.pem");

    let env_name = format!("PNW_TP_VERIFY_{}", std::process::id());
    unsafe { std::env::set_var(&env_name, PASSWORD) };
    let cfg = TomlConfigLoader::new_from_str(&relay_serving_config_toml(
        local_dir.path(),
        &network_local_id,
        &env_name,
        &encode_hex(foreign_root.public_key().as_bytes()),
        &foreign_meta_path,
        &foreign_state_path,
    ))
    .unwrap();

    let pool = load_pool(&cfg).await;
    let verified = pool
        .read()
        .await
        .verify_member_cert(&foreign_cert, NOW)
        .unwrap();
    assert_eq!(verified.cert, foreign_cert);
    assert_eq!(verified.signer_id, foreign_root.id());
    unsafe { std::env::remove_var(env_name) };
}

#[tokio::test]
async fn test_config_without_relay_serving_loads_self_root_only() {
    let local_dir = tempfile::tempdir().unwrap();
    let (local_root, network_local_id, local_cert, local_sk) = sample_context_parts();
    write_domain_files(
        local_dir.path(),
        &network_local_id,
        &local_root,
        &local_cert,
        &local_sk,
        PASSWORD,
    );

    let env_name = format!("PNW_TP_SELF_{}", std::process::id());
    unsafe { std::env::set_var(&env_name, PASSWORD) };
    let cfg = TomlConfigLoader::new_from_str(&no_relay_serving_config_toml(
        local_dir.path(),
        &network_local_id,
        &env_name,
    ))
    .unwrap();

    let pool = load_pool(&cfg).await;
    let pool = pool.read().await;
    let ids = pool.ids().copied().collect::<Vec<_>>();
    assert_eq!(ids, vec![local_root.id()]);
    unsafe { std::env::remove_var(env_name) };
}
