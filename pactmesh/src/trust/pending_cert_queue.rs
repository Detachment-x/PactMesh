use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::VerifyingKey;
use pnet::ipnetwork::IpNetwork as IpNet;

use super::{
    Capabilities, JoinRequest, MemberCert, TrustDomainRoot, UnsignedMemberCert,
    config_sync_service::PendingCertCache,
};

const DEFAULT_CERT_LIFETIME_SECS: u64 = 365 * 24 * 60 * 60;

#[derive(Clone)]
pub struct PendingCertQueue {
    entries: HashMap<[u8; 32], JoinRequest>,
    root: TrustDomainRoot,
    pending_cert_cache: Option<Arc<Mutex<PendingCertCache>>>,
    default_capabilities: Capabilities,
    default_network_state_version_ref: u64,
    default_cert_lifetime_secs: u64,
}

impl PendingCertQueue {
    pub fn new(root: TrustDomainRoot) -> Self {
        Self {
            entries: HashMap::new(),
            root,
            pending_cert_cache: None,
            default_capabilities: Capabilities {
                can_relay_data: false,
                can_relay_control: false,
                can_proxy_subnet: Vec::<IpNet>::new(),
                can_be_exit_node: false,
            },
            default_network_state_version_ref: 0,
            default_cert_lifetime_secs: DEFAULT_CERT_LIFETIME_SECS,
        }
    }

    pub fn with_pending_cert_cache(
        mut self,
        pending_cert_cache: Arc<Mutex<PendingCertCache>>,
    ) -> Self {
        self.pending_cert_cache = Some(pending_cert_cache);
        self
    }

    pub fn with_default_network_state_version_ref(mut self, version: u64) -> Self {
        self.default_network_state_version_ref = version;
        self
    }

    pub fn enqueue(&mut self, jr: JoinRequest) {
        self.entries.insert(jr.applicant_pk.0, jr);
    }

    pub fn contains(&self, applicant_pk: &[u8]) -> bool {
        self.entries.contains_key(&to_applicant_key(applicant_pk))
    }

    pub fn try_approve(&mut self, applicant_pk: &[u8]) -> Option<MemberCert> {
        if self.contains(applicant_pk) {
            Some(self.approve(applicant_pk))
        } else {
            None
        }
    }

    pub fn try_approve_with_cert(
        &mut self,
        applicant_pk: &[u8],
        cert: MemberCert,
    ) -> Option<MemberCert> {
        let applicant_pk = to_applicant_key(applicant_pk);
        self.entries.remove(&applicant_pk)?;
        if let Some(cache) = self.pending_cert_cache.as_ref() {
            cache.lock().unwrap().insert(cert.clone());
        }
        Some(cert)
    }

    pub fn try_reject(&mut self, applicant_pk: &[u8]) -> bool {
        self.entries
            .remove(&to_applicant_key(applicant_pk))
            .is_some()
    }

    pub fn approve(&mut self, applicant_pk: &[u8]) -> MemberCert {
        let applicant_pk = to_applicant_key(applicant_pk);
        let jr = self
            .entries
            .remove(&applicant_pk)
            .expect("pending join request not found");
        let now = now_unix();
        let cert = UnsignedMemberCert {
            trust_domain_id: jr.trust_domain_id,
            network_local_id: jr.network_local_id,
            device_pk: VerifyingKey::from_bytes(&jr.applicant_pk.0)
                .expect("applicant_pk must be a valid ed25519 key"),
            device_label: jr.device_label,
            not_before: now.saturating_sub(1),
            expires_at: now.saturating_add(self.default_cert_lifetime_secs),
            capabilities: self.default_capabilities.clone(),
            network_state_version_ref: self.default_network_state_version_ref,
            hostname: None,
        }
        .sign(&self.root);

        if let Some(cache) = self.pending_cert_cache.as_ref() {
            cache.lock().unwrap().insert(cert.clone());
        }

        cert
    }

    pub fn reject(&mut self, applicant_pk: &[u8]) {
        self.entries.remove(&to_applicant_key(applicant_pk));
    }

    pub fn list(&self) -> Vec<JoinRequest> {
        let mut items = self.entries.values().cloned().collect::<Vec<_>>();
        items.sort_by_key(|left| left.applicant_pk.0);
        items
    }
}

fn to_applicant_key(applicant_pk: &[u8]) -> [u8; 32] {
    applicant_pk
        .try_into()
        .expect("applicant_pk must be exactly 32 bytes")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}
