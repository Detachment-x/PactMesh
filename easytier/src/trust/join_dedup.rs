use std::{collections::HashMap, time::{Duration, Instant}};

const DEDUP_TTL: Duration = Duration::from_secs(10 * 60);
const GC_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DupError {
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DedupKey {
    applicant_pk: Vec<u8>,
    nonce: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct JoinDedup {
    entries: HashMap<DedupKey, Instant>,
    last_gc_at: Instant,
}

impl Default for JoinDedup {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            last_gc_at: Instant::now(),
        }
    }
}

impl JoinDedup {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_or_drop(&mut self, applicant_pk: &[u8], nonce: &[u8]) -> Result<(), DupError> {
        let now = Instant::now();
        self.gc(now);

        let key = DedupKey {
            applicant_pk: applicant_pk.to_vec(),
            nonce: nonce.to_vec(),
        };
        if self
            .entries
            .get(&key)
            .is_some_and(|seen_at| now.duration_since(*seen_at) < DEDUP_TTL)
        {
            return Err(DupError::Duplicate);
        }

        self.entries.insert(key, now);
        Ok(())
    }

    fn gc(&mut self, now: Instant) {
        if now.duration_since(self.last_gc_at) < GC_INTERVAL {
            return;
        }

        self.entries
            .retain(|_, seen_at| now.duration_since(*seen_at) < DEDUP_TTL);
        self.last_gc_at = now;
    }
}
