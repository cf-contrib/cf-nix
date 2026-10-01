use std::collections::HashMap;

use sha2::{Digest, Sha256};

/// Per-isolate cache of auth results, keyed by the SHA-256 of the credential
/// so raw tokens are never stored.
pub(super) struct TtlCache<V> {
    entries: HashMap<[u8; 32], (u64, V)>,
}

impl<V: Clone> TtlCache<V> {
    /// Upper bound on entries, so a flood of distinct credentials can't grow
    /// the isolate's memory without limit.
    const MAX_ENTRIES: usize = 1024;

    pub(super) fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub(super) fn key(credential: &str) -> [u8; 32] {
        Sha256::digest(credential.as_bytes()).into()
    }

    pub(super) fn get(&self, key: &[u8; 32], now_ms: u64) -> Option<V> {
        self.entries
            .get(key)
            .filter(|(expires_at, _)| now_ms < *expires_at)
            .map(|(_, value)| value.clone())
    }

    pub(super) fn insert(&mut self, key: [u8; 32], value: V, expires_at: u64, now_ms: u64) {
        if self.entries.len() >= Self::MAX_ENTRIES {
            self.entries
                .retain(|_, (expires_at, _)| now_ms < *expires_at);
        }
        if self.entries.len() >= Self::MAX_ENTRIES {
            self.entries.clear();
        }
        self.entries.insert(key, (expires_at, value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_cache_expires_entries() {
        let mut cache = TtlCache::new();
        let key = TtlCache::<u8>::key("token");
        cache.insert(key, 1u8, 100, 0);
        assert_eq!(cache.get(&key, 99), Some(1));
        assert_eq!(cache.get(&key, 100), None);
    }

    #[test]
    fn ttl_cache_is_bounded() {
        let mut cache = TtlCache::new();
        for i in 0..=TtlCache::<u8>::MAX_ENTRIES {
            cache.insert(TtlCache::<u8>::key(&i.to_string()), 1u8, 100, 0);
        }
        assert!(cache.entries.len() <= TtlCache::<u8>::MAX_ENTRIES);
    }
}
