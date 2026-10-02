use std::collections::HashMap;

use sha2::{Digest, Sha256};

use super::{AuthError, Identity};

/// Per-isolate cache of auth results, keyed by the SHA-256 of the credential
/// so raw tokens are never stored.
///
/// Holds refusals (`403`) as well as identities, so a token no claim set
/// allows isn't verified again on every request either.
pub(super) struct IdentityCache {
    entries: HashMap<[u8; 32], (u64, Result<Identity, AuthError>)>,
}

impl IdentityCache {
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

    pub(super) fn get(&self, key: &[u8; 32], now_ms: u64) -> Option<Result<Identity, AuthError>> {
        self.entries
            .get(key)
            .filter(|(expires_at, _)| now_ms < *expires_at)
            .map(|(_, result)| result.clone())
    }

    pub(super) fn insert(
        &mut self,
        key: [u8; 32],
        result: Result<Identity, AuthError>,
        expires_at: u64,
        now_ms: u64,
    ) {
        if self.entries.len() >= Self::MAX_ENTRIES {
            self.entries
                .retain(|_, (expires_at, _)| now_ms < *expires_at);
        }
        if self.entries.len() >= Self::MAX_ENTRIES {
            self.entries.clear();
        }
        self.entries.insert(key, (expires_at, result));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Result<Identity, AuthError> {
        Ok(Identity {
            issuer: "https://issuer.example.com".to_string(),
            subject: "repo:example-org/app:ref:refs/heads/main".to_string(),
            claims: 0,
        })
    }

    #[test]
    fn identity_cache_expires_entries() {
        let mut cache = IdentityCache::new();
        let key = IdentityCache::key("token");
        cache.insert(key, identity(), 100, 0);
        assert_eq!(cache.get(&key, 99), Some(identity()));
        assert_eq!(cache.get(&key, 100), None);
    }

    #[test]
    fn identity_cache_holds_refusals() {
        let mut cache = IdentityCache::new();
        let key = IdentityCache::key("token");
        let refused = Err(AuthError::Forbidden("no claim set matched".to_string()));
        cache.insert(key, refused.clone(), 100, 0);
        assert_eq!(cache.get(&key, 0), Some(refused));
    }

    #[test]
    fn identity_cache_is_bounded() {
        let mut cache = IdentityCache::new();
        for i in 0..=IdentityCache::MAX_ENTRIES {
            cache.insert(IdentityCache::key(&i.to_string()), identity(), 100, 0);
        }
        assert!(cache.entries.len() <= IdentityCache::MAX_ENTRIES);
    }
}
