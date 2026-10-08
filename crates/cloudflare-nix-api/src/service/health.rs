//! The cache's readiness check, for `/health/ready`.
//!
//! [`Config::from_env`] checks what it can without reading anything: the
//! bindings and the provider list, and a Worker that fails it serves nothing.
//! [`ConfigCheck`] checks the rest of the configuration, what only reading it
//! can: the signing key, if one is bound, read and parsed as an upload would
//! sign with it. A key that's bound but can't be read, say one Secrets Store
//! won't hand over, or that isn't a valid key, then shows up as `503` on the
//! probe, with why in the log, not only as a `500` on the first upload that
//! needs signing.
//!
//! It doesn't touch the bucket or fetch any issuer's keys: the endpoint is
//! public, and anyone probing it would spend R2 operations and the issuers'
//! rate limits.

use std::{future::Future, sync::Arc};

use cloudflare_nix_sdk::v1::{HealthCheck, HealthCheckError, NarInfoSigKey};
use worker::{console_error, send::SendFuture};

use super::config::{Config, SECRET_KEY};

/// Checks the configuration as an upload would read it.
pub struct ConfigCheck {
    config: Arc<Config>,
}

impl ConfigCheck {
    /// A check over the Worker's configuration, shared with the handler.
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    /// Reads the signing key if one is bound, and derives its public half,
    /// which takes a valid key pair.
    async fn read_signing_key(&self) -> Result<(), String> {
        let Some(secret) = self
            .config
            .signing_key()
            .await
            .map_err(|err| format!("reading {SECRET_KEY} failed: {err}"))?
        else {
            return Ok(());
        };
        NarInfoSigKey::parse(&secret)
            .and_then(|key| key.public_key())
            .map_err(|err| format!("{SECRET_KEY} isn't a valid signing key: {err}"))?;
        Ok(())
    }
}

impl HealthCheck for ConfigCheck {
    // Secrets Store futures aren't `Send`: they hold JavaScript values. A
    // Worker is single-threaded, so the check runs in a `SendFuture`, as the
    // handler's methods do.
    fn check(&self) -> impl Future<Output = Result<(), HealthCheckError>> + Send {
        SendFuture::new(async move {
            self.read_signing_key().await.map_err(|why| {
                console_error!("unready: {why}");
                why.into()
            })
        })
    }
}
