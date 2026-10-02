//! The Worker's configuration, read from its bindings.
//!
//! [`Config::from_env`] is the only place that reads `Env`: the crate root
//! builds one per request and hands it to the handler and the auth layer,
//! which take what they need from it.
//!
//! An unbound bucket or an invalid provider list fails it, and the Worker
//! serves nothing until it's fixed. The signing key's value is read only when
//! an upload needs signing, since reading it is async.

use worker::{Bucket, Env, Error, SecretStore, send::SendWrapper};

use super::layer::ProviderConfig;

/// The binding of the R2 bucket every narinfo and NAR is stored in.
pub const BUCKET_KEY: &str = "CF_NIX_CACHE_API_BUCKET";

/// The binding of the narinfo signing key.
pub const SECRET_KEY: &str = "CF_NIX_CACHE_API_SECRET";

/// The binding of the providers whose tokens may upload.
pub const PROVIDERS_KEY: &str = "CF_NIX_CACHE_API_OIDC_PROVIDERS";

/// What the Worker is configured with, from its bindings.
pub struct Config {
    /// `CF_NIX_CACHE_API_BUCKET`.
    bucket: BucketConfig,
    /// `CF_NIX_CACHE_API_SECRET`'s binding, not yet its value.
    secret: SecretConfig,
    /// `CF_NIX_CACHE_API_OIDC_PROVIDERS`. None turns uploads off.
    providers: Vec<ProviderConfig>,
}

impl Config {
    /// Reads the Worker's bindings.
    ///
    /// # Errors
    ///
    /// When `CF_NIX_CACHE_API_BUCKET` isn't bound to an R2 bucket, or
    /// `CF_NIX_CACHE_API_OIDC_PROVIDERS` isn't a valid provider list.
    pub fn from_env(env: &Env) -> worker::Result<Self> {
        Ok(Self {
            bucket: BucketConfig::from_env(env)?,
            secret: SecretConfig::from_env(env),
            providers: ProviderConfig::from_env(env)?,
        })
    }

    /// The bucket every narinfo and NAR is stored in.
    pub fn bucket(&self) -> &Bucket {
        &self.bucket.0
    }

    /// The providers whose tokens may upload: none if uploads are off.
    pub fn providers(&self) -> &[ProviderConfig] {
        &self.providers
    }

    /// Reads the narinfo signing key, or `None` if none is configured.
    pub async fn secret(&self) -> worker::Result<Option<String>> {
        self.secret.read().await
    }
}

/// The R2 bucket every narinfo and NAR is stored in. A `Bucket` holds a
/// JavaScript value, so it isn't `Send`; a Worker is single-threaded, so the
/// wrapper asserts it.
struct BucketConfig(SendWrapper<Bucket>);

impl BucketConfig {
    fn from_env(env: &Env) -> worker::Result<Self> {
        let bucket = env.bucket(BUCKET_KEY).map_err(|err| {
            Error::RustError(format!("{BUCKET_KEY} isn't bound to an R2 bucket: {err}"))
        })?;
        Ok(Self(SendWrapper::new(bucket)))
    }
}

impl ProviderConfig {
    /// The providers in `CF_NIX_CACHE_API_OIDC_PROVIDERS`: none if it's unset
    /// or empty, which turns uploads off.
    fn from_env(env: &Env) -> worker::Result<Vec<Self>> {
        let value = env.var(PROVIDERS_KEY).ok().map(|value| value.to_string());
        Self::from_var(value.as_deref()).map_err(Error::RustError)
    }
}

/// Where the narinfo signing key is.
///
/// Deployments bind it from Secrets Store, so the key never passes through
/// Terraform. `wrangler dev` and plain `secret_text` bindings are read as a
/// var.
enum SecretConfig {
    Store(SecretStore),
    Text(String),
    Unset,
}

impl SecretConfig {
    fn from_env(env: &Env) -> Self {
        if let Ok(store) = env.secret_store(SECRET_KEY) {
            return Self::Store(store);
        }
        match env.var(SECRET_KEY) {
            Ok(secret) => Self::Text(secret.to_string()),
            Err(_) => Self::Unset,
        }
    }

    async fn read(&self) -> worker::Result<Option<String>> {
        match self {
            Self::Store(store) => store.get().await,
            Self::Text(secret) => Ok(Some(secret.clone())),
            Self::Unset => Ok(None),
        }
    }
}
