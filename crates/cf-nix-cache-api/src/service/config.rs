//! The Worker's configuration, read from its bindings.
//!
//! [`Config::from_env`] is the only place that reads `Env`: the crate root
//! builds one per request and hands it to the handler and the auth layer,
//! which take what they need from it.
//!
//! An unbound bucket or an invalid provider list fails it, and the Worker
//! serves nothing until it's fixed. The signing key's value is read only when
//! an upload needs signing, since reading it is async.
//!
//! The provider list's format is here too: [`ProviderConfig`], a
//! [`Provider`] with the claim sets that let its tokens upload, and what
//! parsing checks. Verifying a token against it is cf-oidc-core's, which the
//! auth [`layer`](super::layer) calls.

use cf_oidc_core::{ClaimRules, Provider, Providers};
use serde::Deserialize;
use worker::{Bucket, Env, Error, SecretStore, send::SendWrapper};

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
    providers: Providers<ProviderConfig>,
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
    pub fn providers(&self) -> &Providers<ProviderConfig> {
        &self.providers
    }

    /// Reads the narinfo signing key, `<key-name>:<base64>`, or `None` if
    /// none is configured.
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

/// One identity provider: its issuer, the audience its tokens must be for,
/// and who may upload.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    /// Matched exactly against a token's `iss`.
    issuer: String,
    /// Expected `aud`. A trailing `/` is ignored, here and in the token.
    audience: String,
    /// Where its keys are. `None` means its metadata says.
    #[serde(default)]
    jwks_uri: Option<String>,
    /// The `typ` its tokens must have: `at+jwt` for a cf-oidc-exchange
    /// broker's, so no other token it signs can upload. `None` takes any.
    #[serde(default)]
    typ: Option<String>,
    /// A token is accepted if any claim set matches; the first one wins.
    pub(super) claims: ClaimRules,
}

impl Provider for ProviderConfig {
    fn issuer(&self) -> &str {
        &self.issuer
    }

    fn audience(&self) -> &str {
        &self.audience
    }

    fn jwks_uri(&self) -> Option<&str> {
        self.jwks_uri.as_deref()
    }

    fn typ(&self) -> Option<&str> {
        self.typ.as_deref()
    }
}

impl ProviderConfig {
    /// The providers in `CF_NIX_CACHE_API_OIDC_PROVIDERS`: none if it's unset
    /// or empty, which turns uploads off.
    fn from_env(env: &Env) -> worker::Result<Providers<Self>> {
        let value = env.var(PROVIDERS_KEY).ok().map(|value| value.to_string());
        Self::from_var(value.as_deref()).map_err(Error::RustError)
    }

    /// The providers in `value`, `CF_NIX_CACHE_API_OIDC_PROVIDERS`'s value:
    /// none if it's unset or empty, which turns uploads off.
    ///
    /// # Errors
    ///
    /// Why `value` isn't a valid provider list.
    pub fn from_var(value: Option<&str>) -> Result<Providers<Self>, String> {
        match value.filter(|value| !value.is_empty()) {
            Some(value) => Self::parse(value),
            None => Ok(Providers::from(Vec::new())),
        }
    }

    /// The providers in `json`, checked: cf-oidc-core checks the providers,
    /// and each one's claim sets, saying where anything's wrong.
    fn parse(json: &str) -> Result<Providers<Self>, String> {
        let providers: Providers<Self> = serde_json::from_str(json).map_err(|err| {
            format!(
                "{PROVIDERS_KEY} must be a JSON array of {{ issuer, audience, jwks_uri?, typ?, claims }}: {err}"
            )
        })?;
        providers.check(PROVIDERS_KEY)?;
        for (index, provider) in providers.iter().enumerate() {
            provider
                .claims
                .check(&format!("{PROVIDERS_KEY}[{index}].claims"))?;
        }
        Ok(providers)
    }
}

/// Where the narinfo signing key is.
///
/// Deployments bind it from Secrets Store, so the key never passes through
/// Terraform. `wrangler dev` and plain `secret_text` bindings are read as a
/// var.
enum SecretConfig {
    /// A Secrets Store binding, read when an upload needs signing.
    Store(SecretStore),
    /// A plain secret or var.
    Text(String),
    /// Neither: only narinfo the uploader signed can be stored.
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

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    const ISSUER: &str = "https://issuer.example.com";

    /// One provider with these claim sets.
    fn config(issuer: &str, claims: Value) -> Providers<ProviderConfig> {
        let json = json!([{
            "issuer": issuer,
            "audience": "https://cache.example.com",
            "claims": claims,
        }]);
        ProviderConfig::parse(&json.to_string()).expect("config should parse")
    }

    fn parse_err(json: Value) -> String {
        ProviderConfig::parse(&json.to_string()).unwrap_err()
    }

    #[test]
    fn config_is_off_without_providers() {
        assert!(ProviderConfig::from_var(None).unwrap().is_empty());
        assert!(ProviderConfig::from_var(Some("")).unwrap().is_empty());
    }

    #[test]
    fn config_fails_closed() {
        assert!(ProviderConfig::from_var(Some("not json")).is_err());
    }

    #[test]
    fn config_rejects_bad_issuer_lists() {
        let issuer = |issuer: &str| json!({ "issuer": issuer, "audience": "https://cache.example.com", "claims": [{ "ref": "x" }] });
        let cases = [
            (json!("not a list"), "JSON array"),
            (json!([]), "at least one provider"),
            (
                json!([{ "issuer": ISSUER, "claims": [] }]),
                "missing field `audience`",
            ),
            (
                json!([issuer(ISSUER), issuer(ISSUER)]),
                "CF_NIX_CACHE_API_OIDC_PROVIDERS[1]: https://issuer.example.com is configured twice",
            ),
            (
                json!([issuer("http://issuer.example.com")]),
                "CF_NIX_CACHE_API_OIDC_PROVIDERS[0].issuer must be an https:// URL",
            ),
            (json!([issuer("https://")]), "https://"),
            (
                json!([{ "issuer": ISSUER, "audience": "https://cache.example.com", "claims": [{ "ref": "x" }], "extra": 1 }]),
                "unknown field `extra`",
            ),
        ];
        for (json, expected) in cases {
            let err = parse_err(json.clone());
            assert!(err.contains(expected), "{json}: {err}");
        }
    }

    #[test]
    fn config_allows_http_only_on_loopback() {
        for issuer in [
            "http://127.0.0.1:8788",
            "http://localhost",
            "http://[::1]:9000/oidc",
        ] {
            config(issuer, json!([{ "ref": "x" }]));
        }
        for issuer in [
            "http://127.0.0.1.example.com",
            "http://localhost.example.com",
        ] {
            let err = parse_err(
                json!([{ "issuer": issuer, "audience": "x", "claims": [{ "ref": "x" }] }]),
            );
            assert!(err.contains("https://"), "{issuer}: {err}");
        }
    }

    #[test]
    fn config_rejects_bad_audiences_and_jwks_uris() {
        let cases = [
            (
                json!([{ "issuer": ISSUER, "audience": "/", "claims": [{ "ref": "x" }] }]),
                "audience must not be empty",
            ),
            (
                json!([{ "issuer": ISSUER, "audience": "x", "jwks_uri": "http://keys.example.com", "claims": [{ "ref": "x" }] }]),
                "jwks_uri must be an https:// URL",
            ),
        ];
        for (json, expected) in cases {
            let err = parse_err(json.clone());
            assert!(err.contains(expected), "{json}: {err}");
        }
    }

    #[test]
    fn config_rejects_bad_claim_sets() {
        let cases = [
            (
                json!([]),
                "CF_NIX_CACHE_API_OIDC_PROVIDERS[0].claims must contain at least one claim set",
            ),
            (json!([{}]), "a claim set must match at least one claim"),
            (
                json!([{ "repository_id": "2000*" }]),
                "claim repository_id: ID claims must match exactly",
            ),
            (json!([{ "ref": "" }]), "non-empty string"),
            (json!([{ "ref": "*main" }]), "may only end a pattern"),
        ];
        for (claims, expected) in cases {
            let err = parse_err(json!([{ "issuer": ISSUER, "audience": "x", "claims": claims }]));
            assert!(err.contains(expected), "{claims}: {err}");
        }
    }

    #[test]
    fn config_takes_the_typ_a_providers_tokens_must_have() {
        let json = json!([
            { "issuer": ISSUER, "audience": "x", "claims": [{ "ref": "x" }] },
            { "issuer": "https://broker.example.com", "audience": "x", "typ": "at+jwt", "claims": [{ "profile": "nix-push" }] },
        ]);
        let providers = ProviderConfig::parse(&json.to_string()).unwrap();
        assert_eq!(providers[0].typ(), None);
        assert_eq!(providers[1].typ(), Some(cf_oidc_core::AT_JWT));
    }
}
