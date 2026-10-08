//! The Worker's configuration, read from its bindings.
//!
//! [`Config::from_env`] is the only place that reads `Env`: the crate root
//! builds one per request and hands it to the handler and the auth layer,
//! which take what they need from it.
//!
//! An unbound bucket, an invalid provider list, or a signing key that isn't a
//! Secrets Store binding fails it, and the Worker serves nothing until it's
//! fixed. The signing key's value is read only when an upload needs signing,
//! since reading it is async, so a rotated one takes effect on the next.
//!
//! The provider list's format is here too: [`ProviderConfig`], a
//! [`Provider`] with the claim sets that let its tokens upload, and what
//! parsing checks. Verifying a token against it is cf-sts-core's, which the
//! auth [`layer`](super::layer) calls.

use cf_sts_core::{ClaimRules, Provider, Providers};
use serde::Deserialize;
use worker::{Bucket, Env, Error, SecretStore, js_sys, send::SendWrapper, wasm_bindgen::JsValue};

/// The binding of the R2 bucket every narinfo and NAR is stored in.
pub const BUCKET_KEY: &str = "CLOUDFLARE_NIX_API_BUCKET";

/// The binding of the narinfo signing key, `<key-name>:<base64>`. Optional:
/// without it, only narinfo the uploader signed can be stored.
pub const SECRET_KEY: &str = "CLOUDFLARE_NIX_API_SECRET";

/// The binding of the providers whose tokens may upload.
pub const PROVIDERS_KEY: &str = "CLOUDFLARE_NIX_API_OIDC_PROVIDERS";

/// What the Worker is configured with, from its bindings.
pub struct Config {
    /// `CLOUDFLARE_NIX_API_BUCKET`.
    bucket: BucketConfig,
    /// `CLOUDFLARE_NIX_API_SECRET`'s binding, not yet its value. None signs
    /// nothing.
    signing_key: Option<Secret>,
    /// `CLOUDFLARE_NIX_API_OIDC_PROVIDERS`. None turns uploads off.
    providers: Providers<ProviderConfig>,
}

impl Config {
    /// Reads the Worker's bindings.
    ///
    /// # Errors
    ///
    /// When `CLOUDFLARE_NIX_API_BUCKET` isn't bound to an R2 bucket,
    /// `CLOUDFLARE_NIX_API_SECRET` is bound but not from Secrets Store, or
    /// `CLOUDFLARE_NIX_API_OIDC_PROVIDERS` isn't a valid provider list.
    pub fn from_env(env: &Env) -> worker::Result<Self> {
        Ok(Self {
            bucket: BucketConfig::from_env(env)?,
            signing_key: Secret::from_env(env, SECRET_KEY)?,
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
    /// none is bound.
    pub async fn signing_key(&self) -> worker::Result<Option<String>> {
        match &self.signing_key {
            Some(secret) => secret.read().await.map(Some),
            None => Ok(None),
        }
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
    /// The `typ` its tokens must have: `at+jwt` for a cf-sts
    /// broker's, so no other token it signs can upload. `None` takes any.
    #[serde(default)]
    typ: Option<String>,
    /// A token is accepted if any claim set matches; the first one wins.
    pub(super) claims: ClaimRules,
}

/// What the auth layer verifies a token from it against.
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
    /// The providers in `CLOUDFLARE_NIX_API_OIDC_PROVIDERS`: none if it's unset
    /// or empty, which turns uploads off.
    fn from_env(env: &Env) -> worker::Result<Providers<Self>> {
        let value = env.var(PROVIDERS_KEY).ok().map(|value| value.to_string());
        Self::from_var(value.as_deref()).map_err(Error::RustError)
    }

    /// The providers in `value`, `CLOUDFLARE_NIX_API_OIDC_PROVIDERS`'s value:
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

    /// The providers in `json`, checked: cf-sts-core checks the providers,
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

/// A secret in Secrets Store, read when it's used.
///
/// Bound as anything else, a plain Worker secret or a var say, it's refused
/// rather than taken as a weaker setup: a Secrets Store secret never passes
/// through Terraform, or a command line.
struct Secret {
    key: &'static str,
    store: SecretStore,
}

impl Secret {
    /// The secret bound as `key`, or `None` if nothing is.
    fn from_env(env: &Env, key: &'static str) -> worker::Result<Option<Self>> {
        if let Ok(store) = env.secret_store(key) {
            return Ok(Some(Self { key, store }));
        }
        let bound = js_sys::Reflect::get(env.as_ref(), &JsValue::from_str(key))
            .is_ok_and(|binding| !binding.is_undefined());
        if bound {
            return Err(Error::RustError(format!(
                "{key} must be a Secrets Store binding"
            )));
        }
        Ok(None)
    }

    async fn read(&self) -> worker::Result<String> {
        let key = self.key;
        match self.store.get().await {
            Ok(Some(value)) if !value.is_empty() => Ok(value),
            Ok(_) => Err(Error::RustError(format!("{key} is empty"))),
            Err(err) => Err(Error::RustError(format!("{key} can't be read: {err}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    const ISSUER: &str = "https://token.actions.githubusercontent.com";
    const BROKER: &str = "https://cf-sts.example.com";
    const CACHE: &str = "https://cache.example.com";

    /// A provider list: GitHub Actions, pinned to the test org, and a
    /// cf-sts broker, whose access tokens only.
    fn providers() -> Value {
        json!([
            { "issuer": ISSUER, "audience": CACHE, "claims": [{ "repository_owner_id": "100000001" }] },
            { "issuer": BROKER, "audience": CACHE, "typ": "at+jwt", "claims": [{ "profile": "nix-push" }] },
        ])
    }

    fn parse(providers: &Value) -> Providers<ProviderConfig> {
        ProviderConfig::parse(&providers.to_string()).expect("the providers should parse")
    }

    fn parse_err(providers: &Value) -> String {
        ProviderConfig::parse(&providers.to_string()).unwrap_err()
    }

    /// The test providers, with `pointer` set to `value`.
    fn with(pointer: &str, value: Value) -> Value {
        let mut providers = providers();
        let (parent, key) = pointer.rsplit_once('/').unwrap();
        match providers.pointer_mut(parent).unwrap() {
            Value::Object(map) => map.insert(key.to_string(), value),
            Value::Array(list) => {
                list.push(value);
                None
            }
            _ => unreachable!(),
        };
        providers
    }

    #[test]
    fn parses_the_test_providers() {
        let providers = parse(&providers());
        assert_eq!(providers.len(), 2);
        assert_eq!(providers[0].typ(), None);
        assert_eq!(providers[1].typ(), Some(cf_sts_core::AT_JWT));
    }

    #[test]
    fn uploads_are_off_without_providers() {
        assert!(ProviderConfig::from_var(None).unwrap().is_empty());
        assert!(ProviderConfig::from_var(Some("")).unwrap().is_empty());
    }

    #[test]
    fn fails_closed() {
        assert!(ProviderConfig::from_var(Some("not json")).is_err());
    }

    #[test]
    fn rejects_bad_providers() {
        let key = PROVIDERS_KEY;
        let cases = [
            (json!("not a list"), "JSON array".to_string()),
            (json!([]), "at least one provider".to_string()),
            (
                with("/0/claims", json!([])),
                format!("{key}[0].claims must contain at least one claim set"),
            ),
            (
                with("/0/audience", json!("/")),
                format!("{key}[0].audience must not be empty"),
            ),
            (
                with("/0/issuer", json!("http://issuer.example.com")),
                format!("{key}[0].issuer must be an https:// URL"),
            ),
            (
                with("/0/jwks_uri", json!("http://keys.example.com")),
                format!("{key}[0].jwks_uri must be an https:// URL"),
            ),
            (
                with(
                    "/-",
                    json!({ "issuer": ISSUER, "audience": CACHE, "claims": [{ "x": "y" }] }),
                ),
                format!("{key}[2]: {ISSUER} is configured twice"),
            ),
            (
                with("/0/extra", json!(1)),
                "unknown field `extra`".to_string(),
            ),
        ];
        for (providers, expected) in cases {
            let err = parse_err(&providers);
            assert!(err.contains(&expected), "{expected}: {err}");
        }
    }

    #[test]
    fn allows_http_only_on_loopback() {
        for issuer in [
            "http://127.0.0.1:8788",
            "http://localhost",
            "http://[::1]:9000/oidc",
        ] {
            parse(&with("/0/issuer", json!(issuer)));
        }
        for issuer in [
            "http://127.0.0.1.example.com",
            "http://localhost.example.com",
        ] {
            let err = parse_err(&with("/0/issuer", json!(issuer)));
            assert!(err.contains("https://"), "{issuer}: {err}");
        }
    }

    #[test]
    fn rejects_bad_claim_sets() {
        let cases = [
            (json!([{}]), "a claim set must match at least one claim"),
            (
                json!([{ "repository_id": "2000*" }]),
                "claim repository_id: ID claims must match exactly",
            ),
            (json!([{ "ref": "" }]), "non-empty string"),
            (json!([{ "ref": "*main" }]), "may only end a pattern"),
        ];
        for (claims, expected) in cases {
            let err = parse_err(&with("/0/claims", claims.clone()));
            assert!(err.contains(expected), "{claims}: {err}");
        }
    }
}
