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
//! The provider list's format is here too: [`ProviderConfig`], its claim sets
//! and their patterns, and what parsing checks. Checking a token against it
//! is in the auth [`layer`](super::layer).

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{Map, Value};
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
    pub(super) issuer: String,
    /// Expected `aud`. A trailing `/` is ignored, here and in the token.
    pub(super) audience: String,
    /// Where its keys are. `None` means its discovery document says.
    #[serde(default)]
    pub(super) jwks_uri: Option<String>,
    /// A token is accepted if any claim set matches; the first one wins.
    pub(super) claims: Vec<ClaimSet>,
}

impl ProviderConfig {
    /// The providers in `CF_NIX_CACHE_API_OIDC_PROVIDERS`: none if it's unset
    /// or empty, which turns uploads off.
    fn from_env(env: &Env) -> worker::Result<Vec<Self>> {
        let value = env.var(PROVIDERS_KEY).ok().map(|value| value.to_string());
        Self::from_var(value.as_deref()).map_err(Error::RustError)
    }

    /// The providers in `value`, `CF_NIX_CACHE_API_OIDC_PROVIDERS`'s value:
    /// none if it's unset or empty, which turns uploads off.
    ///
    /// # Errors
    ///
    /// Why `value` isn't a valid provider list.
    pub fn from_var(value: Option<&str>) -> Result<Vec<Self>, String> {
        match value.filter(|value| !value.is_empty()) {
            Some(value) => Self::parse(value),
            None => Ok(Vec::new()),
        }
    }

    fn parse(json: &str) -> Result<Vec<Self>, String> {
        let providers: Vec<Self> = serde_json::from_str(json).map_err(|err| {
            format!(
                "{PROVIDERS_KEY} must be a JSON array of {{ issuer, audience, jwks_uri?, claims }}: {err}"
            )
        })?;
        if providers.is_empty() {
            return Err(format!("{PROVIDERS_KEY} must name at least one provider"));
        }
        for (index, provider) in providers.iter().enumerate() {
            provider.check(&format!("{PROVIDERS_KEY}[{index}]"))?;
            if providers[..index]
                .iter()
                .any(|other| other.issuer == provider.issuer)
            {
                return Err(format!(
                    "{PROVIDERS_KEY}[{index}]: {} is configured twice",
                    provider.issuer
                ));
            }
        }
        Ok(providers)
    }

    /// What deserializing can't check.
    fn check(&self, at: &str) -> Result<(), String> {
        check_url(&self.issuer).map_err(|why| format!("{at}.issuer {why}"))?;
        if let Some(jwks_uri) = &self.jwks_uri {
            check_url(jwks_uri).map_err(|why| format!("{at}.jwks_uri {why}"))?;
        }
        if self.audience.trim_end_matches('/').is_empty() {
            return Err(format!("{at}.audience must not be empty"));
        }
        if self.claims.is_empty() {
            return Err(format!("{at}.claims must contain at least one claim set"));
        }
        Ok(())
    }

    /// Whether `aud`, one of a token's audiences, is this issuer's.
    pub(super) fn audience_is(&self, aud: &str) -> bool {
        aud.trim_end_matches('/') == self.audience.trim_end_matches('/')
    }
}

/// Whether `url` is somewhere keys may be fetched from: HTTPS, or plain HTTP
/// on a loopback address, for a local issuer in development.
pub(super) fn check_url(url: &str) -> Result<(), &'static str> {
    let loopback = ["http://127.0.0.1", "http://localhost", "http://[::1]"]
        .iter()
        .any(|prefix| {
            url.strip_prefix(prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '/']))
        });
    let https = url
        .strip_prefix("https://")
        .is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/'));
    if url.contains(char::is_whitespace) || !(https || loopback) {
        return Err("must be an https:// URL");
    }
    Ok(())
}

/// Claim name to pattern. Matches when every claim matches.
#[derive(Debug, Deserialize)]
#[serde(try_from = "Map<String, Value>")]
pub(super) struct ClaimSet(BTreeMap<String, Pattern>);

impl TryFrom<Map<String, Value>> for ClaimSet {
    type Error = String;

    fn try_from(raw: Map<String, Value>) -> Result<Self, String> {
        if raw.is_empty() {
            return Err("a claim set must match at least one claim".to_string());
        }

        let mut claims = BTreeMap::new();
        for (claim, value) in raw {
            // IDs may be written as JSON numbers; most issuers send strings.
            let pattern = match value {
                Value::String(s) if !s.is_empty() => s,
                Value::Number(n) if n.is_u64() => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => {
                    return Err(format!(
                        "claim {claim} must be a non-empty string, a number or a boolean"
                    ));
                }
            };
            let pattern = Pattern::parse(&pattern)
                .filter(|pattern| !is_id_claim(&claim) || matches!(pattern, Pattern::Exact(_)))
                .ok_or_else(|| {
                    if is_id_claim(&claim) {
                        format!("claim {claim}: ID claims must match exactly")
                    } else {
                        format!("claim {claim}: * may only end a pattern, after a prefix")
                    }
                })?;
            claims.insert(claim, pattern);
        }
        Ok(Self(claims))
    }
}

impl ClaimSet {
    pub(super) fn matches(&self, claims: &Map<String, Value>) -> bool {
        self.0
            .iter()
            .all(|(claim, pattern)| match claims.get(claim) {
                // A list claim (`groups`, `amr`) matches if any entry does.
                Some(Value::Array(values)) => {
                    values.iter().any(|value| pattern.matches_value(value))
                }
                Some(value) => pattern.matches_value(value),
                None => false,
            })
    }
}

/// A claim's expected value: exact, or a prefix written with one trailing
/// `*` (`example-org/*`). `*_id` claims must be exact.
#[derive(Debug, PartialEq)]
enum Pattern {
    Exact(String),
    Prefix(String),
}

impl Pattern {
    /// `None` for a `*` anywhere but at the end of a non-empty prefix.
    fn parse(pattern: &str) -> Option<Self> {
        match pattern.strip_suffix('*') {
            Some(prefix) if !prefix.is_empty() && !prefix.contains('*') => {
                Some(Self::Prefix(prefix.to_string()))
            }
            Some(_) => None,
            None if pattern.contains('*') => None,
            None => Some(Self::Exact(pattern.to_string())),
        }
    }

    fn matches(&self, value: &str) -> bool {
        match self {
            Self::Exact(expected) => value == expected,
            Self::Prefix(prefix) => value.starts_with(prefix.as_str()),
        }
    }

    /// Numbers and booleans compare as they're written in JSON.
    fn matches_value(&self, value: &Value) -> bool {
        match value {
            Value::String(s) => self.matches(s),
            Value::Number(n) => self.matches(&n.to_string()),
            Value::Bool(b) => self.matches(if *b { "true" } else { "false" }),
            _ => false,
        }
    }
}

fn is_id_claim(claim: &str) -> bool {
    claim.ends_with("_id")
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
pub(super) mod tests {
    use serde_json::json;

    use super::*;

    pub(crate) const NOW: u64 = 1_800_000_000;
    pub(crate) const ISSUER: &str = "https://issuer.example.com";

    /// One provider with these claim sets.
    pub(crate) fn config(issuer: &str, claims: Value) -> Vec<ProviderConfig> {
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

    pub(crate) fn claims() -> Map<String, Value> {
        json!({
            "iss": ISSUER,
            "aud": "https://cache.example.com",
            "sub": "repo:example-org/app:ref:refs/heads/main",
            "exp": NOW + 300,
            "nbf": NOW - 10,
            "iat": NOW - 10,
            "repository": "example-org/app",
            "repository_id": "200000002",
            "repository_owner_id": "100000001",
            "ref": "refs/heads/main",
            "groups": ["cache-readers", "cache-uploaders"],
            "email_verified": true,
        })
        .as_object()
        .unwrap()
        .clone()
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
            (json!([issuer(ISSUER), issuer(ISSUER)]), "configured twice"),
            (json!([issuer("http://issuer.example.com")]), "https://"),
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
    fn audience_ignores_a_trailing_slash_on_either_side() {
        let json = json!([{ "issuer": ISSUER, "audience": "https://cache.example.com/", "claims": [{ "ref": "x" }] }]);
        let config = ProviderConfig::parse(&json.to_string()).unwrap();
        let provider = &config[0];
        assert!(provider.audience_is("https://cache.example.com"));
        assert!(provider.audience_is("https://cache.example.com/"));
        assert!(!provider.audience_is("https://cache.example.com.evil"));
    }

    #[test]
    fn config_rejects_bad_claim_sets() {
        let cases = [
            (json!([]), "at least one claim set"),
            (json!([{}]), "a claim set must match at least one claim"),
            (
                json!([{ "repository_id": "2000*" }]),
                "claim repository_id: ID claims must match exactly",
            ),
            (json!([{ "ref": "" }]), "non-empty string"),
            (json!([{ "ref": null }]), "non-empty string"),
            (
                json!([{ "ref": "*" }]),
                "claim ref: * may only end a pattern",
            ),
            (json!([{ "ref": "*main" }]), "may only end a pattern"),
            (json!([{ "ref": "refs/*/main" }]), "may only end a pattern"),
            (json!([{ "ref": "refs/**" }]), "may only end a pattern"),
        ];
        for (claims, expected) in cases {
            let err = parse_err(json!([{ "issuer": ISSUER, "audience": "x", "claims": claims }]));
            assert!(err.contains(expected), "{claims}: {err}");
        }
    }

    #[test]
    fn pattern_is_exact_or_a_trailing_prefix() {
        let parse = |p| Pattern::parse(p).unwrap();
        assert!(parse("example-org/*").matches("example-org/app"));
        assert!(parse("refs/heads/*").matches("refs/heads/feature/x"));
        assert!(parse("refs/heads/main").matches("refs/heads/main"));
        assert!(!parse("refs/heads/main").matches("refs/heads/main2"));
        assert!(!parse("example-org/*").matches("other-org/app"));
        for pattern in ["*", "*x", "a*b", "a**"] {
            assert_eq!(Pattern::parse(pattern), None, "{pattern}");
        }
    }

    #[test]
    fn claim_set_needs_every_claim_to_match() {
        let config = config(
            ISSUER,
            json!([{ "repository": "example-org/*", "ref": "refs/heads/main" }]),
        );
        let set = &config[0].claims[0];
        assert!(set.matches(&claims()));

        let mut other_ref = claims();
        other_ref.insert("ref".into(), "refs/heads/dev".into());
        assert!(!set.matches(&other_ref));
    }

    #[test]
    fn claim_set_matches_lists_numbers_and_booleans() {
        let config = config(
            ISSUER,
            json!([
                { "groups": "cache-uploaders" },
                { "email_verified": true },
                { "repository_id": 200000002 },
                { "groups": "admins" },
                { "environment": "release" },
            ]),
        );
        let sets = &config[0].claims;
        assert!(
            sets[0].matches(&claims()),
            "a list matches if any entry does"
        );
        assert!(sets[1].matches(&claims()), "booleans compare as written");
        assert!(sets[2].matches(&claims()), "numbers compare as written");
        assert!(!sets[3].matches(&claims()));
        assert!(!sets[4].matches(&claims()), "a missing claim never matches");
    }
}
