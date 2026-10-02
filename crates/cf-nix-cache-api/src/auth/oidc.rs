//! OIDC auth, for any issuer: GitHub Actions, Cloudflare Access, GitLab, or
//! a broker that issues its own tokens.
//!
//! A token picks its issuer by its `iss` claim, which must be one the config
//! names exactly. Its signature is checked against that issuer's keys, found
//! through its discovery document (or a configured `jwks_uri`) and never
//! through anything in the token. Then the standard claims are checked, and
//! the token is accepted if any of the issuer's claim sets matches.

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use web_sys::{CryptoKey, WorkerGlobalScope};
use worker::{
    Date, Fetch, Method, Request,
    js_sys::{self, Uint8Array},
    wasm_bindgen::{JsCast, JsValue},
    wasm_bindgen_futures::JsFuture,
};

use super::{AuthError, Identity, cache::IdentityCache};

/// The binding the config is read from, for error messages.
const VAR: &str = "CF_NIX_CACHE_API_OIDC_ISSUERS";

/// GitHub Actions' issuer. GitHub gives a token for any audience to any
/// repository on github.com, so its claim sets must pin the owner.
const GITHUB_ACTIONS: &str = "https://token.actions.githubusercontent.com";

/// Clock tolerance for `exp` and `nbf`.
const LEEWAY_SECS: u64 = 60;
/// How long a fetched JWKS is trusted before it's fetched again.
const JWKS_TTL_MS: u64 = 60 * 60 * 1000;
/// An unknown `kid` refetches an issuer's JWKS at most this often, so tokens
/// with made-up key IDs can't make the Worker hammer the issuer.
const JWKS_MIN_REFETCH_MS: u64 = 60 * 1000;

thread_local! {
    /// Each issuer's signing keys, by issuer.
    static JWKS: RefCell<HashMap<String, KeySet>> = RefCell::new(HashMap::new());
    static CACHE: RefCell<IdentityCache> = RefCell::new(IdentityCache::new());
}

/// The issuers whose tokens may upload (`CF_NIX_CACHE_API_OIDC_ISSUERS`).
#[derive(Debug)]
pub(super) struct Config {
    issuers: Vec<Issuer>,
}

/// One issuer, the audience its tokens must be for, and who may upload.
#[derive(Debug)]
struct Issuer {
    /// Matched exactly against a token's `iss`.
    issuer: String,
    /// Expected `aud`, without a trailing `/`.
    audience: String,
    /// Where its keys are. `None` means its discovery document says.
    jwks_uri: Option<String>,
    /// A token is accepted if any claim set matches; the first one wins.
    claims: Vec<ClaimSet>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIssuer {
    issuer: String,
    audience: String,
    #[serde(default)]
    jwks_uri: Option<String>,
    claims: Vec<Map<String, Value>>,
}

impl Config {
    pub(super) fn parse(json: &str) -> Result<Self, String> {
        let raw: Vec<RawIssuer> = serde_json::from_str(json).map_err(|err| {
            format!(
                "{VAR} must be a JSON array of {{ issuer, audience, jwks_uri?, claims }}: {err}"
            )
        })?;
        if raw.is_empty() {
            return Err(format!("{VAR} must name at least one issuer"));
        }

        let mut issuers: Vec<Issuer> = Vec::with_capacity(raw.len());
        for (index, raw) in raw.into_iter().enumerate() {
            let issuer = Issuer::parse(index, raw)?;
            if issuers.iter().any(|other| other.issuer == issuer.issuer) {
                return Err(format!(
                    "{VAR}[{index}]: {} is configured twice",
                    issuer.issuer
                ));
            }
            issuers.push(issuer);
        }
        Ok(Self { issuers })
    }
}

impl Issuer {
    fn parse(index: usize, raw: RawIssuer) -> Result<Self, String> {
        let at = format!("{VAR}[{index}]");
        check_url(&raw.issuer).map_err(|why| format!("{at}.issuer {why}"))?;
        if let Some(jwks_uri) = &raw.jwks_uri {
            check_url(jwks_uri).map_err(|why| format!("{at}.jwks_uri {why}"))?;
        }

        let audience = raw.audience.trim_end_matches('/');
        if audience.is_empty() {
            return Err(format!("{at}.audience must not be empty"));
        }
        let github = raw.issuer == GITHUB_ACTIONS;
        // GitHub's default audience is `https://github.com/<owner>`. A token
        // requested for AWS or GCP carries it, so it must not work here.
        if github
            && (audience == "https://github.com" || audience.starts_with("https://github.com/"))
        {
            return Err(format!(
                "{at}.audience must be custom (e.g. the cache URL), not GitHub's default"
            ));
        }

        if raw.claims.is_empty() {
            return Err(format!("{at}.claims must contain at least one claim set"));
        }
        let claims = raw
            .claims
            .into_iter()
            .enumerate()
            .map(|(set, raw)| ClaimSet::parse(&format!("{at}.claims[{set}]"), raw))
            .collect::<Result<Vec<_>, _>>()?;
        if github {
            if let Some(set) = claims
                .iter()
                .position(|set| !set.0.contains_key("repository_owner_id"))
            {
                return Err(format!(
                    "{at}.claims[{set}] must pin repository_owner_id: GitHub gives a token for any audience to any repository on github.com"
                ));
            }
        }

        Ok(Self {
            issuer: raw.issuer,
            audience: audience.to_string(),
            jwks_uri: raw.jwks_uri,
            claims,
        })
    }
}

/// Whether `url` is somewhere keys may be fetched from: HTTPS, or plain HTTP
/// on a loopback address, for a local issuer in development.
fn check_url(url: &str) -> Result<(), &'static str> {
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
#[derive(Debug)]
struct ClaimSet(BTreeMap<String, Pattern>);

/// A claim's expected value: exact, or a prefix written with one trailing
/// `*` (`example-org/*`). `*_id` claims must be exact.
#[derive(Debug, PartialEq)]
enum Pattern {
    Exact(String),
    Prefix(String),
}

impl ClaimSet {
    fn parse(at: &str, raw: Map<String, Value>) -> Result<Self, String> {
        if raw.is_empty() {
            return Err(format!("{at} must match at least one claim"));
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
                        "{at}.{claim} must be a non-empty string, a number or a boolean"
                    ));
                }
            };
            let pattern = Pattern::parse(&pattern)
                .filter(|pattern| !is_id_claim(&claim) || matches!(pattern, Pattern::Exact(_)))
                .ok_or_else(|| {
                    if is_id_claim(&claim) {
                        format!("{at}.{claim}: ID claims must match exactly")
                    } else {
                        format!("{at}.{claim}: * may only end a pattern, after a prefix")
                    }
                })?;
            claims.insert(claim, pattern);
        }
        Ok(Self(claims))
    }

    fn matches(&self, claims: &Map<String, Value>) -> bool {
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

/// A decoded, not yet verified, JWT.
struct Jwt<'a> {
    kid: String,
    claims: Map<String, Value>,
    /// `<header>.<payload>`, the bytes the signature covers.
    signing_input: &'a str,
    signature: Vec<u8>,
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    kid: Option<String>,
}

fn invalid(what: &str) -> AuthError {
    AuthError::Unauthorized(format!("invalid token: {what}"))
}

fn decode(jwt: &str) -> Result<Jwt<'_>, AuthError> {
    let segment = |s: &str| {
        URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| invalid("bad encoding"))
    };

    let parts: Vec<&str> = jwt.split('.').collect();
    let [header, payload, signature] = parts[..] else {
        return Err(invalid("expected a JWT"));
    };

    let header: JwtHeader =
        serde_json::from_slice(&segment(header)?).map_err(|_| invalid("bad header"))?;
    if header.alg != "RS256" {
        return Err(invalid("alg must be RS256"));
    }
    let Some(kid) = header.kid else {
        return Err(invalid("missing kid"));
    };

    let claims = serde_json::from_slice(&segment(payload)?).map_err(|_| invalid("bad claims"))?;
    let signature = segment(signature)?;
    let signing_input = &jwt[..jwt.len() - parts[2].len() - 1];

    Ok(Jwt {
        kid,
        claims,
        signing_input,
        signature,
    })
}

/// The configured issuer a token claims to come from.
fn issuer_of<'a>(config: &'a Config, claims: &Map<String, Value>) -> Result<&'a Issuer, AuthError> {
    let Some(iss) = claims.get("iss").and_then(Value::as_str) else {
        return Err(invalid("missing iss"));
    };
    config
        .issuers
        .iter()
        .find(|issuer| issuer.issuer == iss)
        .ok_or_else(|| AuthError::Unauthorized(format!("issuer {iss} is not configured")))
}

/// Checks the claims of a token whose signature `issuer`'s keys verified.
fn check_claims(
    issuer: &Issuer,
    claims: &Map<String, Value>,
    now_secs: u64,
) -> Result<Identity, AuthError> {
    let claim = |name| claims.get(name);

    if claim("iss").and_then(Value::as_str) != Some(issuer.issuer.as_str()) {
        return Err(invalid("wrong issuer"));
    }

    let audience_matches = |aud: &Value| {
        aud.as_str()
            .is_some_and(|aud| aud.trim_end_matches('/') == issuer.audience)
    };
    let audience_ok = match claim("aud") {
        Some(Value::Array(auds)) => auds.iter().any(audience_matches),
        Some(aud) => audience_matches(aud),
        None => false,
    };
    if !audience_ok {
        let got = match claim("aud") {
            Some(Value::String(aud)) => aud.clone(),
            Some(Value::Array(auds)) => auds
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", "),
            _ => "missing".to_string(),
        };
        return Err(AuthError::Unauthorized(format!(
            "token audience is {got}, expected {}",
            issuer.audience
        )));
    }

    let Some(exp) = claim("exp").and_then(Value::as_u64) else {
        return Err(invalid("missing exp"));
    };
    if now_secs > exp + LEEWAY_SECS {
        return Err(AuthError::Unauthorized("token expired".to_string()));
    }
    if let Some(nbf) = claim("nbf").and_then(Value::as_u64) {
        if now_secs + LEEWAY_SECS < nbf {
            return Err(AuthError::Unauthorized("token not valid yet".to_string()));
        }
    }

    let subject = claim("sub")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    // Which claims would have matched isn't said: that's the policy, not the
    // caller's to probe.
    let Some(set) = issuer.claims.iter().position(|set| set.matches(claims)) else {
        return Err(AuthError::Forbidden(format!(
            "{subject}: no claim set for {} matched",
            issuer.issuer
        )));
    };

    Ok(Identity {
        issuer: issuer.issuer.clone(),
        subject,
        claims: set,
    })
}

/// Verifies a token from one of the configured issuers and matches it
/// against that issuer's claim sets.
pub(super) async fn authorize(config: &Config, jwt: &str) -> Result<Identity, AuthError> {
    let now_ms = Date::now().as_millis();
    let key = IdentityCache::key(jwt);
    if let Some(result) = CACHE.with_borrow(|cache| cache.get(&key, now_ms)) {
        return result;
    }

    let token = decode(jwt)?;
    let issuer = issuer_of(config, &token.claims)?;
    let jwk = find_key(issuer, &token.kid, now_ms).await?;
    if !verify_rs256(&jwk, token.signing_input.as_bytes(), &token.signature).await? {
        return Err(invalid("bad signature"));
    }

    let result = check_claims(issuer, &token.claims, now_ms / 1000);
    // A verified token's identity can't change, so both outcomes hold until
    // it expires. Expiry and other time-based failures are not cached.
    if matches!(result, Ok(_) | Err(AuthError::Forbidden(_))) {
        if let Some(exp) = token.claims.get("exp").and_then(Value::as_u64) {
            let expires_at = (exp + LEEWAY_SECS) * 1000;
            CACHE.with_borrow_mut(|cache| cache.insert(key, result.clone(), expires_at, now_ms));
        }
    }
    result
}

#[derive(Clone, Debug, PartialEq)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<RawJwk>,
}

#[derive(Deserialize)]
struct RawJwk {
    kty: String,
    kid: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

/// The part of an issuer's discovery document the Worker reads.
#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}

/// An issuer's signing keys, cached per isolate.
struct KeySet {
    keys: Vec<Jwk>,
    fetched_at: u64,
}

#[derive(Debug, PartialEq)]
enum Lookup {
    Hit(Jwk),
    Fetch,
    /// Unknown `kid`, and the JWKS was fetched too recently to try again.
    Miss,
}

impl KeySet {
    fn parse(jwks: Jwks, fetched_at: u64) -> Self {
        let keys = jwks
            .keys
            .into_iter()
            .filter(|key| key.kty == "RSA")
            .filter_map(|key| {
                Some(Jwk {
                    kid: key.kid?,
                    n: key.n?,
                    e: key.e?,
                })
            })
            .collect();
        Self { keys, fetched_at }
    }

    fn find(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|key| key.kid == kid)
    }

    fn lookup(set: Option<&KeySet>, kid: &str, now_ms: u64) -> Lookup {
        let Some(set) = set else {
            return Lookup::Fetch;
        };
        let age = now_ms.saturating_sub(set.fetched_at);
        match set.find(kid) {
            Some(key) if age < JWKS_TTL_MS => Lookup::Hit(key.clone()),
            Some(_) => Lookup::Fetch,
            None if age < JWKS_MIN_REFETCH_MS => Lookup::Miss,
            None => Lookup::Fetch,
        }
    }
}

async fn find_key(issuer: &Issuer, kid: &str, now_ms: u64) -> Result<Jwk, AuthError> {
    let unknown = || invalid("unknown signing key");

    match JWKS.with_borrow(|sets| KeySet::lookup(sets.get(&issuer.issuer), kid, now_ms)) {
        Lookup::Hit(key) => return Ok(key),
        Lookup::Miss => return Err(unknown()),
        Lookup::Fetch => {}
    }

    let set = fetch_jwks(issuer, now_ms).await?;
    let key = set.find(kid).cloned();
    JWKS.with_borrow_mut(|sets| sets.insert(issuer.issuer.clone(), set));
    key.ok_or_else(unknown)
}

async fn fetch_jwks(issuer: &Issuer, now_ms: u64) -> Result<KeySet, AuthError> {
    let jwks_uri = match &issuer.jwks_uri {
        Some(jwks_uri) => jwks_uri.clone(),
        None => {
            let url = format!(
                "{}/.well-known/openid-configuration",
                issuer.issuer.trim_end_matches('/')
            );
            let discovery: Discovery = fetch_json(&url).await?;
            // OIDC Discovery requires the document to name its own issuer, so
            // one issuer can't hand out another's keys.
            if discovery.issuer != issuer.issuer {
                return Err(AuthError::Upstream(format!(
                    "{url} is for issuer {}, not {}",
                    discovery.issuer, issuer.issuer
                )));
            }
            check_url(&discovery.jwks_uri)
                .map_err(|why| AuthError::Upstream(format!("{url}: jwks_uri {why}")))?;
            discovery.jwks_uri
        }
    };
    let jwks: Jwks = fetch_json(&jwks_uri).await?;
    Ok(KeySet::parse(jwks, now_ms))
}

async fn fetch_json<T: serde::de::DeserializeOwned>(url: &str) -> Result<T, AuthError> {
    let upstream = |err: worker::Error| AuthError::Upstream(format!("fetching {url}: {err}"));

    // `Request::new` hands the URL to the runtime; `Url::parse` would pull the
    // `url` crate and its IDNA tables into the bundle.
    let req = Request::new(url, Method::Get).map_err(upstream)?;
    let mut resp = Fetch::Request(req).send().await.map_err(upstream)?;
    if resp.status_code() != 200 {
        return Err(AuthError::Upstream(format!(
            "fetching {url} returned {}",
            resp.status_code()
        )));
    }
    resp.json().await.map_err(upstream)
}

/// Verifies an RS256 (RSASSA-PKCS1-v1_5 with SHA-256) signature with WebCrypto.
async fn verify_rs256(
    jwk: &Jwk,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<bool, AuthError> {
    let webcrypto = |err: JsValue| AuthError::Upstream(format!("WebCrypto: {err:?}"));
    let object = |value: Value| -> Result<js_sys::Object, AuthError> {
        js_sys::JSON::parse(&value.to_string())
            .map(JsCast::unchecked_into)
            .map_err(webcrypto)
    };

    let subtle = js_sys::global()
        .unchecked_into::<WorkerGlobalScope>()
        .crypto()
        .map_err(webcrypto)?
        .subtle();
    let algorithm = object(json!({ "name": "RSASSA-PKCS1-v1_5", "hash": "SHA-256" }))?;
    let key_data = object(json!({ "kty": "RSA", "n": jwk.n, "e": jwk.e, "alg": "RS256" }))?;
    let usages = js_sys::Array::of1(&JsValue::from_str("verify"));

    let key: CryptoKey = JsFuture::from(
        subtle
            .import_key_with_object("jwk", &key_data, &algorithm, false, &usages)
            .map_err(webcrypto)?,
    )
    .await
    .map_err(webcrypto)?
    .unchecked_into();

    // A signature WebCrypto refuses to check (e.g. wrong length) is the
    // caller's problem, not an upstream failure.
    let verified = subtle
        .verify_with_object_and_buffer_source_and_buffer_source(
            &algorithm,
            &key,
            &Uint8Array::from(signature),
            &Uint8Array::from(signing_input),
        )
        .map(JsFuture::from);
    match verified {
        Ok(future) => Ok(future.await.ok().and_then(|v| v.as_bool()) == Some(true)),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const ISSUER: &str = "https://issuer.example.com";

    /// One issuer with these claim sets.
    fn config(issuer: &str, claims: Value) -> Config {
        let json = json!([{
            "issuer": issuer,
            "audience": "https://cache.example.com",
            "claims": claims,
        }]);
        Config::parse(&json.to_string()).expect("config should parse")
    }

    fn parse_err(json: Value) -> String {
        Config::parse(&json.to_string()).unwrap_err()
    }

    fn claims() -> Map<String, Value> {
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

    fn segment(value: Value) -> String {
        URL_SAFE_NO_PAD.encode(value.to_string())
    }

    #[test]
    fn config_rejects_bad_issuer_lists() {
        let issuer = |issuer: &str| json!({ "issuer": issuer, "audience": "https://cache.example.com", "claims": [{ "ref": "x" }] });
        let cases = [
            (json!("not a list"), "JSON array"),
            (json!([]), "at least one issuer"),
            (json!([{ "issuer": ISSUER, "claims": [] }]), "JSON array"),
            (json!([issuer(ISSUER), issuer(ISSUER)]), "configured twice"),
            (json!([issuer("http://issuer.example.com")]), "https://"),
            (json!([issuer("https://")]), "https://"),
            (
                json!([{ "issuer": ISSUER, "audience": "https://cache.example.com", "claims": [{ "ref": "x" }], "extra": 1 }]),
                "JSON array",
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
    fn config_trims_trailing_slash_from_audience() {
        let json = json!([{ "issuer": ISSUER, "audience": "https://cache.example.com/", "claims": [{ "ref": "x" }] }]);
        let config = Config::parse(&json.to_string()).unwrap();
        assert_eq!(config.issuers[0].audience, "https://cache.example.com");
    }

    #[test]
    fn config_rejects_bad_claim_sets() {
        let cases = [
            (json!([]), "at least one claim set"),
            (json!([{}]), "at least one claim"),
            (json!([{ "repository_id": "2000*" }]), "must match exactly"),
            (json!([{ "ref": "" }]), "non-empty string"),
            (json!([{ "ref": null }]), "non-empty string"),
            (json!([{ "ref": "*" }]), "may only end a pattern"),
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
    fn config_guards_github_actions() {
        // Any repository on github.com can get a token for any audience.
        let err = parse_err(json!([{
            "issuer": GITHUB_ACTIONS,
            "audience": "https://cache.example.com",
            "claims": [{ "repository_owner_id": "100000001" }, { "ref": "refs/heads/main" }],
        }]));
        assert!(
            err.contains("claims[1] must pin repository_owner_id"),
            "{err}"
        );

        for audience in ["https://github.com", "https://github.com/example-org"] {
            let err = parse_err(json!([{
                "issuer": GITHUB_ACTIONS,
                "audience": audience,
                "claims": [{ "repository_owner_id": "100000001" }],
            }]));
            assert!(err.contains("not GitHub's default"), "{err}");
        }

        config(
            GITHUB_ACTIONS,
            json!([{ "repository_owner_id": "100000001", "ref": "refs/heads/main" }]),
        );
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
        let set = &config.issuers[0].claims[0];
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
        let sets = &config.issuers[0].claims;
        assert!(
            sets[0].matches(&claims()),
            "a list matches if any entry does"
        );
        assert!(sets[1].matches(&claims()), "booleans compare as written");
        assert!(sets[2].matches(&claims()), "numbers compare as written");
        assert!(!sets[3].matches(&claims()));
        assert!(!sets[4].matches(&claims()), "a missing claim never matches");
    }

    #[test]
    fn issuer_of_picks_the_configured_issuer() {
        let config = config(ISSUER, json!([{ "ref": "refs/heads/main" }]));
        assert_eq!(issuer_of(&config, &claims()).unwrap().issuer, ISSUER);

        let mut other = claims();
        other.insert("iss".into(), "https://other.example.com".into());
        assert_eq!(
            issuer_of(&config, &other).unwrap_err(),
            AuthError::Unauthorized("issuer https://other.example.com is not configured".into())
        );

        other.remove("iss");
        assert!(matches!(
            issuer_of(&config, &other),
            Err(AuthError::Unauthorized(_))
        ));
    }

    #[test]
    fn check_claims_returns_first_matching_set() {
        let config = config(
            ISSUER,
            json!([{ "ref": "refs/heads/release" }, { "repository_id": "200000002", "ref": "refs/heads/main" }]),
        );
        let identity = check_claims(&config.issuers[0], &claims(), NOW).expect("should match");
        assert_eq!(
            identity,
            Identity {
                issuer: ISSUER.to_string(),
                subject: "repo:example-org/app:ref:refs/heads/main".to_string(),
                claims: 1,
            }
        );
    }

    #[test]
    fn check_claims_accepts_audience_array() {
        let mut claims = claims();
        claims.insert(
            "aud".into(),
            json!(["https://other.example.com", "https://cache.example.com"]),
        );
        let config = config(ISSUER, json!([{ "ref": "refs/heads/main" }]));
        assert!(check_claims(&config.issuers[0], &claims, NOW).is_ok());
    }

    #[test]
    fn check_claims_says_what_is_wrong() {
        let config = config(ISSUER, json!([{ "ref": "refs/heads/main" }]));
        let cases: [(&str, Value, &str); 6] = [
            (
                "iss",
                json!("https://other.example.com"),
                "invalid token: wrong issuer",
            ),
            (
                "aud",
                json!("https://wrong.example.com"),
                "token audience is https://wrong.example.com, expected https://cache.example.com",
            ),
            (
                "aud",
                Value::Null,
                "token audience is missing, expected https://cache.example.com",
            ),
            ("exp", json!(NOW - LEEWAY_SECS - 1), "token expired"),
            ("nbf", json!(NOW + LEEWAY_SECS + 1), "token not valid yet"),
            ("exp", Value::Null, "invalid token: missing exp"),
        ];
        for (claim, value, expected) in cases {
            let mut claims = claims();
            claims.insert(claim.into(), value);
            assert_eq!(
                check_claims(&config.issuers[0], &claims, NOW),
                Err(AuthError::Unauthorized(expected.to_string())),
                "{claim}"
            );
        }
    }

    #[test]
    fn check_claims_tolerates_clock_skew() {
        let config = config(ISSUER, json!([{ "ref": "refs/heads/main" }]));
        assert!(check_claims(&config.issuers[0], &claims(), NOW + 300 + LEEWAY_SECS).is_ok());
    }

    #[test]
    fn check_claims_forbids_when_no_set_matches() {
        let config = config(ISSUER, json!([{ "ref": "refs/heads/release" }]));
        assert_eq!(
            check_claims(&config.issuers[0], &claims(), NOW),
            Err(AuthError::Forbidden(format!(
                "repo:example-org/app:ref:refs/heads/main: no claim set for {ISSUER} matched"
            )))
        );
    }

    #[test]
    fn decode_splits_jwt() {
        let header = segment(json!({ "alg": "RS256", "kid": "key-1" }));
        let payload = segment(Value::Object(claims()));
        let jwt = format!("{header}.{payload}.c2ln");

        let token = decode(&jwt).expect("should decode");
        assert_eq!(token.kid, "key-1");
        assert_eq!(token.signing_input, format!("{header}.{payload}"));
        assert_eq!(token.signature, b"sig");
        assert_eq!(token.claims, claims());
    }

    #[test]
    fn decode_rejects_malformed_tokens() {
        let payload = segment(Value::Object(claims()));
        let cases = [
            "not-a-jwt".to_string(),
            "a.b".to_string(),
            "a.b.c.d".to_string(),
            format!(
                "{}.{payload}.c2ln",
                segment(json!({ "alg": "none", "kid": "key-1" }))
            ),
            format!(
                "{}.{payload}.c2ln",
                segment(json!({ "alg": "HS256", "kid": "key-1" }))
            ),
            format!("{}.{payload}.c2ln", segment(json!({ "alg": "RS256" }))),
            format!(
                "{}.!!!.c2ln",
                segment(json!({ "alg": "RS256", "kid": "key-1" }))
            ),
        ];
        for jwt in cases {
            assert!(
                matches!(decode(&jwt), Err(AuthError::Unauthorized(_))),
                "{jwt} should be rejected"
            );
        }
    }

    #[test]
    fn keyset_keeps_rsa_keys_only() {
        let jwks: Jwks = serde_json::from_value(json!({
            "keys": [
                { "kty": "RSA", "kid": "key-1", "n": "AQAB", "e": "AQAB" },
                { "kty": "EC", "kid": "key-2", "x": "AA", "y": "AA" },
                { "kty": "RSA", "n": "AQAB", "e": "AQAB" },
            ]
        }))
        .unwrap();
        let set = KeySet::parse(jwks, 0);
        assert_eq!(set.keys.len(), 1);
        assert_eq!(set.keys[0].kid, "key-1");
    }

    #[test]
    fn keyset_lookup_refetches_sparingly() {
        let set = KeySet {
            keys: vec![Jwk {
                kid: "key-1".into(),
                n: "AQAB".into(),
                e: "AQAB".into(),
            }],
            fetched_at: 0,
        };

        assert_eq!(KeySet::lookup(None, "key-1", 0), Lookup::Fetch);
        assert!(matches!(
            KeySet::lookup(Some(&set), "key-1", 1),
            Lookup::Hit(_)
        ));
        assert_eq!(
            KeySet::lookup(Some(&set), "key-1", JWKS_TTL_MS),
            Lookup::Fetch
        );
        assert_eq!(KeySet::lookup(Some(&set), "key-2", 1), Lookup::Miss);
        assert_eq!(
            KeySet::lookup(Some(&set), "key-2", JWKS_MIN_REFETCH_MS),
            Lookup::Fetch
        );
    }
}
