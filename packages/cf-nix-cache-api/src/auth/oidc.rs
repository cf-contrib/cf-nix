use std::{cell::RefCell, collections::BTreeMap};

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

use super::{AuthError, Identity, IdentityKind, cache::IdentityCache};

const ISSUER: &str = "https://token.actions.githubusercontent.com";
const JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";

/// Clock tolerance for `exp` and `nbf`.
const LEEWAY_SECS: u64 = 60;
/// How long a fetched JWKS is trusted before it's fetched again.
const JWKS_TTL_MS: u64 = 60 * 60 * 1000;
/// An unknown `kid` refetches the JWKS at most this often, so tokens with
/// made-up key IDs can't make the Worker hammer GitHub.
const JWKS_MIN_REFETCH_MS: u64 = 60 * 1000;

thread_local! {
    static JWKS: RefCell<Option<KeySet>> = const { RefCell::new(None) };
    static CACHE: RefCell<IdentityCache> = RefCell::new(IdentityCache::new());
}

/// GitHub Actions OIDC auth. Same matching semantics as cf-oidc-auth.
#[derive(Debug)]
pub(super) struct Config {
    /// Numeric org/user ID (`CF_NIX_WORKER_GITHUB_OWNER_ID`), matched against
    /// `repository_owner_id` for every rule.
    owner_id: String,
    /// Expected `aud` claim (`CF_NIX_WORKER_GITHUB_OIDC_AUDIENCE`), without a trailing `/`.
    audience: String,
    /// `CF_NIX_WORKER_GITHUB_OIDC_RULES`; the first rule that matches wins.
    rules: Vec<Rule>,
}

impl Config {
    pub(super) fn parse(owner_id: &str, audience: &str, rules: &str) -> Result<Self, String> {
        if owner_id.is_empty() || !owner_id.bytes().all(|c| c.is_ascii_digit()) {
            return Err(
                "CF_NIX_WORKER_GITHUB_OWNER_ID must be a numeric GitHub org or user ID".to_string(),
            );
        }

        // GitHub's default audience is `https://github.com/<owner>`. A JWT
        // requested for AWS or GCP carries it, so it must not work here.
        let audience = audience.trim_end_matches('/');
        if audience.is_empty() {
            return Err("CF_NIX_WORKER_GITHUB_OIDC_AUDIENCE must not be empty".to_string());
        }
        if audience == "https://github.com" || audience.starts_with("https://github.com/") {
            return Err(
                "CF_NIX_WORKER_GITHUB_OIDC_AUDIENCE must be custom (e.g. the cache URL), not GitHub's default"
                    .to_string(),
            );
        }

        let raw: Vec<Map<String, Value>> =
            serde_json::from_slice(rules.as_bytes()).map_err(|err| {
                format!("CF_NIX_WORKER_GITHUB_OIDC_RULES must be a JSON array of objects: {err}")
            })?;
        if raw.is_empty() {
            return Err(
                "CF_NIX_WORKER_GITHUB_OIDC_RULES must contain at least one rule".to_string(),
            );
        }
        let rules = raw
            .into_iter()
            .enumerate()
            .map(|(index, rule)| Rule::parse(index, rule))
            .collect::<Result<_, _>>()?;

        Ok(Self {
            owner_id: owner_id.to_string(),
            audience: audience.to_string(),
            rules,
        })
    }
}

/// One `CF_NIX_WORKER_GITHUB_OIDC_RULES` entry: claim name to pattern. Matches when every
/// claim matches. `*` matches any run of characters (including `/`) except
/// in `*_id` claims, which must match exactly.
#[derive(Debug)]
struct Rule(BTreeMap<String, String>);

impl Rule {
    fn parse(index: usize, raw: Map<String, Value>) -> Result<Self, String> {
        if raw.is_empty() {
            return Err(format!(
                "CF_NIX_WORKER_GITHUB_OIDC_RULES[{index}] must match at least one claim"
            ));
        }

        let mut claims = BTreeMap::new();
        for (claim, value) in raw {
            if claim == "repository_owner_id" {
                return Err(format!(
                    "CF_NIX_WORKER_GITHUB_OIDC_RULES[{index}]: repository_owner_id is set by CF_NIX_WORKER_GITHUB_OWNER_ID"
                ));
            }
            // IDs may be written as JSON numbers; GitHub sends them as strings.
            let pattern = match value {
                Value::String(s) if !s.is_empty() => s,
                Value::Number(n) if n.is_u64() => n.to_string(),
                _ => {
                    return Err(format!(
                        "CF_NIX_WORKER_GITHUB_OIDC_RULES[{index}].{claim} must be a non-empty string"
                    ));
                }
            };
            if is_id_claim(&claim) && pattern.contains('*') {
                return Err(format!(
                    "CF_NIX_WORKER_GITHUB_OIDC_RULES[{index}].{claim}: ID claims can't be globbed"
                ));
            }
            claims.insert(claim, pattern);
        }

        Ok(Rule(claims))
    }

    fn matches(&self, claims: &Map<String, Value>) -> bool {
        self.0.iter().all(
            |(claim, pattern)| match claims.get(claim).and_then(Value::as_str) {
                Some(value) if is_id_claim(claim) => value == pattern,
                Some(value) => glob(pattern, value),
                None => false,
            },
        )
    }
}

fn is_id_claim(claim: &str) -> bool {
    claim.ends_with("_id")
}

/// Matches `value` against `pattern`, where `*` matches any run of
/// characters.
fn glob(pattern: &str, value: &str) -> bool {
    let (p, v) = (pattern.as_bytes(), value.as_bytes());
    let (mut pi, mut vi) = (0, 0);
    // Position of the last `*` in the pattern, and where in the value it
    // started matching.
    let mut star: Option<(usize, usize)> = None;

    while vi < v.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, vi));
            pi += 1;
        } else if pi < p.len() && p[pi] == v[vi] {
            pi += 1;
            vi += 1;
        } else if let Some((sp, sv)) = star {
            // Let the last `*` swallow one more character and retry.
            pi = sp + 1;
            vi = sv + 1;
            star = Some((sp, sv + 1));
        } else {
            return false;
        }
    }

    p[pi..].iter().all(|&c| c == b'*')
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

fn decode(jwt: &str) -> Result<Jwt<'_>, AuthError> {
    let invalid = |what: &str| AuthError::Unauthorized(format!("invalid OIDC token: {what}"));
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

/// Checks the claims of a token whose signature was already verified.
fn check_claims(
    config: &Config,
    claims: &Map<String, Value>,
    now_secs: u64,
) -> Result<Identity, AuthError> {
    let invalid = |what: &str| AuthError::Unauthorized(format!("invalid OIDC token: {what}"));
    let claim = |name| claims.get(name);

    if claim("iss").and_then(Value::as_str) != Some(ISSUER) {
        return Err(invalid("wrong issuer"));
    }

    let audience_matches = |aud: &Value| {
        aud.as_str()
            .is_some_and(|aud| aud.trim_end_matches('/') == config.audience)
    };
    let audience_ok = match claim("aud") {
        Some(Value::Array(auds)) => auds.iter().any(audience_matches),
        Some(aud) => audience_matches(aud),
        None => false,
    };
    if !audience_ok {
        return Err(invalid(
            "aud doesn't match CF_NIX_WORKER_GITHUB_OIDC_AUDIENCE",
        ));
    }

    let Some(exp) = claim("exp").and_then(Value::as_u64) else {
        return Err(invalid("missing exp"));
    };
    if now_secs > exp + LEEWAY_SECS {
        return Err(invalid("expired"));
    }
    if let Some(nbf) = claim("nbf").and_then(Value::as_u64) {
        if now_secs + LEEWAY_SECS < nbf {
            return Err(invalid("not valid yet"));
        }
    }

    let subject = claim("sub")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    if claim("repository_owner_id").and_then(Value::as_str) != Some(config.owner_id.as_str()) {
        return Err(AuthError::Forbidden(format!(
            "{subject}: repository owner is not CF_NIX_WORKER_GITHUB_OWNER_ID"
        )));
    }

    let Some(rule) = config.rules.iter().position(|rule| rule.matches(claims)) else {
        return Err(AuthError::Forbidden(format!(
            "{subject}: no CF_NIX_WORKER_GITHUB_OIDC_RULES entry matched"
        )));
    };

    Ok(Identity {
        kind: IdentityKind::Actions,
        subject,
        rule: Some(rule),
    })
}

/// Verifies a GitHub Actions OIDC token and matches it against the rules.
pub(super) async fn authorize(config: &Config, jwt: &str) -> Result<Identity, AuthError> {
    let now_ms = Date::now().as_millis();
    let key = IdentityCache::key(jwt);
    if let Some(result) = CACHE.with_borrow(|cache| cache.get(&key, now_ms)) {
        return result;
    }

    let token = decode(jwt)?;
    let jwk = find_key(&token.kid, now_ms).await?;
    if !verify_rs256(&jwk, token.signing_input.as_bytes(), &token.signature).await? {
        return Err(AuthError::Unauthorized(
            "invalid OIDC token: bad signature".to_string(),
        ));
    }

    let result = check_claims(config, &token.claims, now_ms / 1000);
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

/// GitHub's signing keys, cached per isolate.
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

async fn find_key(kid: &str, now_ms: u64) -> Result<Jwk, AuthError> {
    let unknown = || AuthError::Unauthorized("invalid OIDC token: unknown signing key".to_string());

    match JWKS.with_borrow(|set| KeySet::lookup(set.as_ref(), kid, now_ms)) {
        Lookup::Hit(key) => return Ok(key),
        Lookup::Miss => return Err(unknown()),
        Lookup::Fetch => {}
    }

    let set = fetch_jwks(now_ms).await?;
    let key = set.find(kid).cloned();
    JWKS.with_borrow_mut(|cached| *cached = Some(set));
    key.ok_or_else(unknown)
}

async fn fetch_jwks(now_ms: u64) -> Result<KeySet, AuthError> {
    let upstream = |err: worker::Error| AuthError::Upstream(format!("JWKS fetch: {err}"));

    // `Request::new` hands the URL to the runtime; `Url::parse` would pull the
    // `url` crate and its IDNA tables into the bundle.
    let req = Request::new(JWKS_URL, Method::Get).map_err(upstream)?;
    let mut resp = Fetch::Request(req).send().await.map_err(upstream)?;
    if resp.status_code() != 200 {
        return Err(AuthError::Upstream(format!(
            "JWKS fetch returned {}",
            resp.status_code()
        )));
    }
    let jwks: Jwks = resp.json().await.map_err(upstream)?;
    Ok(KeySet::parse(jwks, now_ms))
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

    fn config(rules: &str) -> Config {
        Config::parse("100000001", "https://cache.example.com", rules).expect("config should parse")
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
            "repository_owner": "example-org",
            "repository_owner_id": "100000001",
            "ref": "refs/heads/main",
            "event_name": "push",
        })
        .as_object()
        .unwrap()
        .clone()
    }

    fn segment(value: Value) -> String {
        URL_SAFE_NO_PAD.encode(value.to_string())
    }

    #[test]
    fn config_requires_numeric_owner_id() {
        for owner_id in ["", "example-org", "12a"] {
            let err = Config::parse(owner_id, "https://cache.example.com", r#"[{"ref":"x"}]"#)
                .unwrap_err();
            assert!(err.contains("CF_NIX_WORKER_GITHUB_OWNER_ID"));
        }
    }

    #[test]
    fn config_rejects_github_default_audience() {
        for audience in ["", "https://github.com", "https://github.com/example-org"] {
            let err = Config::parse("100000001", audience, r#"[{"ref":"x"}]"#).unwrap_err();
            assert!(err.contains("CF_NIX_WORKER_GITHUB_OIDC_AUDIENCE"));
        }
    }

    #[test]
    fn config_trims_trailing_slash_from_audience() {
        let config = Config::parse(
            "100000001",
            "https://cache.example.com/",
            r#"[{"ref":"x"}]"#,
        )
        .unwrap();
        assert_eq!(config.audience, "https://cache.example.com");
    }

    #[test]
    fn config_rejects_bad_rules() {
        let cases = [
            ("not json", "JSON array"),
            ("[]", "at least one rule"),
            ("[{}]", "at least one claim"),
            (
                r#"[{"repository_owner_id":"100000001"}]"#,
                "set by CF_NIX_WORKER_GITHUB_OWNER_ID",
            ),
            (r#"[{"repository_id":"2000*"}]"#, "can't be globbed"),
            (r#"[{"ref":""}]"#, "non-empty string"),
            (r#"[{"ref":true}]"#, "non-empty string"),
        ];
        for (rules, expected) in cases {
            let err = Config::parse("100000001", "https://cache.example.com", rules).unwrap_err();
            assert!(err.contains(expected), "{rules}: {err}");
        }
    }

    #[test]
    fn config_accepts_numeric_ids() {
        let config = config(r#"[{"repository_id":200000002}]"#);
        assert!(config.rules[0].matches(&claims()));
    }

    #[test]
    fn glob_matches_runs_including_slashes() {
        assert!(glob("example-org/*", "example-org/app"));
        assert!(glob("*", ""));
        assert!(glob("refs/heads/*", "refs/heads/feature/x"));
        assert!(glob("a*b*c", "aXXbYYc"));
        assert!(glob("refs/heads/main", "refs/heads/main"));
        assert!(!glob("refs/heads/main", "refs/heads/main2"));
        assert!(!glob("example-org/*", "other-org/app"));
        assert!(!glob("a*b", "aXXc"));
    }

    #[test]
    fn rule_needs_every_claim_to_match() {
        let config = config(r#"[{"repository":"example-org/*","ref":"refs/heads/main"}]"#);
        assert!(config.rules[0].matches(&claims()));

        let mut other_ref = claims();
        other_ref.insert("ref".into(), "refs/heads/dev".into());
        assert!(!config.rules[0].matches(&other_ref));
    }

    #[test]
    fn rule_missing_claim_never_matches() {
        let config = config(r#"[{"environment":"*"}]"#);
        assert!(!config.rules[0].matches(&claims()));
    }

    #[test]
    fn check_claims_returns_first_matching_rule() {
        let config = config(
            r#"[{"ref":"refs/heads/release"},{"repository_id":"200000002","ref":"refs/heads/main"}]"#,
        );
        let identity = check_claims(&config, &claims(), NOW).expect("should match");
        assert_eq!(identity.kind, IdentityKind::Actions);
        assert_eq!(identity.subject, "repo:example-org/app:ref:refs/heads/main");
        assert_eq!(identity.rule, Some(1));
    }

    #[test]
    fn check_claims_accepts_audience_array() {
        let mut claims = claims();
        claims.insert(
            "aud".into(),
            json!(["https://other.example.com", "https://cache.example.com"]),
        );
        assert!(check_claims(&config(r#"[{"ref":"refs/heads/main"}]"#), &claims, NOW).is_ok());
    }

    #[test]
    fn check_claims_rejects_invalid_tokens() {
        let config = config(r#"[{"ref":"refs/heads/main"}]"#);
        let cases: [(&str, Value, u64); 5] = [
            ("iss", json!("https://example.com"), NOW),
            ("aud", json!("https://github.com/example-org"), NOW),
            ("exp", json!(NOW - LEEWAY_SECS - 1), NOW),
            ("nbf", json!(NOW + LEEWAY_SECS + 1), NOW),
            ("exp", Value::Null, NOW),
        ];
        for (claim, value, now) in cases {
            let mut claims = claims();
            claims.insert(claim.into(), value);
            assert!(
                matches!(
                    check_claims(&config, &claims, now),
                    Err(AuthError::Unauthorized(_))
                ),
                "{claim} should be rejected"
            );
        }
    }

    #[test]
    fn check_claims_tolerates_clock_skew() {
        let config = config(r#"[{"ref":"refs/heads/main"}]"#);
        assert!(check_claims(&config, &claims(), NOW + 300 + LEEWAY_SECS).is_ok());
    }

    #[test]
    fn check_claims_pins_owner() {
        let config = config(r#"[{"ref":"refs/heads/main"}]"#);
        let mut claims = claims();
        claims.insert("repository_owner_id".into(), "999999999".into());
        assert!(matches!(
            check_claims(&config, &claims, NOW),
            Err(AuthError::Forbidden(_))
        ));
    }

    #[test]
    fn check_claims_forbids_when_no_rule_matches() {
        let config = config(r#"[{"ref":"refs/heads/release"}]"#);
        assert!(matches!(
            check_claims(&config, &claims(), NOW),
            Err(AuthError::Forbidden(_))
        ));
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
