//! Upload auth, as a tower layer: every `PUT` needs an OIDC token from a
//! provider `CF_NIX_CACHE_API_OIDC_PROVIDERS` names, as the password of HTTP
//! Basic credentials, since a netrc file is the only place Nix sends them from.
//! The username isn't read.
//!
//! [`AuthorizeLayer`] is layered over the API's routes in the crate root. It
//! runs before the request reaches its handler, and so before the body is
//! read: an upload without credentials is refused without buffering it. Reads
//! pass straight through.
//!
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
    convert::Infallible,
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    Json,
    extract::Request,
    http::{Method, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cf_nix_cache_sdk::v1::{self, ErrorCode};
use http_auth_basic::Credentials;
use http_body_util::BodyExt;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tower_layer::Layer;
use tower_service::Service;
use web_sys::{CryptoKey, WorkerGlobalScope};
use worker::{
    Date, Fetch, console_error, console_log,
    js_sys::{self, Uint8Array},
    send::SendFuture,
    wasm_bindgen::{JsCast, JsValue},
    wasm_bindgen_futures::JsFuture,
};

use super::config::{Config, PROVIDERS_KEY};

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

/// Authorizes every `PUT` before the routes it's layered over, against the
/// providers in the Worker's configuration. Every other method passes through.
#[derive(Clone)]
pub struct AuthorizeLayer {
    config: Arc<Config>,
}

impl AuthorizeLayer {
    /// A layer that takes the providers from `config`.
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for AuthorizeLayer {
    type Service = Authorize<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Authorize {
            inner,
            config: self.config.clone(),
        }
    }
}

/// [`AuthorizeLayer`]'s service: authorizes an upload, logs the identity it
/// resolved to (the token's subject and issuer, and the claim set that let it
/// in), then hands the request to the service it wraps.
#[derive(Clone)]
pub struct Authorize<S> {
    inner: S,
    config: Arc<Config>,
}

impl<S> Service<Request> for Authorize<S>
where
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        // The service polled ready is the one to call: a clone takes its
        // place for the next request.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let config = self.config.clone();

        Box::pin(async move {
            if req.method() != Method::PUT {
                return inner.call(req).await;
            }

            // The providers whose tokens may upload. None configured means
            // uploads are off.
            let providers = config.providers();
            if providers.is_empty() {
                let err =
                    AuthError::Unauthorized(format!("uploads are off: {PROVIDERS_KEY} is not set"));
                return Ok(refuse(req, err).await);
            }

            // The token: the password of the request's HTTP Basic credentials.
            let header = req
                .headers()
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok());
            let token = match token(header) {
                Ok(token) => token,
                Err(err) => return Ok(refuse(req, err).await),
            };

            // Verifying fetches the issuer's keys, and fetch futures aren't
            // `Send`, which the router wants; a Worker is single-threaded, so
            // it runs in a `SendFuture`.
            let verify = async {
                let jwt = Jwt::decode(&token)?;
                let provider = providers.find_by_claims(&jwt.claims)?;
                provider.verify_token(&jwt).await
            };
            let identity = match SendFuture::new(verify).await {
                Ok(identity) => identity,
                Err(err) => return Ok(refuse(req, err).await),
            };

            console_log!("PUT {} by {identity}", req.uri().path());
            inner.call(req).await
        })
    }
}

/// Refuses an upload with `err`, after reading its body a chunk at a time and
/// keeping none. An uploader that sent `Expect: 100-continue`, as Nix's
/// libcurl does for a large one, otherwise waits for the body to be read, and
/// the upload hangs instead of failing.
async fn refuse(req: Request, err: AuthError) -> Response {
    let mut body = req.into_body();
    while let Some(Ok(_)) = body.frame().await {}
    err.into_response()
}

/// The token in an `Authorization: Basic` header: its password.
fn token(header: Option<&str>) -> Result<String, AuthError> {
    let Some(header) = header else {
        return Err(AuthError::Unauthorized("missing credentials".to_string()));
    };
    match Credentials::from_header(header.to_string()) {
        Ok(credentials) if !credentials.password.is_empty() => Ok(credentials.password),
        _ => Err(AuthError::Unauthorized(
            "invalid credentials: send HTTP Basic auth with the token as the password".to_string(),
        )),
    }
}

/// The identity an authorized upload was resolved to. Logged for every upload.
#[derive(Clone, Debug, PartialEq)]
pub struct Identity {
    /// The token's `iss`.
    pub issuer: String,
    /// The token's `sub`.
    pub subject: String,
    /// Index of the issuer's claim set that matched.
    pub claims: usize,
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} from {} (claims[{}])",
            self.subject, self.issuer, self.claims
        )
    }
}

/// Why a request was not authorized.
#[derive(Clone, Debug, PartialEq)]
pub enum AuthError {
    /// Missing or invalid credentials (`401`).
    Unauthorized(String),
    /// A valid token no claim set allows (`403`).
    Forbidden(String),
    /// An issuer's discovery document or keys couldn't be fetched (`502`).
    /// Not the caller's fault.
    Upstream(String),
}

/// The error, as the JSON every error has. Upstream details are logged, not
/// returned.
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            AuthError::Unauthorized(msg) => (
                StatusCode::UNAUTHORIZED,
                v1::Error::new(ErrorCode::Unauthorized, msg),
            ),
            AuthError::Forbidden(msg) => (
                StatusCode::FORBIDDEN,
                v1::Error::new(ErrorCode::Forbidden, msg),
            ),
            AuthError::Upstream(msg) => {
                console_error!("auth upstream failure: {msg}");
                (
                    StatusCode::BAD_GATEWAY,
                    v1::Error::new(
                        ErrorCode::UpstreamError,
                        "the token's issuer couldn't be reached",
                    ),
                )
            }
        };
        (status, Json(body)).into_response()
    }
}

fn invalid(what: &str) -> AuthError {
    AuthError::Unauthorized(format!("invalid token: {what}"))
}

/// Extension methods for the configured providers. A trait rather than an
/// inherent impl because a slice is foreign.
trait ProvidersExtension {
    /// The provider a token's claims say it comes from, by its `iss`.
    fn find_by_claims(&self, claims: &Map<String, Value>) -> Result<&ProviderConfig, AuthError>;
}

impl ProvidersExtension for [ProviderConfig] {
    fn find_by_claims(&self, claims: &Map<String, Value>) -> Result<&ProviderConfig, AuthError> {
        let Some(iss) = claims.get("iss").and_then(Value::as_str) else {
            return Err(invalid("missing iss"));
        };
        self.iter()
            .find(|provider| provider.issuer == iss)
            .ok_or_else(|| AuthError::Unauthorized(format!("issuer {iss} is not configured")))
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
    /// Where its keys are. `None` means its discovery document says.
    #[serde(default)]
    jwks_uri: Option<String>,
    /// A token is accepted if any claim set matches; the first one wins.
    claims: Vec<ClaimSet>,
}

impl ProviderConfig {
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

    /// Verifies `jwt`, a token that claims to come from this provider, and
    /// matches it against the provider's claim sets.
    async fn verify_token(&self, jwt: &Jwt<'_>) -> Result<Identity, AuthError> {
        let now_ms = Date::now().as_millis();
        let key = IdentityCache::key(jwt.raw);
        if let Some(result) = CACHE.with_borrow(|cache| cache.get(&key, now_ms)) {
            return result;
        }

        let jwk = self.find_key(&jwt.kid, now_ms).await?;
        if !jwk
            .verify_rs256(jwt.signing_input.as_bytes(), &jwt.signature)
            .await?
        {
            return Err(invalid("bad signature"));
        }

        let result = self.check_claims(&jwt.claims, now_ms / 1000);
        // A verified token's identity can't change, so both outcomes hold until
        // it expires. Expiry and other time-based failures are not cached.
        if matches!(result, Ok(_) | Err(AuthError::Forbidden(_))) {
            if let Some(exp) = jwt.claims.get("exp").and_then(Value::as_u64) {
                let expires_at = (exp + LEEWAY_SECS) * 1000;
                CACHE
                    .with_borrow_mut(|cache| cache.insert(key, result.clone(), expires_at, now_ms));
            }
        }
        result
    }

    /// Checks the claims of a token whose signature `issuer`'s keys verified.
    fn check_claims(
        &self,
        claims: &Map<String, Value>,
        now_secs: u64,
    ) -> Result<Identity, AuthError> {
        let claim = |name| claims.get(name);

        if claim("iss").and_then(Value::as_str) != Some(self.issuer.as_str()) {
            return Err(invalid("wrong issuer"));
        }

        let audience_matches = |aud: &Value| aud.as_str().is_some_and(|aud| self.audience_is(aud));
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
                self.audience
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
        let Some(set) = self.claims.iter().position(|set| set.matches(claims)) else {
            return Err(AuthError::Forbidden(format!(
                "{subject}: no claim set for {} matched",
                self.issuer
            )));
        };

        Ok(Identity {
            issuer: self.issuer.clone(),
            subject,
            claims: set,
        })
    }

    /// Whether `aud`, one of a token's audiences, is this issuer's.
    fn audience_is(&self, aud: &str) -> bool {
        aud.trim_end_matches('/') == self.audience.trim_end_matches('/')
    }

    async fn find_key(&self, kid: &str, now_ms: u64) -> Result<Jwk, AuthError> {
        let unknown = || invalid("unknown signing key");

        match JWKS.with_borrow(|sets| KeySet::lookup(sets.get(&self.issuer), kid, now_ms)) {
            Lookup::Hit(key) => return Ok(key),
            Lookup::Miss => return Err(unknown()),
            Lookup::Fetch => {}
        }

        let set = self.fetch_jwks(now_ms).await?;
        let key = set.find(kid).cloned();
        JWKS.with_borrow_mut(|sets| sets.insert(self.issuer.clone(), set));
        key.ok_or_else(unknown)
    }

    async fn fetch_jwks(&self, now_ms: u64) -> Result<KeySet, AuthError> {
        let jwks_uri = match &self.jwks_uri {
            Some(jwks_uri) => jwks_uri.clone(),
            None => {
                let url = format!(
                    "{}/.well-known/openid-configuration",
                    self.issuer.trim_end_matches('/')
                );
                let discovery: Discovery = fetch_json(&url).await?;
                // OIDC Discovery requires the document to name its own issuer, so
                // one issuer can't hand out another's keys.
                if discovery.issuer != self.issuer {
                    return Err(AuthError::Upstream(format!(
                        "{url} is for issuer {}, not {}",
                        discovery.issuer, self.issuer
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
#[derive(Debug, Deserialize)]
#[serde(try_from = "Map<String, Value>")]
struct ClaimSet(BTreeMap<String, Pattern>);

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

/// A decoded, not yet verified, JWT.
struct Jwt<'a> {
    /// The token as sent, which the auth cache is keyed by.
    raw: &'a str,
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

impl<'a> Jwt<'a> {
    fn decode(jwt: &'a str) -> Result<Self, AuthError> {
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

        let claims =
            serde_json::from_slice(&segment(payload)?).map_err(|_| invalid("bad claims"))?;
        let signature = segment(signature)?;
        let signing_input = &jwt[..jwt.len() - parts[2].len() - 1];

        Ok(Jwt {
            raw: jwt,
            kid,
            claims,
            signing_input,
            signature,
        })
    }
}

/// The part of an issuer's discovery document the Worker reads.
#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
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

#[derive(Clone, Debug, PartialEq)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
}

impl Jwk {
    /// Verifies an RS256 (RSASSA-PKCS1-v1_5 with SHA-256) signature with WebCrypto.
    async fn verify_rs256(
        &self,
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
        let key_data = object(json!({ "kty": "RSA", "n": self.n, "e": self.e, "alg": "RS256" }))?;
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

async fn fetch_json<T: serde::de::DeserializeOwned>(url: &str) -> Result<T, AuthError> {
    let upstream = |err: worker::Error| AuthError::Upstream(format!("fetching {url}: {err}"));

    // `Request::new` hands the URL to the runtime; `Url::parse` would pull the
    // `url` crate and its IDNA tables into the bundle.
    let req = worker::Request::new(url, worker::Method::Get).map_err(upstream)?;
    let mut resp = Fetch::Request(req).send().await.map_err(upstream)?;
    if resp.status_code() != 200 {
        return Err(AuthError::Upstream(format!(
            "fetching {url} returned {}",
            resp.status_code()
        )));
    }
    resp.json().await.map_err(upstream)
}

/// Per-isolate cache of auth results, keyed by the SHA-256 of the credential
/// so raw tokens are never stored.
///
/// Holds refusals (`403`) as well as identities, so a token no claim set
/// allows isn't verified again on every request either.
struct IdentityCache {
    entries: HashMap<[u8; 32], (u64, Result<Identity, AuthError>)>,
}

impl IdentityCache {
    /// Upper bound on entries, so a flood of distinct credentials can't grow
    /// the isolate's memory without limit.
    const MAX_ENTRIES: usize = 1024;

    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn key(credential: &str) -> [u8; 32] {
        Sha256::digest(credential.as_bytes()).into()
    }

    fn get(&self, key: &[u8; 32], now_ms: u64) -> Option<Result<Identity, AuthError>> {
        self.entries
            .get(key)
            .filter(|(expires_at, _)| now_ms < *expires_at)
            .map(|(_, result)| result.clone())
    }

    fn insert(
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

    fn basic(user: &str, password: &str) -> String {
        Credentials::new(user, password).as_http_header()
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
    fn token_is_the_basic_password_whatever_the_username() {
        for user in ["oidc", "actions", "x"] {
            assert_eq!(token(Some(&basic(user, "a.b.c"))), Ok("a.b.c".to_string()));
        }
    }

    #[test]
    fn token_rejects_missing_or_malformed_header() {
        for header in [None, Some("Bearer abc"), Some(basic("oidc", "").as_str())] {
            assert!(
                matches!(token(header), Err(AuthError::Unauthorized(_))),
                "{header:?}"
            );
        }
    }

    #[test]
    fn refusals_are_401_and_403() {
        let unauthorized = AuthError::Unauthorized("missing credentials".into()).into_response();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let forbidden = AuthError::Forbidden("no claim set matched".into()).into_response();
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn identity_is_logged_with_its_issuer() {
        let identity = Identity {
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            subject: "repo:example-org/app:ref:refs/heads/main".to_string(),
            claims: 0,
        };
        assert_eq!(
            identity.to_string(),
            "repo:example-org/app:ref:refs/heads/main from https://token.actions.githubusercontent.com (claims[0])"
        );
    }

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

    const NOW: u64 = 1_800_000_000;
    const ISSUER: &str = "https://issuer.example.com";

    /// One provider with these claim sets.
    fn config(issuer: &str, claims: Value) -> Vec<ProviderConfig> {
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

    #[test]
    fn issuer_of_picks_the_configured_issuer() {
        let config = config(ISSUER, json!([{ "ref": "refs/heads/main" }]));
        assert_eq!(config.find_by_claims(&claims()).unwrap().issuer, ISSUER);

        let mut other = claims();
        other.insert("iss".into(), "https://other.example.com".into());
        assert_eq!(
            config.find_by_claims(&other).unwrap_err(),
            AuthError::Unauthorized("issuer https://other.example.com is not configured".into())
        );

        other.remove("iss");
        assert!(matches!(
            config.find_by_claims(&other),
            Err(AuthError::Unauthorized(_))
        ));
    }

    #[test]
    fn check_claims_returns_first_matching_set() {
        let config = config(
            ISSUER,
            json!([{ "ref": "refs/heads/release" }, { "repository_id": "200000002", "ref": "refs/heads/main" }]),
        );
        let identity = config[0]
            .check_claims(&claims(), NOW)
            .expect("should match");
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
        assert!(config[0].check_claims(&claims, NOW).is_ok());
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
                config[0].check_claims(&claims, NOW),
                Err(AuthError::Unauthorized(expected.to_string())),
                "{claim}"
            );
        }
    }

    #[test]
    fn check_claims_tolerates_clock_skew() {
        let config = config(ISSUER, json!([{ "ref": "refs/heads/main" }]));
        assert!(
            config[0]
                .check_claims(&claims(), NOW + 300 + LEEWAY_SECS)
                .is_ok()
        );
    }

    #[test]
    fn check_claims_forbids_when_no_set_matches() {
        let config = config(ISSUER, json!([{ "ref": "refs/heads/release" }]));
        assert_eq!(
            config[0].check_claims(&claims(), NOW),
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

        let token = Jwt::decode(&jwt).expect("should decode");
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
                matches!(Jwt::decode(&jwt), Err(AuthError::Unauthorized(_))),
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
