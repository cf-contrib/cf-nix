use std::{
    sync::LazyLock,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{Json, Router, routing};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cf_nix_cache_sdk::v1::HttpClient;
use http_auth_basic::Credentials;
use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng};
use rsa::{
    RsaPrivateKey,
    pkcs1v15::SigningKey,
    sha2::Sha256,
    signature::{SignatureEncoding, Signer},
    traits::PublicKeyParts,
};
use serde_json::{Value, json};
use tokio::sync::Mutex;

/// Where `wrangler dev` serves the Worker, and the audience it expects.
pub const BASE_URL: &str = "http://127.0.0.1:8787";

/// The stand-in issuer `wrangler.toml` trusts. Its claim sets let in
/// `repository_owner_id` 100000001 on `refs/heads/main`.
pub const ISSUER: &str = "http://127.0.0.1:8788";
const ISSUER_ADDR: &str = "127.0.0.1:8788";
const KID: &str = "test-key-1";

/// A made-up signing key from a fixed seed, so it's the same every run and
/// the JWKS the Worker caches stays valid between runs.
static KEY: LazyLock<RsaPrivateKey> = LazyLock::new(|| {
    RsaPrivateKey::new(&mut ChaCha8Rng::seed_from_u64(7), 2048).expect("the key generates")
});

/// Serves the issuer's discovery document and JWKS for as long as the tests
/// run, on a thread of its own: each test has its own runtime.
static ISSUER_SERVER: LazyLock<()> = LazyLock::new(|| {
    let listener = std::net::TcpListener::bind(ISSUER_ADDR)
        .unwrap_or_else(|err| panic!("the test issuer can't listen on {ISSUER_ADDR}: {err}"));
    listener.set_nonblocking(true).unwrap();
    let jwks = json!({
        "keys": [{
            "kty": "RSA",
            "kid": KID,
            "alg": "RS256",
            "use": "sig",
            "n": URL_SAFE_NO_PAD.encode(KEY.n().to_bytes_be()),
            "e": URL_SAFE_NO_PAD.encode(KEY.e().to_bytes_be()),
        }]
    });
    let discovery = json!({ "issuer": ISSUER, "jwks_uri": format!("{ISSUER}/jwks") });
    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            routing::get(move || async move { Json(discovery) }),
        )
        .route("/jwks", routing::get(move || async move { Json(jwks) }));

    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                axum::serve(listener, app).await.unwrap();
            });
    });
});

/// The SDK's client, pointed at `wrangler dev`.
pub fn client() -> HttpClient {
    HttpClient::new().with_base_url(BASE_URL)
}

/// Claims the dev config lets upload. Change one to make a token it doesn't.
pub fn claims() -> Value {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    json!({
        "iss": ISSUER,
        "aud": BASE_URL,
        "sub": "repo:example-org/app:ref:refs/heads/main",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "repository": "example-org/app",
        "repository_owner_id": "100000001",
        "ref": "refs/heads/main",
    })
}

/// A token with `claims`, signed by the test issuer.
pub fn token(claims: &Value) -> String {
    LazyLock::force(&ISSUER_SERVER);
    let header = json!({ "alg": "RS256", "kid": KID, "typ": "JWT" });
    let encode = |value: &Value| URL_SAFE_NO_PAD.encode(value.to_string());
    let signing_input = format!("{}.{}", encode(&header), encode(claims));
    let signature = SigningKey::<Sha256>::new(KEY.clone()).sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_vec())
    )
}

/// HTTP Basic credentials, as an `Authorization` header value.
pub fn basic(username: &str, password: &str) -> String {
    Credentials::new(username, password).as_http_header()
}

/// Credentials that may upload: a token with `claims()`, as Nix sends it.
pub fn uploader() -> Option<String> {
    Some(basic("oidc", &token(&claims())))
}

/// Reads a file from `tests/fixture`.
pub fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("tests/fixture/{name}")).unwrap()
}

/// Sends a plain GET, for what the typed client doesn't return: the headers.
pub async fn get(path: &str) -> reqwest::Response {
    reqwest::get(format!("{BASE_URL}/{path}"))
        .await
        .expect("the request failed")
}

/// Sends a plain PUT with credentials that may upload, for requests the typed
/// client can't make: a content type the spec doesn't declare.
pub async fn put(path: &str, content_type: &str, body: Vec<u8>) -> reqwest::Response {
    reqwest::Client::new()
        .put(format!("{BASE_URL}/{path}"))
        .header("content-type", content_type)
        .header("authorization", uploader().unwrap())
        .body(body)
        .send()
        .await
        .expect("the request failed")
}

/// Held by every test that uploads the `j5m1…` narinfo. Tests run in
/// parallel, and one's upload would replace what another is about to read
/// back.
pub static NARINFO_LOCK: Mutex<()> = Mutex::const_new(());
