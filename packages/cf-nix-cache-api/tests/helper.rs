use cf_nix_cache_sdk::v1::HttpClient;
use http_auth_basic::Credentials;

/// Where `wrangler dev` serves the Worker.
pub const BASE_URL: &str = "http://127.0.0.1:8787";

/// The SDK's client, pointed at `wrangler dev`.
pub fn client() -> HttpClient {
    HttpClient::new().with_base_url(BASE_URL)
}

/// GitHub token used for uploads, from `CF_NIX_WORKER_GITHUB_TOKEN`. It needs
/// push access to the `CF_NIX_WORKER_GITHUB_REPOSITORY` in `wrangler.toml`.
pub fn github_token() -> String {
    std::env::var("CF_NIX_WORKER_GITHUB_TOKEN")
        .expect("set CF_NIX_WORKER_GITHUB_TOKEN, e.g. CF_NIX_WORKER_GITHUB_TOKEN=$(gh auth token)")
}

/// HTTP Basic credentials, as an `Authorization` header value.
pub fn basic(username: &str, password: &str) -> String {
    Credentials::new(username, password).as_http_header()
}

/// Credentials that may upload: `users` with `github_token()`.
pub fn uploader() -> Option<String> {
    Some(basic("users", &github_token()))
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
        .basic_auth("users", Some(github_token()))
        .body(body)
        .send()
        .await
        .expect("the request failed")
}
