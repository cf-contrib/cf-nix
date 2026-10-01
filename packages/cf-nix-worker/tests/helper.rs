use std::sync::LazyLock;

use reqwest::*;

static BASE_URL: LazyLock<Url> = LazyLock::new(|| Url::parse("http://127.0.0.1:8787").unwrap());

/// Sends an HTTP GET request to the given URL.
///
/// This is a convenience wrapper that builds a `reqwest::Client` and sends
/// a GET request, returning the response or an error.
pub async fn get(path: &str) -> reqwest::Result<reqwest::Response> {
    let url = BASE_URL.join(path).unwrap();
    println!("{url:?}");
    reqwest::Client::builder()
        .build()?
        .get(url.to_string())
        .send()
        .await
}

/// Sends an HTTP POST request with the given content type and body.
///
/// Builds a `reqwest::Client`, attaches the `content-type` header,
/// and sends the body in a POST request to the target URL.
pub async fn post<B: Into<Body>>(
    path: &str,
    content_type: &str,
    content_body: B,
) -> reqwest::Result<reqwest::Response> {
    let url = BASE_URL.join(path).unwrap();
    println!("{url:?}");
    reqwest::Client::builder()
        .build()?
        .post(url.to_string())
        .body(content_body)
        .header("content-type", content_type)
        .send()
        .await
}

/// GitHub token used for uploads, from `CF_NIX_CACHE_GITHUB_TOKEN`. It needs
/// push access to the `CF_NIX_CACHE_GITHUB_REPOSITORY` in `wrangler.toml`.
pub fn github_token() -> String {
    std::env::var("CF_NIX_CACHE_GITHUB_TOKEN")
        .expect("set CF_NIX_CACHE_GITHUB_TOKEN, e.g. CF_NIX_CACHE_GITHUB_TOKEN=$(gh auth token)")
}

/// Sends an HTTP PUT request with the given content type and body.
///
/// Builds a `reqwest::Client`, attaches the `content-type` header and
/// HTTP Basic credentials for `github_token()`, and sends the body in a PUT
/// request to the target URL.
pub async fn put<B: Into<Body>>(
    path: &str,
    content_type: &str,
    content_body: B,
) -> reqwest::Result<reqwest::Response> {
    let url = BASE_URL.join(path).unwrap();
    println!("{url:?}");
    reqwest::Client::builder()
        .build()?
        .put(url.to_string())
        .body(content_body)
        .header("content-type", content_type)
        .basic_auth("github", Some(github_token()))
        .send()
        .await
}

/// Sends an HTTP GET request with HTTP Basic credentials.
pub async fn get_with_auth(
    path: &str,
    username: &str,
    password: &str,
) -> reqwest::Result<reqwest::Response> {
    let url = BASE_URL.join(path).unwrap();
    println!("{url:?}");
    reqwest::Client::builder()
        .build()?
        .get(url.to_string())
        .basic_auth(username, Some(password))
        .send()
        .await
}

/// Sends an HTTP PUT request with the given HTTP Basic credentials, or none.
pub async fn put_with_auth<B: Into<Body>>(
    path: &str,
    content_type: &str,
    content_body: B,
    credentials: Option<(&str, &str)>,
) -> reqwest::Result<reqwest::Response> {
    let url = BASE_URL.join(path).unwrap();
    println!("{url:?}");
    let mut req = reqwest::Client::builder()
        .build()?
        .put(url.to_string())
        .body(content_body)
        .header("content-type", content_type);
    if let Some((username, password)) = credentials {
        req = req.basic_auth(username, Some(password));
    }
    req.send().await
}
