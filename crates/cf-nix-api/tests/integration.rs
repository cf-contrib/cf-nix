#![cfg(feature = "integration")]

mod helper;

use cf_nix_sdk::v1::{
    ApiOpError, Error, ErrorCode, GetNarApiError, GetNarInfoApiError, HealthClient,
    PutNarInfoApiError,
};
use serde_json::{Value, json};

const NARINFO: &str = "j5m1qd2dbsmhq0mw13yb8wijnm3pq4z0";
const NAR: &str = "j5m1qd2dbsmhq0mw13yb8wijnm3pq4z0";
const MISSING: &str = "j6m2qd3dbsmhq0mw14yb9wijnm4pq6z1";

fn narinfo_fixture(hash: &str) -> String {
    String::from_utf8(helper::fixture(&format!("{hash}.narinfo"))).unwrap()
}

/// The HTTP status of a failed call.
fn status<E: std::fmt::Debug>(err: &ApiOpError<E>) -> u16 {
    err.api().expect("the server responded").status
}

#[tokio::test]
async fn test_get_nix_cache_info() {
    let info = helper::client()
        .get_nix_cache_info()
        .await
        .expect("the request failed");
    assert_eq!(
        info,
        "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n"
    );
}

#[tokio::test]
async fn test_get_narinfo() {
    let _uploads = helper::UPLOADS.lock().await;
    let client = helper::uploader();
    let data = narinfo_fixture(NARINFO);

    client
        .put_nar_info(NARINFO, data.clone())
        .await
        .expect("the upload failed");
    client
        .head_nar_info(NARINFO)
        .await
        .expect("the narinfo exists");

    // The fixture is signed by Nix, so the Worker stores and serves it as is.
    let served = client
        .get_nar_info(NARINFO)
        .await
        .expect("the request failed");
    assert_eq!(served, data);
}

#[tokio::test]
async fn test_post_mass_query() {
    let _uploads = helper::UPLOADS.lock().await;
    let client = helper::uploader();
    client
        .put_nar_info(NARINFO, narinfo_fixture(NARINFO))
        .await
        .expect("the upload failed");

    let found = client
        .post_mass_query(format!("{NARINFO}.narinfo\n{MISSING}\n"))
        .await
        .expect("the request failed");
    assert_eq!(found, format!("{NARINFO}.narinfo\n"));
}

#[tokio::test]
async fn test_get_content_addressed_narinfo() {
    let _uploads = helper::UPLOADS.lock().await;
    // Written and signed by Nix for a `nix store add` path: it has a CA: line.
    let hash = "2h2g7i4x6gsadn2s7vi0af6g8b24n584";
    let client = helper::uploader();
    let data = narinfo_fixture(hash);

    client
        .put_nar_info(hash, data.clone())
        .await
        .expect("the upload failed");

    // Served exactly as uploaded, CA: line included.
    let served = client.get_nar_info(hash).await.expect("the request failed");
    assert_eq!(served, data);
    assert!(
        served.contains(
            "\nCA: fixed:r:sha256:1yk2kns0dq14y0gny9hkg9vnzw02bgqxpqxhbaqgi1i8p7yj78rq\n"
        )
    );
}

#[tokio::test]
async fn test_get_narinfo_not_found() {
    let client = helper::uploader();

    let err = client.get_nar_info(MISSING).await.unwrap_err();
    assert!(matches!(
        err.api().and_then(|api| api.typed.as_ref()),
        Some(GetNarInfoApiError::Status404(Error {
            error: ErrorCode::NotFound,
            ..
        }))
    ));
    assert_eq!(
        status(&client.head_nar_info(MISSING).await.unwrap_err()),
        404
    );
}

#[tokio::test]
async fn test_get_nar() {
    let _uploads = helper::UPLOADS.lock().await;
    let client = helper::uploader();
    let data = helper::fixture(&format!("{NAR}.nar"));

    client
        .put_nar(NAR, data.clone())
        .await
        .expect("the upload failed");
    client.head_nar(NAR).await.expect("the NAR exists");

    let served = client.get_nar(NAR).await.expect("the request failed");
    assert_eq!(served.len(), 256);
    assert_eq!(served, data);
}

#[tokio::test]
async fn test_get_nar_not_found() {
    let client = helper::uploader();

    let err = client.get_nar(MISSING).await.unwrap_err();
    assert!(matches!(
        err.api().and_then(|api| api.typed.as_ref()),
        Some(GetNarApiError::Status404(_))
    ));
    assert_eq!(status(&client.head_nar(MISSING).await.unwrap_err()), 404);
}

#[tokio::test]
async fn test_served_content_types() {
    let _uploads = helper::UPLOADS.lock().await;
    // What Nix and nix-serve use. The client doesn't return headers.
    let client = helper::uploader();
    client
        .put_nar_info(NARINFO, narinfo_fixture(NARINFO))
        .await
        .expect("the upload failed");
    client
        .put_nar(NAR, helper::fixture(&format!("{NAR}.nar")))
        .await
        .expect("the upload failed");

    for (path, content_type) in [
        ("nix-cache-info".to_string(), "text/x-nix-cache-info"),
        (format!("{NARINFO}.narinfo"), "text/x-nix-narinfo"),
        (format!("nar/{NAR}.nar"), "application/x-nix-archive"),
    ] {
        let resp = helper::get(&path).await;
        assert_eq!(resp.status(), 200, "{path}");
        assert_eq!(resp.headers()["content-type"], content_type, "{path}");
    }
}

#[tokio::test]
async fn test_put_rejects_undeclared_content_type() {
    let _uploads = helper::UPLOADS.lock().await;
    let resp = helper::put(
        &format!("{NARINFO}.narinfo"),
        "application/octet-stream",
        narinfo_fixture(NARINFO).into_bytes(),
    )
    .await;
    assert_eq!(resp.status(), 415);
}

/// Uploads the fixture narinfo with `authorization`, and returns the
/// rejection's status and body.
async fn rejected(authorization: Option<String>) -> (u16, Option<Error>) {
    let err = helper::client_with(authorization)
        .put_nar_info(NARINFO, narinfo_fixture(NARINFO))
        .await
        .expect_err("the upload should be refused");
    let body = match err.api().and_then(|api| api.typed.clone()) {
        Some(PutNarInfoApiError::Status401(body) | PutNarInfoApiError::Status403(body)) => {
            Some(body)
        }
        _ => None,
    };
    (status(&err), body)
}

/// A token from the test issuer with `claim` changed.
fn token_with(claim: &str, value: Value) -> Option<String> {
    let mut claims = helper::claims();
    claims[claim] = value;
    Some(helper::basic("oidc", &helper::token(&claims)))
}

#[tokio::test]
async fn test_put_rejects_bad_credentials() {
    let _uploads = helper::UPLOADS.lock().await;
    for authorization in [
        None,
        Some("Bearer abc".to_string()),
        Some(helper::basic("oidc", "not-a-jwt")),
    ] {
        let (status, body) = rejected(authorization.clone()).await;
        assert_eq!(status, 401, "{authorization:?}");
        assert_eq!(body.map(|body| body.error), Some(ErrorCode::Unauthorized));
    }
}

#[tokio::test]
async fn test_put_says_why_a_token_is_refused() {
    let _uploads = helper::UPLOADS.lock().await;
    let now = helper::claims()["iat"].as_u64().unwrap();
    for (claim, value, expected) in [
        (
            "iss",
            json!("https://other.example.com"),
            "no provider is for issuer https://other.example.com".to_string(),
        ),
        (
            "aud",
            json!("https://wrong.example.com"),
            format!(
                "token audience is https://wrong.example.com, expected {}",
                helper::base_url()
            ),
        ),
        ("exp", json!(now - 3600), "token expired".to_string()),
    ] {
        let (status, body) = rejected(token_with(claim, value)).await;
        assert_eq!(status, 401, "{claim}");
        assert_eq!(body.map(|body| body.message), Some(expected), "{claim}");
    }
}

#[tokio::test]
async fn test_put_forbids_a_token_no_claim_set_allows() {
    let _uploads = helper::UPLOADS.lock().await;
    let (status, body) = rejected(token_with("ref", json!("refs/heads/dev"))).await;
    assert_eq!(status, 403);
    let body = body.expect("a JSON error");
    assert_eq!(body.error, ErrorCode::Forbidden);
    assert_eq!(
        body.message,
        format!(
            "repo:example-org/app:ref:refs/heads/main: no claim set for {} matched",
            helper::ISSUER
        )
    );
}

#[tokio::test]
async fn test_health() {
    let health = HealthClient::new(helper::base_url());
    assert!(health.is_live().await.expect("the request failed"));
    assert!(health.is_ready().await.expect("the request failed"));
}

#[tokio::test]
async fn test_put_narinfo_keeps_unknown_fields() {
    let _uploads = helper::UPLOADS.lock().await;
    // Nix ignores keys it doesn't know; the Worker must not drop them either.
    let client = helper::uploader();
    let with_extra = format!(
        "{}System: x86_64-linux\nFuture: kept\n",
        narinfo_fixture(NARINFO)
    );

    client
        .put_nar_info(NARINFO, with_extra.clone())
        .await
        .expect("the upload failed");

    let served = client
        .get_nar_info(NARINFO)
        .await
        .expect("the request failed");
    assert_eq!(served, with_extra);
}
