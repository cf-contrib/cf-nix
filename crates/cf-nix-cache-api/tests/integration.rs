#![cfg(feature = "integration")]

mod helper;

use cf_nix_cache_sdk::v1::{
    ApiOpError, Error, ErrorCode, GetNarApiError, GetNarInfoApiError, GetWhoamiApiError,
    IdentityKind, PutNarInfoApiError,
};

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
    let _lock = helper::NARINFO_LOCK.lock().await;
    let client = helper::client();
    let data = narinfo_fixture(NARINFO);

    client
        .put_nar_info(NARINFO, helper::uploader(), data.clone())
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
    let _lock = helper::NARINFO_LOCK.lock().await;
    let client = helper::client();
    client
        .put_nar_info(NARINFO, helper::uploader(), narinfo_fixture(NARINFO))
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
    // Written and signed by Nix for a `nix store add` path: it has a CA: line.
    let hash = "2h2g7i4x6gsadn2s7vi0af6g8b24n584";
    let client = helper::client();
    let data = narinfo_fixture(hash);

    client
        .put_nar_info(hash, helper::uploader(), data.clone())
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
    let client = helper::client();

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
    let client = helper::client();
    let data = helper::fixture(&format!("{NAR}.nar"));

    client
        .put_nar(NAR, helper::uploader(), data.clone())
        .await
        .expect("the upload failed");
    client.head_nar(NAR).await.expect("the NAR exists");

    let served = client.get_nar(NAR).await.expect("the request failed");
    assert_eq!(served.len(), 256);
    assert_eq!(served, data);
}

#[tokio::test]
async fn test_get_nar_not_found() {
    let client = helper::client();

    let err = client.get_nar(MISSING).await.unwrap_err();
    assert!(matches!(
        err.api().and_then(|api| api.typed.as_ref()),
        Some(GetNarApiError::Status404(_))
    ));
    assert_eq!(status(&client.head_nar(MISSING).await.unwrap_err()), 404);
}

#[tokio::test]
async fn test_served_content_types() {
    let _lock = helper::NARINFO_LOCK.lock().await;
    // What Nix and nix-serve use. The client doesn't return headers.
    let client = helper::client();
    client
        .put_nar_info(NARINFO, helper::uploader(), narinfo_fixture(NARINFO))
        .await
        .expect("the upload failed");
    client
        .put_nar(
            NAR,
            helper::uploader(),
            helper::fixture(&format!("{NAR}.nar")),
        )
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
    let resp = helper::put(
        &format!("{NARINFO}.narinfo"),
        "application/octet-stream",
        narinfo_fixture(NARINFO).into_bytes(),
    )
    .await;
    assert_eq!(resp.status(), 415);
}

#[tokio::test]
async fn test_whoami_with_github_token() {
    let identity = helper::client()
        .get_whoami(helper::uploader())
        .await
        .expect("the request failed");
    assert_eq!(identity.kind, IdentityKind::Users);
    assert!(!identity.subject.is_empty());
}

#[tokio::test]
async fn test_whoami_without_credentials() {
    let err = helper::client()
        .get_whoami(None::<String>)
        .await
        .unwrap_err();
    assert_eq!(status(&err), 401);
}

#[tokio::test]
async fn test_whoami_with_oidc_disabled() {
    // The dev config only sets CF_NIX_WORKER_GITHUB_REPOSITORY, so OIDC auth is off.
    let err = helper::client()
        .get_whoami(Some(helper::basic("actions", "a.b.c")))
        .await
        .unwrap_err();
    let Some(GetWhoamiApiError::Status401(body)) = err.api().and_then(|api| api.typed.clone())
    else {
        panic!("expected a 401: {err:?}");
    };
    assert_eq!(body.error, ErrorCode::Unauthorized);
    assert_eq!(body.message, "actions auth is not enabled");
}

#[tokio::test]
async fn test_put_rejects_bad_credentials() {
    let client = helper::client();
    let data = narinfo_fixture(NARINFO);

    for credentials in [
        None,
        Some(("users", "gho_notARealToken000000000000000000000")),
        Some(("github", "gho_notARealToken000000000000000000000")),
        Some(("x-auth-token", "nix-token-dev")),
        Some(("someone", "secret")),
    ] {
        let authorization = credentials.map(|(user, password)| helper::basic(user, password));
        let err = client
            .put_nar_info(NARINFO, authorization, data.clone())
            .await
            .unwrap_err();
        assert!(
            matches!(
                err.api().and_then(|api| api.typed.as_ref()),
                Some(PutNarInfoApiError::Status401(_))
            ),
            "{credentials:?}: {err:?}"
        );
    }
}

#[tokio::test]
async fn test_healthz() {
    // Not in the spec, so the client has no method for it.
    let resp = helper::get("healthz").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.expect("the body failed"), "ok");
}

#[tokio::test]
async fn test_put_narinfo_keeps_unknown_fields() {
    let _lock = helper::NARINFO_LOCK.lock().await;
    // Nix ignores keys it doesn't know; the Worker must not drop them either.
    let client = helper::client();
    let with_extra = format!(
        "{}System: x86_64-linux\nFuture: kept\n",
        narinfo_fixture(NARINFO)
    );

    client
        .put_nar_info(NARINFO, helper::uploader(), with_extra.clone())
        .await
        .expect("the upload failed");

    let served = client
        .get_nar_info(NARINFO)
        .await
        .expect("the request failed");
    assert_eq!(served, with_extra);
}
