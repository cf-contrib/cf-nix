#![cfg(feature = "integration")]

mod helper;

#[tokio::test]
async fn test_get_nix_cache_info() {
    let response = helper::get("nix-cache-info")
        .await
        .expect("the request failed");
    assert_eq!(response.status(), 200);
    let data = response.text().await.expect("the body failed");
    assert_eq!(
        data,
        "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n"
    );
}

#[tokio::test]
async fn test_get_narinfo() {
    let file_type = "text/x-nix-narinfo";
    let file_name = "j5m1qd2dbsmhq0mw13yb8wijnm3pq4z0.narinfo";
    let file_path = format!("tests/fixture/{file_name}");
    let file_data = std::fs::read_to_string(file_path).unwrap();

    let post_resp = helper::put(file_name, file_type, file_data.clone())
        .await
        .expect("the request failed");
    assert_eq!(post_resp.status(), 200);

    let get_resp = helper::get(file_name).await.expect("the request failed");
    assert_eq!(get_resp.status(), 200);
    assert_eq!(get_resp.headers().get("content-type").unwrap(), file_type);

    // The fixture is signed by Nix, so the Worker stores and serves it as is.
    let resp_body = get_resp.text().await.expect("the body failed");
    assert_eq!(resp_body, file_data);
}

#[tokio::test]
async fn test_post_narinfo() {
    let file_type = "text/plain; charset=utf-8";
    let file_name = "j5m1qd2dbsmhq0mw13yb8wijnm3pq4z0.narinfo";
    let file_path = format!("tests/fixture/{file_name}");
    let file_data = std::fs::read_to_string(file_path).unwrap();

    let post_resp = helper::put(file_name, file_type, file_data.clone())
        .await
        .expect("the request failed");
    assert_eq!(post_resp.status(), 200);

    let get_resp = helper::post("/", "text/x-nix-narinfo", file_name)
        .await
        .expect("the request failed");
    assert_eq!(get_resp.status(), 200);
    assert_eq!(get_resp.headers().get("content-type").unwrap(), file_type);

    let resp_body = get_resp.text().await.expect("the body failed");
    let lines: Vec<&str> = resp_body.lines().collect();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines.first().unwrap(), &file_name);
}

#[tokio::test]
async fn test_get_content_addressed_narinfo() {
    // Written and signed by Nix for a `nix store add` path: it has a CA: line.
    let file_type = "text/x-nix-narinfo";
    let file_name = "2h2g7i4x6gsadn2s7vi0af6g8b24n584.narinfo";
    let file_path = format!("tests/fixture/{file_name}");
    let file_data = std::fs::read_to_string(file_path).unwrap();

    let put_resp = helper::put(file_name, file_type, file_data.clone())
        .await
        .expect("the request failed");
    assert_eq!(put_resp.status(), 200);

    let get_resp = helper::get(file_name).await.expect("the request failed");
    assert_eq!(get_resp.status(), 200);

    // Served exactly as uploaded, CA: line included.
    let resp_body = get_resp.text().await.expect("the body failed");
    assert_eq!(resp_body, file_data);
    assert!(
        resp_body.contains(
            "\nCA: fixed:r:sha256:1yk2kns0dq14y0gny9hkg9vnzw02bgqxpqxhbaqgi1i8p7yj78rq\n"
        )
    );
}

#[tokio::test]
async fn test_get_narinfo_not_found() {
    let get_resp = helper::get("j6m2qd3dbsmhq0mw14yb9wijnm4pq6z1.narinfo")
        .await
        .expect("the request failed");
    assert_eq!(get_resp.status(), 404);
}

#[tokio::test]
async fn test_get_nar() {
    let file_type = "application/x-nix-archive";
    let file_name = "j5m1qd2dbsmhq0mw13yb8wijnm3pq4z0.nar";
    let file_path = format!("tests/fixture/{file_name}");
    let file_url = format!("nar/{file_name}");
    let file_data = std::fs::read(file_path).unwrap();

    let post_resp = helper::put(&file_url, file_type, file_data.clone())
        .await
        .expect("the request failed");
    assert_eq!(post_resp.status(), 200);

    let get_resp = helper::get(&file_url).await.expect("the request failed");
    assert_eq!(get_resp.status(), 200);
    assert_eq!(get_resp.headers().get("content-type").unwrap(), file_type,);

    let bytes = get_resp.bytes().await.expect("body read failed");
    assert!(!bytes.is_empty(), "nar body should not be empty");
    assert_eq!(bytes.len(), 256);
}

#[tokio::test]
async fn test_get_nar_not_found() {
    let get_resp = helper::get("nar/j6m2qd3dbsmhq0mw14yb9wijnm4pq6z1.nar")
        .await
        .expect("the request failed");
    assert_eq!(get_resp.status(), 404);
}

#[tokio::test]
async fn test_whoami_with_github_token() {
    let resp = helper::get_with_auth("v1/whoami", "user", &helper::github_token())
        .await
        .expect("the request failed");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value =
        serde_json::from_str(&resp.text().await.expect("the body failed")).unwrap();
    assert_eq!(body["kind"], "user");
    assert!(
        body["subject"]
            .as_str()
            .is_some_and(|login| !login.is_empty())
    );
}

#[tokio::test]
async fn test_whoami_without_credentials() {
    let resp = helper::get("v1/whoami").await.expect("the request failed");
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_whoami_with_oidc_disabled() {
    // The dev config only sets CF_NIX_WORKER_GITHUB_REPOSITORY, so OIDC auth is off.
    let resp = helper::get_with_auth("v1/whoami", "actions", "a.b.c")
        .await
        .expect("the request failed");
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value =
        serde_json::from_str(&resp.text().await.expect("the body failed")).unwrap();
    assert_eq!(
        body,
        serde_json::json!({ "error": "unauthorized", "message": "actions auth is not enabled" })
    );
}

#[tokio::test]
async fn test_put_rejects_bad_credentials() {
    let file_name = "j5m1qd2dbsmhq0mw13yb8wijnm3pq4z0.narinfo";
    let file_data = std::fs::read_to_string(format!("tests/fixture/{file_name}")).unwrap();

    for credentials in [
        None,
        Some(("user", "gho_notARealToken000000000000000000000")),
        Some(("github", "gho_notARealToken000000000000000000000")),
        Some(("x-auth-token", "nix-token-dev")),
        Some(("someone", "secret")),
    ] {
        let resp = helper::put_with_auth(
            file_name,
            "text/x-nix-narinfo",
            file_data.clone(),
            credentials,
        )
        .await
        .expect("the request failed");
        assert_eq!(resp.status(), 401, "{credentials:?}");
    }
}

#[tokio::test]
async fn test_healthz() {
    let resp = helper::get("healthz").await.expect("the request failed");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.expect("the body failed"), "ok");
}

#[tokio::test]
async fn test_put_narinfo_keeps_unknown_fields() {
    // Nix ignores keys it doesn't know; the Worker must not drop them either.
    let file_name = "j5m1qd2dbsmhq0mw13yb8wijnm3pq4z0.narinfo";
    let file_data = std::fs::read_to_string(format!("tests/fixture/{file_name}")).unwrap();
    let with_extra = format!("{file_data}System: x86_64-linux\nFuture: kept\n");

    let put_resp = helper::put(file_name, "text/x-nix-narinfo", with_extra.clone())
        .await
        .expect("the request failed");
    assert_eq!(put_resp.status(), 200);

    let get_resp = helper::get(file_name).await.expect("the request failed");
    assert_eq!(get_resp.text().await.expect("the body failed"), with_extra);
}
