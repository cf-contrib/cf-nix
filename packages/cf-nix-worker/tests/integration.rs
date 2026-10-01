#![cfg(feature = "integration")]

mod helper;

use narinfo::{NarInfo, NixCacheInfo};

#[tokio::test]
async fn test_get_nix_cache_info() {
    let response = helper::get("nix-cache-info")
        .await
        .expect("the request failed");
    assert_eq!(response.status(), 200);
    let data = response.text().await.expect("the body failed");
    let info = NixCacheInfo::parse(&data).expect("the response failed");
    assert_eq!(info.priority, 40);
    assert_eq!(info.store_dir, "/nix/store");
    assert!(info.wants_mass_query);
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

    let resp_body = get_resp.text().await.expect("the body failed");

    let local_info = NarInfo::parse(&file_data).unwrap();
    let server_info = NarInfo::parse(&resp_body).expect("the response failed");
    assert_eq!(server_info.url, local_info.url);
    assert_eq!(server_info.nar_hash, local_info.nar_hash);
    assert_eq!(server_info.store_path, local_info.store_path);
    assert_eq!(server_info.deriver.unwrap(), local_info.deriver.unwrap(),);
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
    let resp = helper::get_with_auth("auth/whoami", "github", &helper::github_token())
        .await
        .expect("the request failed");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value =
        serde_json::from_str(&resp.text().await.expect("the body failed")).unwrap();
    assert_eq!(body["kind"], "github");
    assert!(
        body["subject"]
            .as_str()
            .is_some_and(|login| !login.is_empty())
    );
}

#[tokio::test]
async fn test_whoami_without_credentials() {
    let resp = helper::get("auth/whoami")
        .await
        .expect("the request failed");
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_whoami_with_oidc_disabled() {
    // The dev config only sets CF_NIX_CACHE_GITHUB_REPOSITORY, so OIDC auth is off.
    let resp = helper::get_with_auth("auth/whoami", "oidc", "a.b.c")
        .await
        .expect("the request failed");
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_put_rejects_bad_credentials() {
    let file_name = "j5m1qd2dbsmhq0mw13yb8wijnm3pq4z0.narinfo";
    let file_data = std::fs::read_to_string(format!("tests/fixture/{file_name}")).unwrap();

    for credentials in [
        None,
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
