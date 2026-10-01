use std::cell::RefCell;

use serde::Deserialize;
use worker::{Date, Fetch, Headers, Method, Request, RequestInit, Response};

use crate::auth::{AuthError, Identity, IdentityKind, TtlCache};

const API_URL: &str = "https://api.github.com";

/// How long a user check result is reused, so a `nix copy` doesn't call the
/// GitHub API on every PUT.
const CACHE_TTL_MS: u64 = 5 * 60 * 1000;

thread_local! {
    static CACHE: RefCell<TtlCache<Result<Identity, AuthError>>> = RefCell::new(TtlCache::new());
}

/// GitHub user token auth: anyone with push access to `repository` can upload.
#[derive(Debug)]
pub struct Config {
    /// `owner/repo` (`GITHUB_REPOSITORY`).
    pub repository: String,
}

impl Config {
    pub fn parse(repository: &str) -> Result<Self, String> {
        let valid_part = |part: &str| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        };
        match repository.split_once('/') {
            Some((owner, repo)) if valid_part(owner) && valid_part(repo) => Ok(Self {
                repository: repository.to_string(),
            }),
            _ => Err("GITHUB_REPOSITORY must be in the format owner/repo".to_string()),
        }
    }
}

#[derive(Deserialize)]
struct User {
    login: String,
}

#[derive(Deserialize)]
struct Repository {
    #[serde(default)]
    permissions: Option<Permissions>,
}

#[derive(Deserialize)]
struct Permissions {
    #[serde(default)]
    push: bool,
}

/// Checks that `token` belongs to a GitHub user with push access to the
/// configured repository.
pub async fn authorize(config: &Config, token: &str) -> Result<Identity, AuthError> {
    reject_installation_token(token)?;

    let key = TtlCache::<()>::key(token);
    let now = Date::now().as_millis();
    if let Some(result) = CACHE.with_borrow(|cache| cache.get(&key, now)) {
        return result;
    }

    let result = check(config, token).await;
    // Transient failures are retried on the next request, not cached.
    if !matches!(result, Err(AuthError::Upstream(_))) {
        CACHE.with_borrow_mut(|cache| cache.insert(key, result.clone(), now + CACHE_TTL_MS, now));
    }
    result
}

/// `GITHUB_TOKEN` and other installation tokens identify a repo, not a
/// person, and fork PRs get one too. CI should use OIDC instead.
fn reject_installation_token(token: &str) -> Result<(), AuthError> {
    if token.starts_with("ghs_") {
        return Err(AuthError::Unauthorized(
            "GitHub App installation tokens (including GITHUB_TOKEN) are not accepted; \
             in GitHub Actions use the oidc username with an Actions OIDC token"
                .to_string(),
        ));
    }
    Ok(())
}

async fn check(config: &Config, token: &str) -> Result<Identity, AuthError> {
    let mut resp = get(&format!("{API_URL}/user"), token).await?;
    if resp.status_code() != 200 {
        return Err(error_for(&resp, "GitHub token"));
    }
    let user: User = resp
        .json()
        .await
        .map_err(|err| AuthError::Upstream(format!("GitHub /user response: {err}")))?;

    let repository = &config.repository;
    let mut resp = get(&format!("{API_URL}/repos/{repository}"), token).await?;
    if resp.status_code() != 200 {
        return Err(error_for(&resp, repository));
    }
    let repo: Repository = resp
        .json()
        .await
        .map_err(|err| AuthError::Upstream(format!("GitHub /repos response: {err}")))?;

    if !repo.permissions.is_some_and(|p| p.push) {
        return Err(AuthError::Forbidden(format!(
            "{} has no push access to {repository}",
            user.login
        )));
    }

    Ok(Identity {
        kind: IdentityKind::Github,
        subject: user.login,
        rule: None,
    })
}

async fn get(url: &str, token: &str) -> Result<Response, AuthError> {
    let upstream = |err: worker::Error| AuthError::Upstream(format!("GitHub API request: {err}"));

    let headers = Headers::new();
    headers
        .set("Accept", "application/vnd.github+json")
        .map_err(upstream)?;
    headers
        .set("Authorization", &format!("Bearer {token}"))
        .map_err(upstream)?;
    headers
        .set("User-Agent", "cf-nix-cache")
        .map_err(upstream)?;
    headers
        .set("X-GitHub-Api-Version", "2022-11-28")
        .map_err(upstream)?;

    let mut init = RequestInit::new();
    init.with_method(Method::Get).with_headers(headers);
    let req = Request::new_with_init(url, &init).map_err(upstream)?;
    Fetch::Request(req).send().await.map_err(upstream)
}

fn error_for(resp: &Response, resource: &str) -> AuthError {
    let header = |name| resp.headers().get(name).ok().flatten();
    classify(
        resp.status_code(),
        header("x-ratelimit-remaining").as_deref() == Some("0"),
        header("x-github-sso").is_some(),
        resource,
    )
}

/// Maps a non-200 GitHub API status to an auth error.
fn classify(status: u16, rate_limited: bool, sso_required: bool, resource: &str) -> AuthError {
    match status {
        401 => AuthError::Unauthorized(format!("{resource}: invalid GitHub token")),
        429 => AuthError::Upstream(format!("{resource}: GitHub API rate limit exceeded")),
        403 if rate_limited => {
            AuthError::Upstream(format!("{resource}: GitHub API rate limit exceeded"))
        }
        403 if sso_required => AuthError::Forbidden(format!(
            "{resource}: the GitHub token must be authorized for SAML SSO"
        )),
        403 | 404 => AuthError::Forbidden(format!("{resource}: no access with this GitHub token")),
        _ => AuthError::Upstream(format!("{resource}: GitHub API returned {status}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_accepts_owner_repo() {
        let config = Config::parse("example-org/nix.config_1").expect("should parse");
        assert_eq!(config.repository, "example-org/nix.config_1");
    }

    #[test]
    fn config_rejects_bad_repository() {
        for value in [
            "",
            "example-org",
            "/repo",
            "example-org/",
            "a/b/c",
            "a/b?x=1",
        ] {
            assert!(Config::parse(value).is_err(), "{value} should be rejected");
        }
    }

    #[test]
    fn installation_tokens_are_rejected() {
        assert!(matches!(
            reject_installation_token("ghs_example"),
            Err(AuthError::Unauthorized(_))
        ));
        assert!(reject_installation_token("gho_example").is_ok());
        assert!(reject_installation_token("github_pat_example").is_ok());
    }

    #[test]
    fn classify_maps_statuses() {
        let r = "example-org/infra";
        assert!(matches!(
            classify(401, false, false, r),
            AuthError::Unauthorized(_)
        ));
        assert!(matches!(
            classify(403, false, false, r),
            AuthError::Forbidden(_)
        ));
        assert!(matches!(
            classify(404, false, false, r),
            AuthError::Forbidden(_)
        ));
        assert!(matches!(
            classify(403, true, false, r),
            AuthError::Upstream(_)
        ));
        assert!(matches!(
            classify(429, false, false, r),
            AuthError::Upstream(_)
        ));
        assert!(matches!(
            classify(500, false, false, r),
            AuthError::Upstream(_)
        ));

        let AuthError::Forbidden(msg) = classify(403, false, true, r) else {
            panic!("SSO should be forbidden");
        };
        assert!(msg.contains("SSO"));
    }

    #[test]
    fn repository_without_permissions_has_no_push() {
        let repo: Repository =
            serde_json::from_str(r#"{"full_name":"example-org/infra"}"#).unwrap();
        assert!(!repo.permissions.is_some_and(|p| p.push));

        let repo: Repository =
            serde_json::from_str(r#"{"permissions":{"admin":false,"push":true,"pull":true}}"#)
                .unwrap();
        assert!(repo.permissions.is_some_and(|p| p.push));
    }
}
