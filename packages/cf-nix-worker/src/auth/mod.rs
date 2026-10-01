use std::fmt;

use http_auth_basic::Credentials;
use serde::Serialize;
use worker::{Env, Request, Response, Result, console_error};

use crate::error_response;

mod cache;
mod github;
mod oidc;

/// The identity an authorized request was resolved to.
///
/// Returned by `GET /v1/whoami` and logged for every upload.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Identity {
    pub kind: IdentityKind,
    /// GitHub login (`user`) or the OIDC `sub` claim (`actions`).
    pub subject: String,
    /// Index of the matching `CF_NIX_WORKER_GITHUB_OIDC_RULES` entry (`actions` only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityKind {
    /// A person, with their GitHub user token.
    User,
    /// A GitHub Actions job, with its OIDC token.
    Actions,
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            IdentityKind::User => "user",
            IdentityKind::Actions => "actions",
        };
        write!(f, "{kind}:{}", self.subject)?;
        if let Some(rule) = self.rule {
            write!(f, " (rule {rule})")?;
        }
        Ok(())
    }
}

/// Why a request was not authorized.
#[derive(Clone, Debug, PartialEq)]
pub enum AuthError {
    /// Missing or invalid credentials (`401`).
    Unauthorized(String),
    /// Valid credentials without upload access (`403`).
    Forbidden(String),
    /// The Worker's auth configuration is invalid (`500`). Fails closed.
    Config(String),
    /// The GitHub API or the JWKS endpoint failed (`502`). Not the caller's fault.
    Upstream(String),
}

impl AuthError {
    /// Converts the error into a response. Config and upstream details are
    /// logged, not returned.
    pub fn into_response(self) -> Result<Response> {
        match self {
            AuthError::Unauthorized(msg) => error_response(401, "unauthorized", &msg),
            AuthError::Forbidden(msg) => error_response(403, "forbidden", &msg),
            AuthError::Config(msg) => {
                console_error!("auth config invalid: {msg}");
                error_response(500, "misconfigured", "auth is misconfigured")
            }
            AuthError::Upstream(msg) => {
                console_error!("auth upstream failure: {msg}");
                error_response(502, "upstream_error", "GitHub couldn't be reached")
            }
        }
    }
}

/// Auth configuration read from the Worker's vars and secrets.
///
/// Each mechanism is enabled only when its vars are set. With none set,
/// every authorized request is rejected with `401`.
#[derive(Debug)]
struct Config {
    /// GitHub user tokens (`CF_NIX_WORKER_GITHUB_REPOSITORY`).
    github: Option<github::Config>,
    /// GitHub Actions OIDC (`CF_NIX_WORKER_GITHUB_OWNER_ID`, `CF_NIX_WORKER_GITHUB_OIDC_AUDIENCE`, `CF_NIX_WORKER_GITHUB_OIDC_RULES`).
    oidc: Option<oidc::Config>,
}

impl Config {
    fn from_env(env: &Env) -> std::result::Result<Self, AuthError> {
        Self::from_vars(|name| {
            env.var(name)
                .ok()
                .map(|value| value.to_string())
                .filter(|value| !value.is_empty())
        })
    }

    fn from_vars(get: impl Fn(&str) -> Option<String>) -> std::result::Result<Self, AuthError> {
        let github = get("CF_NIX_WORKER_GITHUB_REPOSITORY")
            .map(|repository| github::Config::parse(&repository))
            .transpose()
            .map_err(AuthError::Config)?;

        let oidc = match (
            get("CF_NIX_WORKER_GITHUB_OWNER_ID"),
            get("CF_NIX_WORKER_GITHUB_OIDC_AUDIENCE"),
            get("CF_NIX_WORKER_GITHUB_OIDC_RULES"),
        ) {
            (None, None, None) => None,
            (Some(owner_id), Some(audience), Some(rules)) => {
                Some(oidc::Config::parse(&owner_id, &audience, &rules).map_err(AuthError::Config)?)
            }
            _ => {
                return Err(AuthError::Config(
                    "OIDC needs CF_NIX_WORKER_GITHUB_OWNER_ID, CF_NIX_WORKER_GITHUB_OIDC_AUDIENCE and CF_NIX_WORKER_GITHUB_OIDC_RULES"
                        .to_string(),
                ));
            }
        };

        Ok(Self { github, oidc })
    }
}

/// A credential taken from the HTTP Basic `Authorization` header. The
/// username selects how the password is verified.
#[derive(Debug, PartialEq)]
enum Credential {
    /// `user:<GitHub user token>`
    User(String),
    /// `actions:<GitHub Actions OIDC JWT>`
    Actions(String),
}

impl Credential {
    fn parse(header: Option<&str>) -> std::result::Result<Self, AuthError> {
        let Some(header) = header else {
            return Err(AuthError::Unauthorized("missing credentials".to_string()));
        };

        let Ok(input) = Credentials::from_header(header.to_string()) else {
            return Err(AuthError::Unauthorized("invalid credentials".to_string()));
        };

        match input.user_id.as_str() {
            "user" => Ok(Credential::User(input.password)),
            "actions" => Ok(Credential::Actions(input.password)),
            _ => Err(AuthError::Unauthorized(
                "unknown username: use user or actions".to_string(),
            )),
        }
    }
}

/// Checks that the auth config is valid, for `GET /healthz`.
pub fn check_config(env: &Env) -> std::result::Result<(), String> {
    match Config::from_env(env) {
        Ok(_) => Ok(()),
        Err(AuthError::Config(msg)) => Err(msg),
        Err(err) => Err(format!("{err:?}")),
    }
}

/// Resolves the request's HTTP Basic credentials to an identity allowed to
/// upload.
pub async fn authorize(req: &Request, env: &Env) -> std::result::Result<Identity, AuthError> {
    let config = Config::from_env(env)?;
    let header = req.headers().get("Authorization").unwrap_or_default();

    match Credential::parse(header.as_deref())? {
        Credential::User(token) => {
            let Some(config) = config.github else {
                return Err(AuthError::Unauthorized(
                    "user auth is not enabled".to_string(),
                ));
            };
            github::authorize(&config, &token).await
        }
        Credential::Actions(jwt) => {
            let Some(config) = config.oidc else {
                return Err(AuthError::Unauthorized(
                    "actions auth is not enabled".to_string(),
                ));
            };
            oidc::authorize(&config, &jwt).await
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name| map.get(name).cloned()
    }

    fn basic(user: &str, password: &str) -> String {
        Credentials::new(user, password).as_http_header()
    }

    #[test]
    fn config_with_nothing_set_disables_every_mechanism() {
        let config = Config::from_vars(vars(&[])).expect("empty config is valid");
        assert!(config.github.is_none());
        assert!(config.oidc.is_none());
    }

    #[test]
    fn config_enables_oidc_with_all_three_vars() {
        let config = Config::from_vars(vars(&[
            ("CF_NIX_WORKER_GITHUB_OWNER_ID", "100000001"),
            (
                "CF_NIX_WORKER_GITHUB_OIDC_AUDIENCE",
                "https://cache.example.com",
            ),
            (
                "CF_NIX_WORKER_GITHUB_OIDC_RULES",
                r#"[{"ref":"refs/heads/main"}]"#,
            ),
        ]))
        .expect("config should parse");
        assert!(config.oidc.is_some());
    }

    #[test]
    fn config_rejects_partial_oidc() {
        let err = Config::from_vars(vars(&[(
            "CF_NIX_WORKER_GITHUB_OIDC_AUDIENCE",
            "https://cache.example.com",
        )]))
        .unwrap_err();
        assert!(matches!(err, AuthError::Config(_)));
    }

    #[test]
    fn config_rejects_invalid_repository() {
        let err = Config::from_vars(vars(&[("CF_NIX_WORKER_GITHUB_REPOSITORY", "not-a-repo")]))
            .unwrap_err();
        assert!(matches!(err, AuthError::Config(_)));
    }

    #[test]
    fn credential_dispatches_on_username() {
        let parse = |user, password| Credential::parse(Some(&basic(user, password)));
        assert_eq!(
            parse("user", "gho_example"),
            Ok(Credential::User("gho_example".to_string()))
        );
        assert_eq!(
            parse("actions", "a.b.c"),
            Ok(Credential::Actions("a.b.c".to_string()))
        );
        for user in ["someone", "x-auth-token", "github", "oidc"] {
            assert!(matches!(
                parse(user, "secret"),
                Err(AuthError::Unauthorized(_))
            ));
        }
    }

    #[test]
    fn credential_rejects_missing_or_malformed_header() {
        assert!(matches!(
            Credential::parse(None),
            Err(AuthError::Unauthorized(_))
        ));
        assert!(matches!(
            Credential::parse(Some("Bearer abc")),
            Err(AuthError::Unauthorized(_))
        ));
    }

    #[test]
    fn identity_serializes_for_whoami() {
        let identity = Identity {
            kind: IdentityKind::Actions,
            subject: "repo:example-org/app:ref:refs/heads/main".to_string(),
            rule: Some(0),
        };
        assert_eq!(
            serde_json::to_value(&identity).unwrap(),
            serde_json::json!({
                "kind": "actions",
                "subject": "repo:example-org/app:ref:refs/heads/main",
                "rule": 0,
            })
        );
    }
}
