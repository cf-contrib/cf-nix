use std::fmt;

use http_auth_basic::Credentials;
use serde::Serialize;
use worker::{Env, Request, Response, Result, console_error};

mod cache;
mod github;
mod oidc;

/// The identity an authorized request was resolved to.
///
/// Returned by `GET /auth/whoami` and logged for every upload.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Identity {
    pub kind: IdentityKind,
    /// GitHub login (`github`) or the OIDC `sub` claim (`oidc`).
    pub subject: String,
    /// Index of the matching `CF_NIX_WORKER_GITHUB_OIDC_RULES` entry (`oidc` only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityKind {
    Github,
    Oidc,
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            IdentityKind::Github => "github",
            IdentityKind::Oidc => "oidc",
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
            AuthError::Unauthorized(msg) => Response::error(msg, 401),
            AuthError::Forbidden(msg) => Response::error(msg, 403),
            AuthError::Config(msg) => {
                console_error!("auth config invalid: {msg}");
                Response::error("auth is misconfigured", 500)
            }
            AuthError::Upstream(msg) => {
                console_error!("auth upstream failure: {msg}");
                Response::error("auth upstream failure", 502)
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
    /// `github:<GitHub user token>`
    Github(String),
    /// `oidc:<GitHub Actions OIDC JWT>`
    Oidc(String),
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
            "github" => Ok(Credential::Github(input.password)),
            "oidc" => Ok(Credential::Oidc(input.password)),
            _ => Err(AuthError::Unauthorized(
                "unknown username: use github or oidc".to_string(),
            )),
        }
    }
}

/// Resolves the request's HTTP Basic credentials to an identity allowed to
/// upload.
pub async fn authorize(req: &Request, env: &Env) -> std::result::Result<Identity, AuthError> {
    let config = Config::from_env(env)?;
    let header = req.headers().get("Authorization").unwrap_or_default();

    match Credential::parse(header.as_deref())? {
        Credential::Github(token) => {
            let Some(config) = config.github else {
                return Err(AuthError::Unauthorized(
                    "github auth is not enabled".to_string(),
                ));
            };
            github::authorize(&config, &token).await
        }
        Credential::Oidc(jwt) => {
            let Some(config) = config.oidc else {
                return Err(AuthError::Unauthorized(
                    "oidc auth is not enabled".to_string(),
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
            parse("github", "gho_example"),
            Ok(Credential::Github("gho_example".to_string()))
        );
        assert_eq!(
            parse("oidc", "a.b.c"),
            Ok(Credential::Oidc("a.b.c".to_string()))
        );
        for user in ["someone", "x-auth-token"] {
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
            kind: IdentityKind::Oidc,
            subject: "repo:example-org/app:ref:refs/heads/main".to_string(),
            rule: Some(0),
        };
        assert_eq!(
            serde_json::to_value(&identity).unwrap(),
            serde_json::json!({
                "kind": "oidc",
                "subject": "repo:example-org/app:ref:refs/heads/main",
                "rule": 0,
            })
        );
    }
}
