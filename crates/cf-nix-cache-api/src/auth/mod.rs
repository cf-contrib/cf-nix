//! Upload auth: an OIDC token from an issuer `CF_NIX_CACHE_API_OIDC_ISSUERS`
//! names, as the password of HTTP Basic credentials, since a netrc file is the
//! only place Nix sends them from. The username isn't read.

use std::fmt;

use cf_nix_cache_sdk::v1::{self, ErrorCode};
use http_auth_basic::Credentials;
use worker::{Env, console_error};

use crate::error;

mod cache;
mod oidc;

/// The binding the issuers are configured in.
const ISSUERS: &str = "CF_NIX_CACHE_API_OIDC_ISSUERS";

/// The identity an authorized upload was resolved to. Logged for every upload.
#[derive(Clone, Debug, PartialEq)]
pub struct Identity {
    /// The token's `iss`.
    pub issuer: String,
    /// The token's `sub`.
    pub subject: String,
    /// Index of the issuer's claim set that matched.
    pub claims: usize,
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} from {} (claims[{}])",
            self.subject, self.issuer, self.claims
        )
    }
}

/// Why a request was not authorized.
#[derive(Clone, Debug, PartialEq)]
pub enum AuthError {
    /// Missing or invalid credentials (`401`).
    Unauthorized(String),
    /// A valid token no claim set allows (`403`).
    Forbidden(String),
    /// The Worker's auth configuration is invalid (`500`). Fails closed.
    Config(String),
    /// An issuer's discovery document or keys couldn't be fetched (`502`).
    /// Not the caller's fault.
    Upstream(String),
}

/// Converts the error into the response of each operation that authorizes,
/// which share these four. Config and upstream details are logged, not
/// returned.
macro_rules! impl_from_auth_error {
    ($($response:ident),*) => {$(
        impl From<AuthError> for v1::$response {
            fn from(err: AuthError) -> Self {
                match err {
                    AuthError::Unauthorized(msg) => {
                        Self::Unauthorized(error(ErrorCode::Unauthorized, msg))
                    }
                    AuthError::Forbidden(msg) => Self::Forbidden(error(ErrorCode::Forbidden, msg)),
                    AuthError::Config(msg) => {
                        console_error!("auth config invalid: {msg}");
                        Self::InternalServerError(error(
                            ErrorCode::Misconfigured,
                            "auth is misconfigured",
                        ))
                    }
                    AuthError::Upstream(msg) => {
                        console_error!("auth upstream failure: {msg}");
                        Self::BadGateway(error(
                            ErrorCode::UpstreamError,
                            "the token's issuer couldn't be reached",
                        ))
                    }
                }
            }
        }
    )*};
}

impl_from_auth_error!(PutNarInfoResponse, PutNarResponse);

/// The auth config, or `None` if no issuer is configured, which turns uploads
/// off.
fn config(value: Option<String>) -> Result<Option<oidc::Config>, AuthError> {
    value
        .filter(|value| !value.is_empty())
        .map(|value| oidc::Config::parse(&value).map_err(AuthError::Config))
        .transpose()
}

fn config_from_env(env: &Env) -> Result<Option<oidc::Config>, AuthError> {
    config(env.var(ISSUERS).ok().map(|value| value.to_string()))
}

/// The token in an `Authorization: Basic` header: its password.
fn token(header: Option<&str>) -> Result<String, AuthError> {
    let Some(header) = header else {
        return Err(AuthError::Unauthorized("missing credentials".to_string()));
    };
    match Credentials::from_header(header.to_string()) {
        Ok(credentials) if !credentials.password.is_empty() => Ok(credentials.password),
        _ => Err(AuthError::Unauthorized(
            "invalid credentials: send HTTP Basic auth with the token as the password".to_string(),
        )),
    }
}

/// Checks that the auth config is valid, for `GET /healthz`.
pub fn check_config(env: &Env) -> Result<(), String> {
    match config_from_env(env) {
        Ok(_) => Ok(()),
        Err(AuthError::Config(msg)) => Err(msg),
        Err(err) => Err(format!("{err:?}")),
    }
}

/// Resolves a request's `Authorization` header to an identity allowed to
/// upload.
pub async fn authorize(header: Option<&str>, env: &Env) -> Result<Identity, AuthError> {
    let Some(config) = config_from_env(env)? else {
        return Err(AuthError::Unauthorized(format!(
            "uploads are off: {ISSUERS} is not set"
        )));
    };
    oidc::authorize(&config, &token(header)?).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic(user: &str, password: &str) -> String {
        Credentials::new(user, password).as_http_header()
    }

    #[test]
    fn config_is_off_without_issuers() {
        assert!(config(None).unwrap().is_none());
        assert!(config(Some(String::new())).unwrap().is_none());
    }

    #[test]
    fn config_fails_closed() {
        assert!(matches!(
            config(Some("not json".to_string())),
            Err(AuthError::Config(_))
        ));
    }

    #[test]
    fn token_is_the_basic_password_whatever_the_username() {
        for user in ["oidc", "actions", "x"] {
            assert_eq!(token(Some(&basic(user, "a.b.c"))), Ok("a.b.c".to_string()));
        }
    }

    #[test]
    fn token_rejects_missing_or_malformed_header() {
        for header in [None, Some("Bearer abc"), Some(basic("oidc", "").as_str())] {
            assert!(
                matches!(token(header), Err(AuthError::Unauthorized(_))),
                "{header:?}"
            );
        }
    }

    #[test]
    fn identity_is_logged_with_its_issuer() {
        let identity = Identity {
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            subject: "repo:example-org/app:ref:refs/heads/main".to_string(),
            claims: 0,
        };
        assert_eq!(
            identity.to_string(),
            "repo:example-org/app:ref:refs/heads/main from https://token.actions.githubusercontent.com (claims[0])"
        );
    }
}
