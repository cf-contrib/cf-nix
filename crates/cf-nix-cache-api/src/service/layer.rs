//! Upload auth, as a tower layer: every `PUT` needs an OIDC token from a
//! provider `CF_NIX_CACHE_API_OIDC_PROVIDERS` names, as the password of HTTP
//! Basic credentials, since a netrc file is the only place Nix sends them from.
//! The username isn't read.
//!
//! [`AuthorizeLayer`] is layered over the API's routes in the crate root. It
//! runs before the request reaches its handler, and so before the body is
//! read: an upload without credentials is refused without buffering it. Reads
//! pass straight through.
//!
//! OIDC auth, for any issuer: GitHub Actions, Cloudflare Access, GitLab, or
//! a cf-oidc-exchange broker. cf-oidc-core verifies the token against the
//! provider its `iss` names, as RFC 7519 and RFC 8725 say, and then the
//! token is accepted if any of that provider's claim sets matches. This layer
//! is what's left: finding the token, and answering for it.

use std::{
    convert::Infallible,
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    extract::Request,
    http::{HeaderMap, Method, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use cf_nix_cache_sdk::v1::{self, ErrorCode};
use cf_oidc_core::Provider;
use http_auth_basic::Credentials;
use http_body_util::BodyExt;
use tower_layer::Layer;
use tower_service::Service;
use worker::{console_error, console_log, send::SendFuture};

use super::config::{Config, PROVIDERS_KEY};

/// Authorizes every `PUT` before the routes it's layered over, against the
/// providers in the Worker's configuration. Every other method passes through.
#[derive(Clone)]
pub struct AuthorizeLayer {
    config: Arc<Config>,
}

impl AuthorizeLayer {
    /// A layer that takes the providers from `config`.
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for AuthorizeLayer {
    type Service = Authorize<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Authorize {
            inner,
            config: self.config.clone(),
        }
    }
}

/// [`AuthorizeLayer`]'s service: authorizes an upload, logs the identity it
/// resolved to (the token's subject and issuer, and the claim set that let it
/// in), then hands the request to the service it wraps.
#[derive(Clone)]
pub struct Authorize<S> {
    inner: S,
    config: Arc<Config>,
}

impl<S> Authorize<S> {
    /// Who may upload, from a request's headers: the identity its token
    /// resolves to, if one of the providers issued it and one of its claim
    /// sets lets it in.
    ///
    /// # Errors
    ///
    /// Why it may not: uploads are off (no providers), there's no token, or
    /// cf-oidc-core refused it.
    pub async fn authorize(&self, headers: &HeaderMap) -> Result<Identity, v1::Error> {
        let providers = self.config.providers();
        if providers.is_empty() {
            return Err(v1::Error::new(
                ErrorCode::Unauthorized,
                format!("uploads are off: {PROVIDERS_KEY} is not set"),
            ));
        }

        let header = headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok());
        let token = basic_password(header)?;

        let (provider, jwt) = providers.verify(&token).await.map_err(api_error)?;
        let claims = provider.claims.authorize(&jwt.claims).map_err(api_error)?;
        Ok(Identity {
            issuer: provider.issuer().to_string(),
            subject: jwt.claims.sub().unwrap_or_default().to_string(),
            claims,
        })
    }
}

impl<S> Service<Request> for Authorize<S>
where
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        // The service polled ready is the one to call: a clone takes its
        // place for the next request.
        let clone = self.clone();
        let mut this = std::mem::replace(self, clone);

        Box::pin(async move {
            if req.method() != Method::PUT {
                return this.inner.call(req).await;
            }

            // Verifying fetches the issuer's keys, and fetch futures aren't
            // `Send`, which the router wants; a Worker is single-threaded, so
            // it runs in a `SendFuture`.
            match SendFuture::new(this.authorize(req.headers())).await {
                Ok(identity) => {
                    console_log!("PUT {} by {identity}", req.uri().path());
                    this.inner.call(req).await
                }
                Err(err) => Ok(reject(req, err).await),
            }
        })
    }
}

/// The password of an `Authorization: Basic` header: where Nix sends the
/// token from, since a netrc file is the only place it reads credentials.
/// The username isn't read.
fn basic_password(header: Option<&str>) -> Result<String, v1::Error> {
    let unauthorized = |message: &str| v1::Error::new(ErrorCode::Unauthorized, message);
    let Some(header) = header else {
        return Err(unauthorized("missing credentials"));
    };
    match Credentials::from_header(header.to_string()) {
        Ok(credentials) if !credentials.password.is_empty() => Ok(credentials.password),
        _ => Err(unauthorized(
            "invalid credentials: send HTTP Basic auth with the token as the password",
        )),
    }
}

/// What cf-oidc-core refused, as the API's error: an invalid token is the
/// uploader's to fix (`unauthorized`), one no claim set allows isn't theirs
/// to have (`forbidden`), and an issuer that can't be reached isn't their
/// fault (`upstream_error`).
fn api_error(err: cf_oidc_core::Error) -> v1::Error {
    match err {
        cf_oidc_core::Error::InvalidToken(message) => {
            v1::Error::new(ErrorCode::Unauthorized, message)
        }
        // Which claims would have matched isn't said: that's the policy, not
        // the caller's to probe.
        cf_oidc_core::Error::InsufficientScope { issuer, subject } => v1::Error::new(
            ErrorCode::Forbidden,
            format!(
                "{}: no claim set for {issuer} matched",
                subject.unwrap_or_default()
            ),
        ),
        cf_oidc_core::Error::TemporarilyUnavailable(message) => {
            v1::Error::new(ErrorCode::UpstreamError, message)
        }
    }
}

/// Rejects an upload with `err`, after reading its body a chunk at a time and
/// keeping none. An uploader that sent `Expect: 100-continue`, as Nix's
/// libcurl does for a large one, otherwise waits for the body to be read, and
/// the upload hangs instead of failing.
///
/// An issuer that couldn't be reached isn't the uploader's to know about: what
/// went wrong is logged, and the response only says it was the issuer.
async fn reject(req: Request, mut err: v1::Error) -> Response {
    if err.error == ErrorCode::UpstreamError {
        console_error!("auth upstream failure: {}", err.message);
        err.message = "the token's issuer couldn't be reached".to_string();
    }
    let mut body = req.into_body();
    while let Some(Ok(_)) = body.frame().await {}
    err.into_response()
}

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

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::*;

    fn basic(user: &str, password: &str) -> String {
        Credentials::new(user, password).as_http_header()
    }

    /// An error's code and message: the generated error isn't `PartialEq`.
    fn said(err: v1::Error) -> (ErrorCode, String) {
        (err.error, err.message)
    }

    #[test]
    fn the_token_is_the_basic_password_whatever_the_username() {
        for user in ["oidc", "actions", "x"] {
            let password = basic_password(Some(&basic(user, "a.b.c"))).map_err(said);
            assert_eq!(password, Ok("a.b.c".to_string()));
        }
    }

    #[test]
    fn a_missing_or_malformed_header_is_unauthorized() {
        for header in [None, Some("Bearer abc"), Some(basic("oidc", "").as_str())] {
            let err = basic_password(header).unwrap_err();
            assert_eq!(err.error, ErrorCode::Unauthorized, "{header:?}");
        }
    }

    #[test]
    fn errors_answer_with_their_codes_status() {
        let unauthorized = v1::Error::new(ErrorCode::Unauthorized, "missing credentials");
        assert_eq!(
            unauthorized.into_response().status(),
            StatusCode::UNAUTHORIZED
        );
        let forbidden = v1::Error::new(ErrorCode::Forbidden, "no claim set matched");
        assert_eq!(forbidden.into_response().status(), StatusCode::FORBIDDEN);
        let upstream = v1::Error::new(ErrorCode::UpstreamError, "fetching keys returned 500");
        assert_eq!(upstream.into_response().status(), StatusCode::BAD_GATEWAY);
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

    #[test]
    fn core_errors_keep_their_meaning() {
        let cases = [
            (
                cf_oidc_core::Error::InvalidToken("token expired".into()),
                ErrorCode::Unauthorized,
                "token expired",
            ),
            (
                cf_oidc_core::Error::InsufficientScope {
                    issuer: "https://issuer.example.com".into(),
                    subject: Some("repo:example-org/app:ref:refs/heads/main".into()),
                },
                ErrorCode::Forbidden,
                "repo:example-org/app:ref:refs/heads/main: no claim set for https://issuer.example.com matched",
            ),
            (
                cf_oidc_core::Error::TemporarilyUnavailable("fetching keys returned 500".into()),
                ErrorCode::UpstreamError,
                "fetching keys returned 500",
            ),
        ];
        for (err, code, message) in cases {
            assert_eq!(said(api_error(err)), (code, message.to_string()));
        }
    }
}
