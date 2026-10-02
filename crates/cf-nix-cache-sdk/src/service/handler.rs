//! The health endpoints a server of the API answers beside it, and a client
//! for them. Hand-written, not generated: they're plain HTTP, not part of the
//! API's OpenAPI document.

/// The liveness endpoint: the server is up and serving HTTP. Shared by the
/// server that answers it and the [`HealthClient`] that asks, so the two can't
/// drift apart.
pub const HEALTH_LIVE_PATH: &str = "/health/live";

/// The readiness endpoint: the server can serve. Shared as
/// [`HEALTH_LIVE_PATH`] is.
pub const HEALTH_READY_PATH: &str = "/health/ready";

#[cfg(feature = "client")]
pub use client::HealthClient;
#[cfg(feature = "server")]
pub use server::{HealthCheck, HealthCheckError, HealthHandler};

#[cfg(feature = "client")]
mod client {
    use super::{HEALTH_LIVE_PATH, HEALTH_READY_PATH};

    /// Checks a server's health endpoints, [`HEALTH_LIVE_PATH`] and
    /// [`HEALTH_READY_PATH`].
    #[derive(Clone)]
    pub struct HealthClient {
        base_url: String,
        http: reqwest::Client,
    }

    impl HealthClient {
        /// A client for the server at `base_url`, e.g.
        /// `https://cf-nix-cache.example.workers.dev`.
        pub fn new(base_url: impl Into<String>) -> Self {
            Self {
                base_url: base_url.into(),
                http: reqwest::Client::new(),
            }
        }

        /// Whether the server is up: `GET /health/live` answered 2xx.
        pub async fn is_live(&self) -> Result<bool, reqwest::Error> {
            self.check(HEALTH_LIVE_PATH).await
        }

        /// Whether the server can serve: `GET /health/ready` answered 2xx.
        pub async fn is_ready(&self) -> Result<bool, reqwest::Error> {
            self.check(HEALTH_READY_PATH).await
        }

        async fn check(&self, path: &str) -> Result<bool, reqwest::Error> {
            let url = format!("{}{path}", self.base_url.trim_end_matches('/'));
            Ok(self.http.get(url).send().await?.status().is_success())
        }
    }
}

#[cfg(feature = "server")]
mod server {
    use std::{future::Future, pin::Pin, sync::Arc};

    use axum::{http::StatusCode, routing::get};

    use super::{HEALTH_LIVE_PATH, HEALTH_READY_PATH};

    /// What a failed [`HealthCheck::check`] carries: why.
    pub type HealthCheckError = Box<dyn std::error::Error + Send + Sync>;

    /// A check of something the server depends on, for readiness to ask.
    /// `/health/ready` asks every one given to [`HealthHandler::readiness`].
    pub trait HealthCheck: Send + Sync + 'static {
        /// `Ok` when what it checks is healthy; the error says why not.
        fn check(&self) -> impl Future<Output = Result<(), HealthCheckError>> + Send;
    }

    /// [`HealthCheck`] with its future boxed, which is what lets a
    /// [`HealthHandler`] hold checks of any type without being generic over
    /// them, while an implementor still writes a plain `async fn check`.
    trait DynHealthCheck: Send + Sync {
        fn check(&self) -> Pin<Box<dyn Future<Output = Result<(), HealthCheckError>> + Send + '_>>;
    }

    impl<R: HealthCheck> DynHealthCheck for R {
        fn check(&self) -> Pin<Box<dyn Future<Output = Result<(), HealthCheckError>> + Send + '_>> {
            Box::pin(HealthCheck::check(self))
        }
    }

    /// Answers the health endpoints, [`HEALTH_LIVE_PATH`] and
    /// [`HEALTH_READY_PATH`].
    ///
    /// Liveness says the server is up and serving HTTP, and never asks
    /// anything. Readiness asks every check given with
    /// [`readiness`](Self::readiness), and is ready only while all of them
    /// pass: with none, whenever it is live.
    #[derive(Clone, Default)]
    pub struct HealthHandler {
        checks: Vec<Arc<dyn DynHealthCheck>>,
    }

    impl HealthHandler {
        /// A [`HealthHandler`] with no readiness checks yet.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Ask `check` too before answering ready: one per thing the server
        /// can't serve without.
        #[must_use]
        pub fn readiness(mut self, check: impl HealthCheck) -> Self {
            self.checks.push(Arc::new(check));
            self
        }

        /// Both endpoints, as a router to merge beside the API's.
        pub fn into_router(self) -> axum::Router {
            axum::Router::new()
                .route(HEALTH_LIVE_PATH, get(Self::live))
                .route(
                    HEALTH_READY_PATH,
                    get(move || async move { self.ready().await }),
                )
        }

        /// Liveness: serving HTTP at all is the whole of it.
        pub async fn live() -> StatusCode {
            StatusCode::OK
        }

        /// Readiness: 200 when every check passes, 503 otherwise. The caller
        /// sees only the code. Unlike a server with a runtime to time out
        /// on, this waits for the checks however long they take.
        pub async fn ready(&self) -> StatusCode {
            for check in &self.checks {
                if check.check().await.is_err() {
                    return StatusCode::SERVICE_UNAVAILABLE;
                }
            }
            StatusCode::OK
        }
    }
}
