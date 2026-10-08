//! The Worker half of cloudflare-nix: a Nix binary cache on Cloudflare Workers
//! and R2.
//!
//! Each request reads the Worker's configuration from its bindings, then
//! serves the SDK's router over it: the cache protocol, with the auth layer
//! authorizing every upload before its handler, and the health endpoints
//! beside it, ready only while the signing key can be read. A configuration
//! that can't be read, an unbound bucket or an invalid provider list, fails
//! every request instead.

mod service;

use std::sync::Arc;

use axum::response::{IntoResponse, Response as HttpResponse};
use cloudflare_nix_sdk::v1::{self, ErrorCode};
use tower_service::Service;
use worker::*;

use crate::service::{
    config::Config, handler::CacheServiceHandler, health::ConfigCheck, layer::AuthorizeLayer,
};

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, _ctx: Context) -> Result<HttpResponse> {
    let mut router = match Config::from_env(&env) {
        // The router checks each request against the spec before it reaches
        // a handler. Reads are public; the auth layer authorizes every upload
        // first, before its body is read.
        Ok(config) => {
            let config = Arc::new(config);
            v1::cache_service_api_router(CacheServiceHandler::new(config.clone()))
                .layer(AuthorizeLayer::new(config.clone()))
                // Merged after the layer, so outside it. Not in the spec:
                // they're for whoever deploys the Worker, not its clients.
                // Ready only while the config checks out.
                .merge(
                    v1::HealthHandler::new()
                        .readiness(ConfigCheck::new(config))
                        .into_router(),
                )
        }
        // Misconfigured, the Worker serves nothing: every request, the health
        // endpoints' too, is refused, with why logged.
        Err(err) => {
            let msg = err.to_string();
            axum::Router::new().fallback(move || async move {
                console_error!("misconfigured: {msg}");
                v1::Error::new(ErrorCode::Misconfigured, "the cache is misconfigured")
                    .into_response()
            })
        }
    };
    Ok(router.call(req).await?)
}
