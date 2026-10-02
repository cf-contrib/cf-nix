mod service;

use axum::response::Response as HttpResponse;
use cf_nix_cache_sdk::v1;
use tower_service::Service;
use worker::*;

use crate::service::{handler::CacheServiceHandler, layer::AuthorizeLayer};

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, _ctx: Context) -> Result<HttpResponse> {
    // The router checks each request against the spec before it reaches a
    // handler. Reads are public; the auth layer authorizes every upload first,
    // before its body is read.
    let mut router = v1::cache_service_api_router(CacheServiceHandler::new(env.clone()))
        .layer(AuthorizeLayer::new(env))
        // Merged after the layer, so outside it. Not in the spec: they're for
        // whoever deploys the Worker, not its clients.
        .merge(v1::HealthHandler::new().into_router());
    Ok(router.call(req).await?)
}
