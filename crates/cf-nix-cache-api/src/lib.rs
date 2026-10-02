mod auth;
mod service;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response as HttpResponse},
};
use cf_nix_cache_sdk::v1::{self, ErrorCode, NarInfoSigKey};
use tower_service::Service;
use worker::{send::SendFuture, *};

use crate::service::{AuthServiceHandler, CacheServiceHandler};

/// The R2 bucket every narinfo and NAR is stored in.
const BUCKET: &str = "CF_NIX_WORKER_BUCKET";

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, _ctx: Context) -> Result<HttpResponse> {
    // The router checks each request against the spec before it reaches a
    // handler. Reads are public; every upload resolves to an identity in its
    // handler, from the Authorization header the spec hands it.
    let mut router = v1::build_router(
        AuthServiceHandler::new(env.clone()),
        CacheServiceHandler::new(env.clone()),
    )
    // Not in the spec: it's for whoever deploys the Worker, not its clients.
    .route(
        "/healthz",
        axum::routing::get(move || SendFuture::new(get_healthz(env))),
    );
    Ok(router.call(req).await?)
}

/// An error in the shape shared with cf-oidc-auth:
/// `{ "error": "<code>", "message": "<reason>" }`. Nix prints the body of a
/// failed upload, so the message says what to fix.
pub(crate) fn error(code: ErrorCode, message: impl Into<String>) -> v1::Error {
    v1::Error {
        error: code,
        message: message.into(),
    }
}

/// GET /healthz
///
/// `200` when the bucket binding, the auth config and the signing key (if
/// bound) are valid, else `500`. Never shows the config: the reason is logged.
async fn get_healthz(env: Env) -> HttpResponse {
    match check_health(&env).await {
        Ok(()) => "ok".into_response(),
        Err(reason) => {
            console_error!("unhealthy: {reason}");
            let body = error(
                ErrorCode::Misconfigured,
                "the Worker's bindings or config are invalid; its logs have the reason",
            );
            (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
        }
    }
}

async fn check_health(env: &Env) -> std::result::Result<(), String> {
    env.bucket(BUCKET)
        .map_err(|_| format!("{BUCKET} is not bound"))?;
    auth::check_config(env)?;
    match signing_secret(env).await {
        Ok(Some(secret)) => NarInfoSigKey::parse(&secret)
            .map(|_| ())
            .map_err(|err| format!("CF_NIX_WORKER_SECRET: {err}")),
        Ok(None) => Ok(()),
        Err(err) => Err(format!("reading CF_NIX_WORKER_SECRET failed: {err}")),
    }
}

/// Reads the narinfo signing key, `CF_NIX_WORKER_SECRET`.
///
/// Deployments bind it from Secrets Store, so the key never passes through
/// Terraform. `wrangler dev` and plain `secret_text` bindings are read as a var.
pub(crate) async fn signing_secret(env: &Env) -> Result<Option<String>> {
    if let Ok(store) = env.secret_store("CF_NIX_WORKER_SECRET") {
        return store.get().await;
    }
    Ok(env
        .var("CF_NIX_WORKER_SECRET")
        .ok()
        .map(|secret| secret.to_string()))
}
