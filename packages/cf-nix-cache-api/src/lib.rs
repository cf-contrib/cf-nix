use std::fmt::Write;

mod auth;
mod model;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response as HttpResponse},
};
use cf_nix_cache_sdk::v1::{self, ErrorCode};
use model::{NarInfo, NarInfoContext, NarInfoSigKey, Validate, append_sig};
use tower_service::Service;
use worker::{send::SendFuture, *};

/// The R2 bucket every narinfo and NAR is stored in.
const BUCKET: &str = "CF_NIX_WORKER_BUCKET";

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, _ctx: Context) -> Result<HttpResponse> {
    // The router checks each request against the spec before it reaches a
    // handler. Reads are public; every upload resolves to an identity in its
    // handler, from the Authorization header the spec hands it.
    let cache = Cache { env: env.clone() };
    let mut router = v1::build_router(cache.clone(), cache)
        // Not in the spec: it's for whoever deploys the Worker, not its clients.
        .route(
            "/healthz",
            axum::routing::get(move || SendFuture::new(get_healthz(env))),
        );
    Ok(router.call(req).await?)
}

/// The Worker's implementation of the API, over its bindings.
///
/// R2 and fetch futures aren't `Send`, which the generated traits require.
/// A Worker is single-threaded, so each operation runs in a `SendFuture`.
#[derive(Clone)]
struct Cache {
    env: Env,
}

#[async_trait::async_trait]
impl v1::AuthApi for Cache {
    async fn get_whoami(&self, authorization: Option<String>) -> v1::GetWhoamiResponse {
        SendFuture::new(get_whoami(&self.env, authorization)).await
    }
}

#[async_trait::async_trait]
impl v1::CacheApi for Cache {
    async fn get_nix_cache_info(&self) -> v1::GetNixCacheInfoResponse {
        get_nix_cache_info()
    }

    async fn post_mass_query(&self, body: String) -> v1::PostMassQueryResponse {
        SendFuture::new(post_mass_query(&self.env, body)).await
    }

    async fn head_nar_info(&self, hash: String) -> v1::HeadNarInfoResponse {
        SendFuture::new(head_nar_info(&self.env, hash)).await
    }

    async fn get_nar_info(&self, hash: String) -> v1::GetNarInfoResponse {
        SendFuture::new(get_nar_info(&self.env, hash)).await
    }

    async fn put_nar_info(
        &self,
        hash: String,
        authorization: Option<String>,
        body: String,
    ) -> v1::PutNarInfoResponse {
        SendFuture::new(put_nar_info(&self.env, hash, authorization, body)).await
    }

    async fn head_nar(&self, hash: String) -> v1::HeadNarResponse {
        SendFuture::new(head_nar(&self.env, hash)).await
    }

    async fn get_nar(&self, hash: String) -> v1::GetNarResponse {
        SendFuture::new(get_nar(&self.env, hash)).await
    }

    async fn put_nar(
        &self,
        hash: String,
        authorization: Option<String>,
        body: bytes::Bytes,
    ) -> v1::PutNarResponse {
        SendFuture::new(put_nar(&self.env, hash, authorization, body)).await
    }
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

fn not_found() -> v1::Error {
    error(ErrorCode::NotFound, "object not found")
}

/// Logs a failed bucket operation and returns the error the caller sees,
/// which doesn't repeat the details.
fn bucket_error(err: worker::Error) -> v1::Error {
    console_error!("bucket operation failed: {err}");
    error(
        ErrorCode::InternalError,
        "the bucket couldn't be read or written",
    )
}

/// GET /v1/whoami
///
/// Resolves the request's credentials the same way as an upload and returns
/// the identity, so clients can check their setup before a `nix copy`.
async fn get_whoami(env: &Env, authorization: Option<String>) -> v1::GetWhoamiResponse {
    match auth::authorize(authorization.as_deref(), env).await {
        Ok(identity) => v1::GetWhoamiResponse::Ok(identity.into()),
        Err(err) => err.into(),
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
        Ok(Some(secret)) => NarInfoSigKey::parse(&secret).map(|_| ()),
        Ok(None) => Ok(()),
        Err(err) => Err(format!("reading CF_NIX_WORKER_SECRET failed: {err}")),
    }
}

/// GET /nix-cache-info
///
/// Returns the cache configuration in the format expected by the Nix client.
fn get_nix_cache_info() -> v1::GetNixCacheInfoResponse {
    v1::GetNixCacheInfoResponse::Ok(
        "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n".to_string(),
    )
}

/// POST /
///
/// Mass query endpoint. Accepts a newline-separated list of store
/// path hashes in the request body and returns the subset that are
/// present in the cache. This allows Nix to batch-check availability
/// instead of issuing individual GET requests per package.
async fn post_mass_query(env: &Env, body: String) -> v1::PostMassQueryResponse {
    match mass_query(env, &body).await {
        Ok(data) => v1::PostMassQueryResponse::Ok(data),
        Err(err) => v1::PostMassQueryResponse::InternalServerError(bucket_error(err)),
    }
}

async fn mass_query(env: &Env, body: &str) -> Result<String> {
    let bucket = env.bucket(BUCKET)?;
    let mut data = String::new();
    for hash in body.lines() {
        let key = if hash.ends_with(".narinfo") {
            hash.to_string()
        } else {
            format!("{hash}.narinfo")
        };

        if bucket.head(key).await?.is_some() {
            writeln!(data, "{hash}").unwrap();
        }
    }
    Ok(data)
}

/// HEAD /:hash.narinfo — used by Nix uploaders to skip already-cached paths.
async fn head_nar_info(env: &Env, hash: String) -> v1::HeadNarInfoResponse {
    match exists(env, format!("{hash}.narinfo")).await {
        Some(true) => v1::HeadNarInfoResponse::Ok,
        Some(false) => v1::HeadNarInfoResponse::NotFound,
        None => v1::HeadNarInfoResponse::InternalServerError,
    }
}

/// GET /:hash.narinfo
///
/// Retrieves a cached `.narinfo` metadata file for the store path
/// identified by `:hash`. The narinfo contains references, nar hash,
/// file size, and other metadata required by Nix to perform
/// substitution of the corresponding store path.
async fn get_nar_info(env: &Env, hash: String) -> v1::GetNarInfoResponse {
    // Served as stored: the text Nix uploaded, plus a Sig: line if the Worker
    // signed it.
    let text = read(env, format!("{hash}.narinfo")).await.and_then(|data| {
        data.map(String::from_utf8)
            .transpose()
            .map_err(|err| Error::RustError(format!("narinfo isn't UTF-8: {err}")))
    });
    let mut data = match text {
        Ok(Some(data)) => data,
        Ok(None) => return v1::GetNarInfoResponse::NotFound(not_found()),
        Err(err) => return v1::GetNarInfoResponse::InternalServerError(bucket_error(err)),
    };
    // Nix needs a newline after the last line. Objects stored before the
    // Worker kept uploads as-is (<= 0.3) don't end with one.
    if !data.ends_with('\n') {
        writeln!(data).unwrap();
    }
    v1::GetNarInfoResponse::Ok(data)
}

/// PUT /:hash.narinfo
///
/// Uploads a `.narinfo` metadata file for the store path identified
/// by `:hash` into the cache. The request body should contain the
/// narinfo contents. This allows for populating the cache with build
/// results from external sources.
async fn put_nar_info(
    env: &Env,
    hash: String,
    authorization: Option<String>,
    body: String,
) -> v1::PutNarInfoResponse {
    match auth::authorize(authorization.as_deref(), env).await {
        Ok(identity) => console_log!("PUT /{hash}.narinfo by {identity}"),
        Err(err) => return err.into(),
    }

    let bad_request =
        |msg: String| v1::PutNarInfoResponse::BadRequest(error(ErrorCode::BadRequest, msg));
    let info = match NarInfo::parse(&body) {
        Ok(info) => info,
        Err(msg) => return bad_request(msg),
    };
    let info_ctx = NarInfoContext { hash: hash.clone() };
    if let Err(msg) = info.validate(&info_ctx) {
        return bad_request(msg);
    }

    // Stored narinfo must always carry a Sig:. If the uploader didn't provide
    // one, sign with CF_NIX_WORKER_SECRET; if neither path produces a signature, reject.
    // The text is stored as Nix sent it, so no field is dropped or reordered.
    let signing_failure = || {
        v1::PutNarInfoResponse::InternalServerError(error(
            ErrorCode::Misconfigured,
            "server signing failure",
        ))
    };
    let data = if !info.sigs.is_empty() {
        body
    } else {
        let secret = match signing_secret(env).await {
            Ok(Some(secret)) => secret,
            Ok(None) => {
                return bad_request(
                    "narinfo must be signed: no Sig: provided and CF_NIX_WORKER_SECRET is not configured"
                        .to_string(),
                );
            }
            Err(err) => {
                console_error!("reading CF_NIX_WORKER_SECRET failed: {err}");
                return signing_failure();
            }
        };
        match NarInfoSigKey::parse(&secret).and_then(|key| key.sign(&info)) {
            Ok(sig) => append_sig(&body, &sig),
            Err(err) => {
                console_error!("narinfo signing failed: {err}");
                return signing_failure();
            }
        }
    };

    match write(env, format!("{hash}.narinfo"), data).await {
        Ok(()) => v1::PutNarInfoResponse::Ok,
        Err(err) => v1::PutNarInfoResponse::InternalServerError(bucket_error(err)),
    }
}

/// Reads the narinfo signing key, `CF_NIX_WORKER_SECRET`.
///
/// Deployments bind it from Secrets Store, so the key never passes through
/// Terraform. `wrangler dev` and plain `secret_text` bindings are read as a var.
async fn signing_secret(env: &Env) -> Result<Option<String>> {
    if let Ok(store) = env.secret_store("CF_NIX_WORKER_SECRET") {
        return store.get().await;
    }
    Ok(env
        .var("CF_NIX_WORKER_SECRET")
        .ok()
        .map(|secret| secret.to_string()))
}

/// HEAD /nar/:hash.nar — used by Nix uploaders to skip already-cached NARs.
async fn head_nar(env: &Env, hash: String) -> v1::HeadNarResponse {
    match exists(env, format!("{hash}.nar")).await {
        Some(true) => v1::HeadNarResponse::Ok,
        Some(false) => v1::HeadNarResponse::NotFound,
        None => v1::HeadNarResponse::InternalServerError,
    }
}

/// GET /nar/:hash.nar
///
/// Serves the actual NAR archive (the binary payload) for the store
/// path identified by `:hash`, fetched by Nix after reading the
/// corresponding `.narinfo` metadata.
async fn get_nar(env: &Env, hash: String) -> v1::GetNarResponse {
    match read(env, format!("{hash}.nar")).await {
        Ok(Some(data)) => v1::GetNarResponse::Ok(data.into()),
        Ok(None) => v1::GetNarResponse::NotFound(not_found()),
        Err(err) => v1::GetNarResponse::InternalServerError(bucket_error(err)),
    }
}

/// PUT /nar/:hash.nar
///
/// Uploads a NAR archive for the store path identified by `:hash`.
/// Uploaded alongside the corresponding `.narinfo` to fully populate
/// a store path in the cache.
async fn put_nar(
    env: &Env,
    hash: String,
    authorization: Option<String>,
    body: bytes::Bytes,
) -> v1::PutNarResponse {
    match auth::authorize(authorization.as_deref(), env).await {
        Ok(identity) => console_log!("PUT /nar/{hash}.nar by {identity}"),
        Err(err) => return err.into(),
    }

    match write(env, format!("{hash}.nar"), body.to_vec()).await {
        Ok(()) => v1::PutNarResponse::Ok,
        Err(err) => v1::PutNarResponse::InternalServerError(bucket_error(err)),
    }
}

/// Whether `key` is in the bucket, or `None` if the bucket couldn't be read,
/// which is logged.
async fn exists(env: &Env, key: String) -> Option<bool> {
    let head = async { env.bucket(BUCKET)?.head(key).await };
    match head.await {
        Ok(object) => Some(object.is_some()),
        Err(err) => {
            bucket_error(err);
            None
        }
    }
}

/// The contents of `key`, or `None` if it isn't in the bucket.
async fn read(env: &Env, key: String) -> Result<Option<Vec<u8>>> {
    let Some(object) = env.bucket(BUCKET)?.get(key).execute().await? else {
        return Ok(None);
    };
    let Some(body) = object.body() else {
        return Err(Error::RustError("object has no body".to_string()));
    };
    Ok(Some(body.bytes().await?))
}

async fn write(env: &Env, key: String, data: impl Into<Data>) -> Result<()> {
    env.bucket(BUCKET)?.put(key, data).execute().await?;
    Ok(())
}
