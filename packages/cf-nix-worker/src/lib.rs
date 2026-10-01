use std::fmt::Write;

mod auth;
mod model;

use model::{NarInfo, NarInfoContext, NarInfoSigKey, Validate, append_sig};
use worker::*;

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // Reads are public; every upload must resolve to an identity.
    if req.method() == Method::Put {
        match auth::authorize(&req, &env).await {
            Ok(identity) => console_log!("PUT {} by {identity}", req.path()),
            Err(err) => return err.into_response(),
        }
    }

    Router::new()
        .get("/nix-cache-info", get_nix_cache_info)
        .get_async("/healthz", get_healthz)
        .get_async("/v1/whoami", get_whoami)
        .post_async("/", post_mass_query)
        .head_async("/:hash", head_narinfo)
        .get_async("/:hash", get_narinfo)
        .put_async("/:hash", put_narinfo)
        .head_async("/nar/:hash", head_nar)
        .get_async("/nar/:hash", get_nar)
        .put_async("/nar/:hash", put_nar)
        .run(req, env)
        .await
}

/// An error response in the shape shared with cf-oidc-auth:
/// `{ "error": "<code>", "message": "<reason>" }`. Nix prints the body of a
/// failed upload, so the message says what to fix.
pub(crate) fn error_response(status: u16, code: &str, message: &str) -> Result<Response> {
    Ok(
        Response::from_json(&serde_json::json!({ "error": code, "message": message }))?
            .with_status(status),
    )
}

/// GET /v1/whoami
///
/// Resolves the request's credentials the same way as an upload and returns
/// the identity, so clients can check their setup before a `nix copy`.
async fn get_whoami(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    match auth::authorize(&req, &ctx.env).await {
        Ok(identity) => Response::from_json(&identity),
        Err(err) => err.into_response(),
    }
}

/// GET /healthz
///
/// `200` when the bucket binding, the auth config and the signing key (if
/// bound) are valid, else `500`. Never shows the config: the reason is logged.
async fn get_healthz(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    match check_health(&ctx.env).await {
        Ok(()) => Response::ok("ok"),
        Err(reason) => {
            console_error!("unhealthy: {reason}");
            error_response(
                500,
                "misconfigured",
                "the Worker's bindings or config are invalid; its logs have the reason",
            )
        }
    }
}

async fn check_health(env: &Env) -> std::result::Result<(), String> {
    env.bucket("CF_NIX_WORKER_BUCKET")
        .map_err(|_| "CF_NIX_WORKER_BUCKET is not bound".to_string())?;
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
fn get_nix_cache_info(_req: Request, _ctx: RouteContext<()>) -> Result<Response> {
    Response::ok("StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n")
}

/// POST /
///
/// Mass query endpoint. Accepts a newline-separated list of store
/// path hashes in the request body and returns the subset that are
/// present in the cache. This allows Nix to batch-check availability
/// instead of issuing individual GET requests per package.
async fn post_mass_query(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let body = req.text().await?;
    let mut data = String::new();
    let bucket = ctx.env.bucket("CF_NIX_WORKER_BUCKET")?;

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

    Response::ok(data)
}

/// HEAD /:hash.narinfo — used by Nix uploaders to skip already-cached paths.
async fn head_narinfo(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let Some(hash) = ctx.param("hash") else {
        return error_response(400, "bad_request", "missing hash");
    };
    let key = if hash.ends_with(".narinfo") {
        hash.to_string()
    } else {
        format!("{hash}.narinfo")
    };
    let bucket = ctx.env.bucket("CF_NIX_WORKER_BUCKET")?;
    if bucket.head(key).await?.is_some() {
        Response::empty()
    } else {
        error_response(404, "not_found", "object not found")
    }
}

/// GET /:hash.narinfo
///
/// Retrieves a cached `.narinfo` metadata file for the store path
/// identified by `:hash`. The narinfo contains references, nar hash,
/// file size, and other metadata required by Nix to perform
/// substitution of the corresponding store path.
async fn get_narinfo(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let Some(hash) = ctx.param("hash") else {
        return error_response(400, "bad_request", "missing hash");
    };

    let key = if hash.ends_with(".narinfo") {
        hash.to_string()
    } else {
        format!("{hash}.narinfo")
    };

    let bucket = ctx.env.bucket("CF_NIX_WORKER_BUCKET")?;
    let Some(object) = bucket.get(key).execute().await? else {
        return error_response(404, "not_found", "object not found");
    };

    let Some(body) = object.body() else {
        return error_response(500, "internal_error", "object has no body");
    };
    // Served as stored: the text Nix uploaded, plus a Sig: line if the Worker
    // signed it.
    let mut data = body.text().await?;
    // Nix needs a newline after the last line. Objects stored before the
    // Worker kept uploads as-is (<= 0.3) don't end with one.
    if !data.ends_with('\n') {
        writeln!(data).unwrap();
    }

    let mut response = Response::ok(data)?;
    response
        .headers_mut()
        .set("content-type", "text/x-nix-narinfo")?;
    Ok(response)
}

/// PUT /:hash.narinfo
///
/// Uploads a `.narinfo` metadata file for the store path identified
/// by `:hash` into the cache. The request body should contain the
/// narinfo contents. This allows for populating the cache with build
/// results from external sources.
async fn put_narinfo(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let Some(hash) = ctx.param("hash") else {
        return error_response(400, "bad_request", "missing hash");
    };

    let key = if hash.ends_with(".narinfo") {
        hash.to_string()
    } else {
        format!("{hash}.narinfo")
    };

    let body = req.text().await?;
    let info = match NarInfo::parse(&body) {
        Ok(info) => info,
        Err(msg) => return error_response(400, "bad_request", &msg),
    };
    let info_ctx = NarInfoContext {
        hash: hash.strip_suffix(".narinfo").unwrap_or(hash).to_string(),
    };
    if let Err(msg) = info.validate(&info_ctx) {
        return error_response(400, "bad_request", &msg);
    }

    // Stored narinfo must always carry a Sig:. If the uploader didn't provide
    // one, sign with CF_NIX_WORKER_SECRET; if neither path produces a signature, reject.
    // The text is stored as Nix sent it, so no field is dropped or reordered.
    let data = if !info.sigs.is_empty() {
        body
    } else {
        let secret = match signing_secret(&ctx.env).await {
            Ok(Some(secret)) => secret,
            Ok(None) => {
                return error_response(
                    400,
                    "bad_request",
                    "narinfo must be signed: no Sig: provided and CF_NIX_WORKER_SECRET is not configured",
                );
            }
            Err(err) => {
                console_error!("reading CF_NIX_WORKER_SECRET failed: {err}");
                return error_response(500, "misconfigured", "server signing failure");
            }
        };
        match NarInfoSigKey::parse(&secret).and_then(|key| key.sign(&info)) {
            Ok(sig) => append_sig(&body, &sig),
            Err(err) => {
                console_error!("narinfo signing failed: {err}");
                return error_response(500, "misconfigured", "server signing failure");
            }
        }
    };

    let bucket = ctx.env.bucket("CF_NIX_WORKER_BUCKET")?;
    bucket.put(key, data).execute().await?;

    Response::empty()
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
async fn head_nar(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let Some(hash) = ctx.param("hash") else {
        return error_response(400, "bad_request", "missing hash");
    };
    let key = if hash.ends_with(".nar") {
        hash.to_string()
    } else {
        format!("{hash}.nar")
    };
    let bucket = ctx.env.bucket("CF_NIX_WORKER_BUCKET")?;
    if bucket.head(key).await?.is_some() {
        Response::empty()
    } else {
        error_response(404, "not_found", "object not found")
    }
}

/// GET /nar/:hash.nar
///
/// Serves the actual NAR archive (the binary payload) for the store
/// path identified by `:hash`. The NAR is the compressed archive of
/// the store path contents, fetched by Nix after reading the
/// corresponding `.narinfo` metadata.
async fn get_nar(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let Some(hash) = ctx.param("hash") else {
        return error_response(400, "bad_request", "missing hash");
    };

    let key = if hash.ends_with(".nar") {
        hash.to_string()
    } else {
        format!("{hash}.nar")
    };

    let bucket = ctx.env.bucket("CF_NIX_WORKER_BUCKET")?;
    let Some(object) = bucket.get(key).execute().await? else {
        return error_response(404, "not_found", "object not found");
    };

    let Some(body) = object.body() else {
        return error_response(500, "internal_error", "object has no body");
    };

    let mut response = Response::from_body(body.response_body()?)?;
    response
        .headers_mut()
        .set("content-type", "application/x-nix-archive")?;
    Ok(response)
}

/// PUT /nar/:hash.nar
///
/// Uploads a NAR archive for the store path identified by `:hash`.
/// The request body should contain the compressed NAR binary.
/// Uploaded alongside the corresponding `.narinfo` to fully populate
/// a store path in the cache.
async fn put_nar(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let Some(hash) = ctx.param("hash") else {
        return error_response(400, "bad_request", "missing hash");
    };

    let key = if hash.ends_with(".nar") {
        hash.to_string()
    } else {
        format!("{hash}.nar")
    };

    let body = match req.inner().body() {
        Some(stream) => stream,
        None => return error_response(400, "bad_request", "missing body"),
    };
    let bucket = ctx.env.bucket("CF_NIX_WORKER_BUCKET")?;
    bucket.put(key, body).execute().await?;

    Response::empty()
}
