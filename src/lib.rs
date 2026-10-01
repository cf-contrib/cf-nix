use std::{borrow::Cow, fmt::Write};

mod auth;
mod github;
mod model;
mod oidc;

use model::{NarInfoContext, NarInfoSigKey, Validate};
use narinfo::*;
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
        .get_async("/auth/whoami", get_whoami)
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

/// GET /auth/whoami
///
/// Resolves the request's credentials the same way as an upload and returns
/// the identity, so clients can check their setup before a `nix copy`.
async fn get_whoami(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    match auth::authorize(&req, &ctx.env).await {
        Ok(identity) => Response::from_json(&identity),
        Err(err) => err.into_response(),
    }
}

/// GET /nix-cache-info
///
/// Returns the cache configuration in the format expected by the Nix client.
fn get_nix_cache_info(_req: Request, _ctx: RouteContext<()>) -> Result<Response> {
    let info = NixCacheInfo {
        store_dir: Cow::from("/nix/store"),
        wants_mass_query: true,
        priority: 40,
    };

    let mut data = String::new();
    info.serialize_into(&mut data).unwrap();
    Response::ok(data)
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
    let bucket = ctx.env.bucket("NIX_BUCKET")?;

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
        return Response::error("missing hash", 400);
    };
    let key = if hash.ends_with(".narinfo") {
        hash.to_string()
    } else {
        format!("{hash}.narinfo")
    };
    let bucket = ctx.env.bucket("NIX_BUCKET")?;
    if bucket.head(key).await?.is_some() {
        Response::empty()
    } else {
        Response::error("object not found", 404)
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
        return Response::error("missing hash", 400);
    };

    let key = if hash.ends_with(".narinfo") {
        hash.to_string()
    } else {
        format!("{hash}.narinfo")
    };

    let bucket = ctx.env.bucket("NIX_BUCKET")?;
    let Some(object) = bucket.get(key).execute().await? else {
        return Response::error("object not found", 404);
    };

    let Some(body) = object.body() else {
        return Response::error("object has no body", 500);
    };
    let body = body.text().await?;
    let info = match NarInfo::parse(&body) {
        Ok(info) => info,
        Err(err) => {
            console_error!("narinfo parse failed: {err:?}");
            return Response::error("object has an invalid body", 500);
        }
    };

    let mut data = String::new();
    info.serialize_into(&mut data).unwrap();
    // The library does not emit a newline which causes the nix client to fail
    writeln!(data).unwrap();

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
        return Response::error("missing hash", 400);
    };

    let key = if hash.ends_with(".narinfo") {
        hash.to_string()
    } else {
        format!("{hash}.narinfo")
    };

    let body = req.text().await?;
    let mut info = match NarInfo::parse(&body) {
        Ok(info) => info,
        Err(err) => {
            console_error!("narinfo parse failed: {err:?}");
            return Response::error("invalid body", 400);
        }
    };
    let info_ctx = NarInfoContext {
        hash: hash.strip_suffix(".narinfo").unwrap_or(hash).to_string(),
    };
    if let Err(msg) = info.validate(&info_ctx) {
        return Response::error(msg, 400);
    }

    // Stored narinfo must always carry a Sig:. If the uploader didn't provide
    // one, sign with NIX_SECRET; if neither path produces a signature, reject.
    if info.sigs.is_empty() {
        let Ok(secret) = ctx.env.var("NIX_SECRET") else {
            return Response::error(
                "narinfo must be signed: no Sig: provided and NIX_SECRET is not configured",
                400,
            );
        };
        match NarInfoSigKey::parse(&secret.to_string()).and_then(|key| key.sign(&info)) {
            Ok(sig) => info.sigs.push(sig),
            Err(err) => {
                console_error!("narinfo signing failed: {err}");
                return Response::error("server signing failure", 500);
            }
        }
    }

    let mut data = String::new();
    info.serialize_into(&mut data).unwrap();

    let bucket = ctx.env.bucket("NIX_BUCKET")?;
    bucket.put(key, data).execute().await?;

    Response::empty()
}

/// HEAD /nar/:hash.nar — used by Nix uploaders to skip already-cached NARs.
async fn head_nar(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let Some(hash) = ctx.param("hash") else {
        return Response::error("missing hash", 400);
    };
    let key = if hash.ends_with(".nar") {
        hash.to_string()
    } else {
        format!("{hash}.nar")
    };
    let bucket = ctx.env.bucket("NIX_BUCKET")?;
    if bucket.head(key).await?.is_some() {
        Response::empty()
    } else {
        Response::error("object not found", 404)
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
        return Response::error("missing hash", 400);
    };

    let key = if hash.ends_with(".nar") {
        hash.to_string()
    } else {
        format!("{hash}.nar")
    };

    let bucket = ctx.env.bucket("NIX_BUCKET")?;
    let Some(object) = bucket.get(key).execute().await? else {
        return Response::error("object not found", 404);
    };

    let Some(body) = object.body() else {
        return Response::error("object has no body", 500);
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
        return Response::error("missing hash", 400);
    };

    let key = if hash.ends_with(".nar") {
        hash.to_string()
    } else {
        format!("{hash}.nar")
    };

    let body = match req.inner().body() {
        Some(stream) => stream,
        None => return Response::error("missing body", 400),
    };
    let bucket = ctx.env.bucket("NIX_BUCKET")?;
    bucket.put(key, body).execute().await?;

    Response::empty()
}
