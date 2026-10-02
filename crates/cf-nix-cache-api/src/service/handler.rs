//! Handler implementations for the generated API traits.
//!
//! Every operation of the Nix binary cache protocol is implemented, in
//! [`CacheServiceHandler`].
//!
//! # Send
//!
//! The generated traits want `Send` futures, so axum can serve them on any
//! thread. R2 and fetch futures aren't `Send`: they hold JavaScript values. A
//! Worker is single-threaded, so each method runs its body in a `SendFuture`,
//! which asserts it.
//!
//! # Errors
//!
//! Each method returns its operation's response enum, one variant per status
//! the spec declares, so a status the spec doesn't list can't be returned. A
//! failed bucket operation is logged, and the caller gets an `internal_error`
//! that doesn't repeat its details. An `AuthError` converts into the response
//! of every operation that authorizes; see `auth`.
//!
//! # Uploads
//!
//! The spec hands each upload its `Authorization` header, and the method
//! authorizes before anything else, logging the identity it resolved to: the
//! token's subject and issuer, and the claim set that let it in.

use std::fmt::Write;

use cf_nix_cache_sdk::v1::{
    self, CacheApi, ErrorCode, NarInfo, NarInfoContext, NarInfoSigKey, Validate, append_sig,
};
use worker::{Data, Env, Error, Result, console_error, console_log, send::SendFuture};

use crate::{BUCKET, auth, error, signing_secret};

/// The Nix binary cache protocol, over the R2 bucket.
#[derive(Clone)]
pub struct CacheServiceHandler {
    env: Env,
}

impl CacheServiceHandler {
    /// Creates a handler over the Worker's bindings.
    pub fn new(env: Env) -> Self {
        Self { env }
    }
}

#[async_trait::async_trait]
impl CacheApi for CacheServiceHandler {
    /// GET /nix-cache-info
    ///
    /// Returns the cache configuration in the format expected by the Nix client.
    async fn get_nix_cache_info(&self) -> v1::GetNixCacheInfoResponse {
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
    async fn post_mass_query(&self, body: String) -> v1::PostMassQueryResponse {
        SendFuture::new(async move {
            let found = async {
                let bucket = self.env.bucket(BUCKET)?;
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
            };

            match found.await {
                Ok(data) => v1::PostMassQueryResponse::Ok(data),
                Err(err) => v1::PostMassQueryResponse::InternalServerError(bucket_error(err)),
            }
        })
        .await
    }

    /// HEAD /:hash.narinfo — used by Nix uploaders to skip already-cached paths.
    async fn head_nar_info(&self, hash: String) -> v1::HeadNarInfoResponse {
        SendFuture::new(async move {
            match exists(&self.env, format!("{hash}.narinfo")).await {
                Some(true) => v1::HeadNarInfoResponse::Ok,
                Some(false) => v1::HeadNarInfoResponse::NotFound,
                None => v1::HeadNarInfoResponse::InternalServerError,
            }
        })
        .await
    }

    /// GET /:hash.narinfo
    ///
    /// Retrieves a cached `.narinfo` metadata file for the store path
    /// identified by `:hash`. The narinfo contains references, nar hash,
    /// file size, and other metadata required by Nix to perform
    /// substitution of the corresponding store path.
    async fn get_nar_info(&self, hash: String) -> v1::GetNarInfoResponse {
        SendFuture::new(async move {
            // Served as stored: the text Nix uploaded, plus a Sig: line if the
            // Worker signed it.
            let text = read(&self.env, format!("{hash}.narinfo"))
                .await
                .and_then(|data| {
                    data.map(String::from_utf8)
                        .transpose()
                        .map_err(|err| Error::RustError(format!("narinfo isn't UTF-8: {err}")))
                });
            let mut data = match text {
                Ok(Some(data)) => data,
                Ok(None) => return v1::GetNarInfoResponse::NotFound(not_found()),
                Err(err) => return v1::GetNarInfoResponse::InternalServerError(bucket_error(err)),
            };
            // Nix needs a newline after the last line. Objects stored before
            // the Worker kept uploads as-is (<= 0.3) don't end with one.
            if !data.ends_with('\n') {
                writeln!(data).unwrap();
            }
            v1::GetNarInfoResponse::Ok(data)
        })
        .await
    }

    /// PUT /:hash.narinfo
    ///
    /// Uploads a `.narinfo` metadata file for the store path identified
    /// by `:hash` into the cache. The request body should contain the
    /// narinfo contents. This allows for populating the cache with build
    /// results from external sources.
    async fn put_nar_info(
        &self,
        hash: String,
        authorization: Option<String>,
        body: String,
    ) -> v1::PutNarInfoResponse {
        SendFuture::new(async move {
            match auth::authorize(authorization.as_deref(), &self.env).await {
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

            // Stored narinfo must always carry a Sig:. If the uploader didn't
            // provide one, sign with CF_NIX_CACHE_API_SECRET; if neither path
            // produces a signature, reject. The text is stored as Nix sent it,
            // so no field is dropped or reordered.
            let signing_failure = || {
                v1::PutNarInfoResponse::InternalServerError(error(
                    ErrorCode::Misconfigured,
                    "server signing failure",
                ))
            };
            let data = if !info.sigs.is_empty() {
                body
            } else {
                let secret = match signing_secret(&self.env).await {
                    Ok(Some(secret)) => secret,
                    Ok(None) => {
                        return bad_request(
                            "narinfo must be signed: no Sig: provided and CF_NIX_CACHE_API_SECRET is not configured"
                                .to_string(),
                        );
                    }
                    Err(err) => {
                        console_error!("reading CF_NIX_CACHE_API_SECRET failed: {err}");
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

            match write(&self.env, format!("{hash}.narinfo"), data).await {
                Ok(()) => v1::PutNarInfoResponse::Ok,
                Err(err) => v1::PutNarInfoResponse::InternalServerError(bucket_error(err)),
            }
        })
        .await
    }

    /// HEAD /nar/:hash.nar — used by Nix uploaders to skip already-cached NARs.
    async fn head_nar(&self, hash: String) -> v1::HeadNarResponse {
        SendFuture::new(async move {
            match exists(&self.env, format!("{hash}.nar")).await {
                Some(true) => v1::HeadNarResponse::Ok,
                Some(false) => v1::HeadNarResponse::NotFound,
                None => v1::HeadNarResponse::InternalServerError,
            }
        })
        .await
    }

    /// GET /nar/:hash.nar
    ///
    /// Serves the actual NAR archive (the binary payload) for the store
    /// path identified by `:hash`, fetched by Nix after reading the
    /// corresponding `.narinfo` metadata.
    async fn get_nar(&self, hash: String) -> v1::GetNarResponse {
        SendFuture::new(async move {
            match read(&self.env, format!("{hash}.nar")).await {
                Ok(Some(data)) => v1::GetNarResponse::Ok(data.into()),
                Ok(None) => v1::GetNarResponse::NotFound(not_found()),
                Err(err) => v1::GetNarResponse::InternalServerError(bucket_error(err)),
            }
        })
        .await
    }

    /// PUT /nar/:hash.nar
    ///
    /// Uploads a NAR archive for the store path identified by `:hash`.
    /// Uploaded alongside the corresponding `.narinfo` to fully populate
    /// a store path in the cache.
    async fn put_nar(
        &self,
        hash: String,
        authorization: Option<String>,
        body: bytes::Bytes,
    ) -> v1::PutNarResponse {
        SendFuture::new(async move {
            match auth::authorize(authorization.as_deref(), &self.env).await {
                Ok(identity) => console_log!("PUT /nar/{hash}.nar by {identity}"),
                Err(err) => return err.into(),
            }

            match write(&self.env, format!("{hash}.nar"), body.to_vec()).await {
                Ok(()) => v1::PutNarResponse::Ok,
                Err(err) => v1::PutNarResponse::InternalServerError(bucket_error(err)),
            }
        })
        .await
    }
}

fn not_found() -> v1::Error {
    error(ErrorCode::NotFound, "object not found")
}

/// Logs a failed bucket operation and returns the error the caller sees,
/// which doesn't repeat the details.
fn bucket_error(err: Error) -> v1::Error {
    console_error!("bucket operation failed: {err}");
    error(
        ErrorCode::InternalError,
        "the bucket couldn't be read or written",
    )
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
