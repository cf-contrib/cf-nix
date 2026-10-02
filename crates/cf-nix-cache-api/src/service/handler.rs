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
//! failed bucket operation is an `internal_error` that doesn't say why.
//!
//! # Uploads
//!
//! No method authorizes: by the time an upload reaches one, the auth
//! [`layer`](super::layer) has.

use std::{fmt::Write, sync::Arc};

use cf_nix_cache_sdk::v1::{
    self, CacheServiceApi, ErrorCode, NarInfo, NarInfoContext, NarInfoSigKey, Validate, append_sig,
};
use worker::{Error, console_error, send::SendFuture};

use super::config::{Config, SECRET_KEY};

/// The Nix binary cache protocol, over the R2 bucket.
#[derive(Clone)]
pub struct CacheServiceHandler {
    config: Arc<Config>,
}

impl CacheServiceHandler {
    /// Creates a handler over the Worker's configuration.
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl CacheServiceApi for CacheServiceHandler {
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
                let bucket = self.config.bucket();
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
                Ok::<_, Error>(data)
            };

            match found.await {
                Ok(data) => v1::PostMassQueryResponse::Ok(data),
                Err(_) => v1::PostMassQueryResponse::InternalServerError(v1::Error::new(
                    ErrorCode::InternalError,
                    "the bucket couldn't be read or written",
                )),
            }
        })
        .await
    }

    /// HEAD /:hash.narinfo — used by Nix uploaders to skip already-cached paths.
    async fn head_nar_info(&self, hash: String) -> v1::HeadNarInfoResponse {
        SendFuture::new(async move {
            let head = async { self.config.bucket().head(format!("{hash}.narinfo")).await };
            match head.await {
                Ok(Some(_)) => v1::HeadNarInfoResponse::Ok,
                Ok(None) => v1::HeadNarInfoResponse::NotFound,
                Err(_) => v1::HeadNarInfoResponse::InternalServerError,
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
            let read = async {
                let bucket = self.config.bucket();
                let Some(object) = bucket.get(format!("{hash}.narinfo")).execute().await? else {
                    return Ok(None);
                };
                let Some(body) = object.body() else {
                    return Err(Error::RustError("object has no body".to_string()));
                };
                let text = String::from_utf8(body.bytes().await?)
                    .map_err(|err| Error::RustError(format!("narinfo isn't UTF-8: {err}")))?;
                Ok(Some(text))
            };
            let mut data = match read.await {
                Ok(Some(data)) => data,
                Ok(None) => {
                    return v1::GetNarInfoResponse::NotFound(v1::Error::new(
                        ErrorCode::NotFound,
                        "object not found",
                    ));
                }
                Err(_) => {
                    return v1::GetNarInfoResponse::InternalServerError(v1::Error::new(
                        ErrorCode::InternalError,
                        "the bucket couldn't be read or written",
                    ));
                }
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
    async fn put_nar_info(&self, hash: String, body: String) -> v1::PutNarInfoResponse {
        SendFuture::new(async move {
            let bad_request =
                |msg: String| v1::PutNarInfoResponse::BadRequest(v1::Error::new(ErrorCode::BadRequest, msg));
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
                v1::PutNarInfoResponse::InternalServerError(v1::Error::new(
                    ErrorCode::Misconfigured,
                    "server signing failure",
                ))
            };
            let data = if !info.sigs.is_empty() {
                body
            } else {
                let secret = match self.config.secret().await {
                    Ok(Some(secret)) => secret,
                    Ok(None) => {
                        return bad_request(
                            format!(
                                "narinfo must be signed: no Sig: provided and {SECRET_KEY} is not configured"
                            ),
                        );
                    }
                    Err(err) => {
                        console_error!("reading {SECRET_KEY} failed: {err}");
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

            let write = async {
                let bucket = self.config.bucket();
                bucket.put(format!("{hash}.narinfo"), data).execute().await
            };
            match write.await {
                Ok(_) => v1::PutNarInfoResponse::Ok,
                Err(_) => v1::PutNarInfoResponse::InternalServerError(v1::Error::new(ErrorCode::InternalError, "the bucket couldn't be read or written")),
            }
        })
        .await
    }

    /// HEAD /nar/:hash.nar — used by Nix uploaders to skip already-cached NARs.
    async fn head_nar(&self, hash: String) -> v1::HeadNarResponse {
        SendFuture::new(async move {
            let head = async { self.config.bucket().head(format!("{hash}.nar")).await };
            match head.await {
                Ok(Some(_)) => v1::HeadNarResponse::Ok,
                Ok(None) => v1::HeadNarResponse::NotFound,
                Err(_) => v1::HeadNarResponse::InternalServerError,
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
            let read = async {
                let bucket = self.config.bucket();
                let Some(object) = bucket.get(format!("{hash}.nar")).execute().await? else {
                    return Ok(None);
                };
                let Some(body) = object.body() else {
                    return Err(Error::RustError("object has no body".to_string()));
                };
                Ok(Some(body.bytes().await?))
            };
            match read.await {
                Ok(Some(data)) => v1::GetNarResponse::Ok(data.into()),
                Ok(None) => v1::GetNarResponse::NotFound(v1::Error::new(
                    ErrorCode::NotFound,
                    "object not found",
                )),
                Err(_) => v1::GetNarResponse::InternalServerError(v1::Error::new(
                    ErrorCode::InternalError,
                    "the bucket couldn't be read or written",
                )),
            }
        })
        .await
    }

    /// PUT /nar/:hash.nar
    ///
    /// Uploads a NAR archive for the store path identified by `:hash`.
    /// Uploaded alongside the corresponding `.narinfo` to fully populate
    /// a store path in the cache.
    async fn put_nar(&self, hash: String, body: bytes::Bytes) -> v1::PutNarResponse {
        SendFuture::new(async move {
            let write = async {
                let bucket = self.config.bucket();
                bucket
                    .put(format!("{hash}.nar"), body.to_vec())
                    .execute()
                    .await
            };
            match write.await {
                Ok(_) => v1::PutNarResponse::Ok,
                Err(_) => v1::PutNarResponse::InternalServerError(v1::Error::new(
                    ErrorCode::InternalError,
                    "the bucket couldn't be read or written",
                )),
            }
        })
        .await
    }
}
