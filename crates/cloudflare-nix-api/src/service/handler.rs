//! The Nix binary cache protocol: every operation of the SDK's
//! `CacheServiceApi`, in [`CacheServiceHandler`], over the bucket and signing
//! key in the Worker's [`Config`].
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

use cloudflare_nix_sdk::v1::{
    self, CacheServiceApi, ErrorCode, NarInfo, NarInfoContext, NarInfoSigKey, Validate, append_sig,
};
use worker::{Error, console_error, send::SendFuture};

use super::config::{Config, SECRET_KEY};

/// The Nix binary cache protocol, over the R2 bucket. Narinfo and NARs are
/// stored as `<hash>.narinfo` and `<hash>.nar`, and served as stored.
#[derive(Clone)]
pub struct CacheServiceHandler {
    config: Arc<Config>,
}

impl CacheServiceHandler {
    /// A handler over the Worker's configuration, shared with the auth layer.
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl CacheServiceApi for CacheServiceHandler {
    /// `GET /nix-cache-info`: the store directory, priority and mass-query
    /// support, in the format Nix reads, and a `PublicKey:` line with
    /// `CLOUDFLARE_NIX_API_SECRET`'s public half when one is set. Nix ignores that
    /// line: clients add the key to `trusted-public-keys` themselves.
    async fn get_nix_cache_info(&self) -> v1::GetNixCacheInfoResponse {
        SendFuture::new(async move {
            let mut data = "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n".to_string();
            // Nix reads this before every substitution, so a key that can't
            // be read leaves the line out rather than failing the cache.
            let public_key = match self.config.signing_key().await {
                Ok(Some(secret)) => NarInfoSigKey::parse(&secret).and_then(|key| key.public_key()),
                Ok(None) => return v1::GetNixCacheInfoResponse::Ok(data),
                Err(err) => Err(err.to_string()),
            };
            match public_key {
                Ok(public_key) => writeln!(data, "PublicKey: {public_key}").unwrap(),
                Err(err) => console_error!("reading {SECRET_KEY}'s public key failed: {err}"),
            }
            v1::GetNixCacheInfoResponse::Ok(data)
        })
        .await
    }

    /// `POST /`: takes a newline-separated list of store path hashes and
    /// returns the ones the cache has, one per line, so a client can check
    /// many at once instead of a `HEAD` each.
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

    /// `HEAD /{hash}.narinfo`: whether the cache has a store path's narinfo,
    /// so an uploader can skip it.
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

    /// `GET /{hash}.narinfo`: the narinfo of the store path whose hash part
    /// is `hash`, as it was uploaded, with a `Sig:` line if the Worker signed
    /// it.
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

    /// `PUT /{hash}.narinfo`: stores a narinfo as sent, once it parses and
    /// validates and its `StorePath` matches `hash`. One without a `Sig:` is
    /// signed with `CLOUDFLARE_NIX_API_SECRET`, and refused when no key is set.
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
            // provide one, sign with CLOUDFLARE_NIX_API_SECRET; if neither path
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
                let secret = match self.config.signing_key().await {
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

    /// `HEAD /nar/{hash}.nar`: whether the cache has a NAR, so an uploader
    /// can skip it.
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

    /// `GET /nar/{hash}.nar`: the NAR a narinfo's `URL` points at, `hash`
    /// being its file hash.
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

    /// `PUT /nar/{hash}.nar`: stores a NAR as sent. Compressed NARs aren't
    /// supported: the narinfo that points at one is refused, since its
    /// `Compression` must be `none`.
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
