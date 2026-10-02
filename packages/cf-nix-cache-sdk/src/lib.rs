//! The Rust SDK for the cf-nix-cache HTTP API: its types, a client, and the
//! traits a server of it implements, generated from the OpenAPI document.
//!
//! Everything is under [`v1`]:
//!
//! ```
//! use cf_nix_cache_sdk::v1::*;
//! ```
//!
//! # What is in it
//!
//! - **Types**: [`v1::Identity`], what `GET /v1/whoami` returns, and
//!   [`v1::Error`], the body of every error.
//! - **Server** (`server` feature): a trait per tag, `CacheApi`, `AuthApi` and
//!   `HealthApi`, a response enum per operation, and `build_router`, an axum
//!   router over all three that checks requests against the spec before they
//!   reach a handler.
//! - **Client** (`client` feature): `HttpClient`, a method per operation.
//!
//! # Generated code
//!
//! `openapi/nix/cache/v1/cachev1.yaml` is the source. `build.rs` runs
//! [openapi-to-rust](https://github.com/gpu-cli/openapi-to-rust) over it into
//! `OUT_DIR`, so none of it is checked in or edited by hand.

/// Everything for `nix.cache.v1`: the types, and the server and client the
/// crate's features enable.
pub mod v1 {
    // The generated module root opens with `unused_imports`, which `include!`
    // can't take: build.rs strips it, and it's restated here. The clippy lints
    // are the generator's style, not ours to fix.
    #![allow(
        unused_imports,
        clippy::collapsible_if,
        clippy::match_single_binding,
        clippy::redundant_field_names,
        clippy::result_large_err
    )]

    include!(concat!(env!("OUT_DIR"), "/cachev1/mod.rs"));
}
