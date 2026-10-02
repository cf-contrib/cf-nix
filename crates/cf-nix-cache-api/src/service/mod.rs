//! Service implementations for the generated API traits.
//!
//! Everything is in [`handler`]: the service types, the bindings they carry,
//! and the trait impls.
//!
//! `/healthz` is beside them, in the crate root: it's a deployment check, not
//! part of the API, so the spec doesn't declare it.

mod handler;

pub use handler::CacheServiceHandler;
