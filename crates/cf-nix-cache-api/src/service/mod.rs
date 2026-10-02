//! Service implementations for the generated API traits.
//!
//! The service types, the bindings they carry, and the trait impls are in
//! [`handler`]. Upload auth is in [`middleware`], which the crate root layers
//! over the API's routes, so no handler authorizes.
//!
//! `/healthz` is beside them, in the crate root: it's a deployment check, not
//! part of the API, so the spec doesn't declare it.

mod handler;
pub mod middleware;

pub use handler::CacheServiceHandler;
