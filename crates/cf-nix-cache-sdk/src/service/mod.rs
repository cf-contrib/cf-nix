//! The hand-written part of the SDK, mounted into `v1` beside the generated
//! code: the models' companions in [`model`] (the narinfo format, and
//! constructors for generated types), and the health endpoints in
//! [`handler`].

pub(crate) mod handler;
pub(crate) mod model;
