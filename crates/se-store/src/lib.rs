//! Compile-only storage design contract. No SQLite implementation is admitted.
//!
//! Normative behavior and formats: docs/design/20-data-model.md.
//! All executable functions are trait declarations, without stub/default bodies.
mod api;
mod event;
mod model;

pub use api::*;
pub use event::*;
pub use model::*;
