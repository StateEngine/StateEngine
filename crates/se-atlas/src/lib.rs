//! Compile-only Atlas contract. See docs/design/60-atlas.md.
//! No indexer, watcher, SQL executor, runtime stub or transport is implemented.

#![allow(dead_code, reason = "Declarations only until design approval")]

pub mod errors;
pub mod lifecycle;
pub mod model;
pub mod queries;
