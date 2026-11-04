//! Rebuildable Atlas foundation. Native custody is supplied by host adapters.
#![forbid(unsafe_code)]

pub mod errors;
pub mod lifecycle;
pub mod model;
pub mod queries;

pub mod cache;
pub mod scope;
pub mod source;
