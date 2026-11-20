//! Rebuildable Atlas foundation. Native custody is supplied by host adapters.
#![deny(unsafe_code)]
// Native SQLite and trusted-path FFI are isolated in scoped modules.

pub mod coverage;
pub mod errors;
pub mod lifecycle;
pub mod model;
pub mod native_sql;
pub mod queries;

pub mod cache;
pub mod clock;
pub mod history;
pub mod parse;
pub mod query;
pub mod rank;
pub mod reader;
pub mod records;
pub mod render;
pub mod scope;
pub mod source;
pub mod text;

pub mod resolve;

pub mod update;

pub mod controller;
pub mod policy;
pub mod scheduler;
