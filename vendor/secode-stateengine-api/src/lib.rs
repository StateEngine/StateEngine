// SPDX-License-Identifier: MIT OR Apache-2.0
//! Optional StateEngine linked interface owned by SE Code.
//! Traits and data only: no engine, runtime, I/O or implicit global state.
//! Package/API major 2 is an exact linked compatibility boundary.
use std::{future::Future, pin::Pin};
mod config;
mod error;
mod handover;
mod host;
mod identity;
mod native;
mod read;
mod session;
pub use config::*;
pub use error::*;
pub use handover::*;
pub use host::*;
pub use identity::*;
pub use native::*;
pub use read::*;
pub use session::*;
pub type HostFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;
