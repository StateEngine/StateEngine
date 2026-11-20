//! Native state-path traversal and protected-path error facts.
mod resolve;
pub use resolve::resolve;
mod state_error;
#[cfg(unix)]
pub use state_error::unsafe_path_observed;
pub use state_error::{Result, StateFileError, StateFileErrorCode, failure, io_error, unsafe_path};
#[cfg(unix)]
pub mod ancestors;
