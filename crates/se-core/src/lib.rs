//! Kernel operations and the single operation registry that generates the CLI and MCP surfaces.

pub mod admission;
/// Synchronous read/batch/typed-continuation seam.
pub mod commit;
pub mod dispatch;
pub mod ports;
pub mod scope;
pub mod store_error;

pub mod config_policy;
pub mod registry;

pub mod ops;

pub mod machine_identity;
