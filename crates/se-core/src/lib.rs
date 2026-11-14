//! Kernel operations and the single operation registry that generates the CLI and MCP surfaces.

pub mod admission;
pub mod atlas_records;
pub mod atlas_resume;
/// Synchronous read/batch/typed-continuation seam.
pub mod commit;
pub mod dispatch;
pub mod ports;
pub mod scope;
pub mod store_error;

/// TODO: Remove this compatibility export after pending callers migrate to se-config.
pub use se_config::config_policy;
pub mod harness_selection;
pub mod registry;
pub mod remote;

pub mod ops;

pub mod machine_identity;
