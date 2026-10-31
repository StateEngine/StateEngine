//! Kernel operations and the single operation registry that generates the CLI and MCP surfaces.

/// S-R1 compile-only read/batch/typed-continuation seam.
pub mod commit;

pub mod registry;
pub mod config_policy;
