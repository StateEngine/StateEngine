//! Host-side Atlas query, continuity, hook, and owner-driver adapters.
#[cfg(feature = "listener")]
pub mod atlas_continuity;
pub mod atlas_hooks;
#[cfg(all(
    feature = "listener",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub mod atlas_owner;
pub mod atlas_queries;
pub mod atlas_records;
pub mod atlas_runtime;
#[cfg(all(
    feature = "listener",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub mod host;
