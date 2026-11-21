//! Host-side Atlas query, renewal, continuity, hook, and owner-driver adapters.
pub use se_atlas_cold::atlas_cache;
#[cfg(any(target_os = "linux", all(windows, feature = "listener")))]
use se_atlas_cold::atlas_ignore;
pub use se_atlas_cold::atlas_source;
#[cfg(any(target_os = "linux", all(windows, feature = "listener")))]
use se_atlas_cold::atlas_watch_error;

pub mod atlas_cold;
#[cfg(feature = "listener")]
pub mod atlas_continuity;
#[cfg(any(target_os = "linux", all(windows, feature = "listener")))]
mod atlas_git_watch;
pub mod atlas_hooks;
#[cfg(all(feature = "listener", any(target_os = "linux", windows)))]
pub mod atlas_owner;
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
mod atlas_parse;
pub mod atlas_queries;
pub mod atlas_records;
#[cfg(any(target_os = "linux", all(windows, feature = "listener")))]
pub mod atlas_renewal;
pub mod atlas_runtime;
#[cfg(all(feature = "listener", any(target_os = "linux", windows)))]
pub mod host;
