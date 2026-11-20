//! Atlas private worker: the one derived cold epoch, its Git history reader and
//! the cache ingestion that publishes it.
pub mod apply;
pub mod atlas_cache;
pub mod atlas_git;
pub mod atlas_ignore;
pub mod atlas_source;
pub mod atlas_watch_error;
pub mod cold;
pub mod deadline;
#[cfg(target_os = "linux")]
mod quantum;
