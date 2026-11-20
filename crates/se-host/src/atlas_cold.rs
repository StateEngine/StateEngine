//! One derived cold epoch; the worker body lives in the se-atlas-cold crate.
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
pub use se_atlas_cold::cold::job;
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
pub use se_atlas_cold::cold::parser_memory_guard;
pub use se_atlas_cold::cold::protocol;
pub use se_atlas_cold::cold::{EXTRACTOR, empty_coverage, failure, sql_deadline};

#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
pub fn private_entry() -> se_atlas::errors::AtlasResult<u8> {
    let (mut channel, bytes) = se_proc::atlas_worker::WorkerChannel::receive().map_err(failure)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(failure)?;
    if value.get("parse_only").is_some() {
        return crate::atlas_parse::run_child(&mut channel, &bytes);
    }
    se_atlas_cold::cold::private_entry_with(&mut channel, &bytes)
}
