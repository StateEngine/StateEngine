//! The CLI's view of the recorded host process; the observation lives in the host crate.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub use se_host::host_process::{from_identity, observe, same_start};

pub(super) fn witness_exit(
    files: &super::files::Files,
    instance: &se_types::ProcessInstance,
    bound: &se_host::client::lease::Deadline,
) -> se_types::Result<()> {
    let machine = super::identity::require_machine(files)?;
    se_host::host_process::witness_exit(&machine, instance, bound)
}
