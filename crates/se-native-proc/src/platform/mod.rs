#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use crate::macos_process::{read_process, read_process_until};
#[cfg(target_os = "macos")]
pub use macos::process_attach_entry;
#[cfg(target_os = "macos")]
pub use macos::{Driver, Scope, uncreated_scope};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{Driver, Scope, read_process, read_process_until, uncreated_scope};
#[cfg(target_os = "linux")]
pub(crate) use linux::{runtime_boot_id, runtime_cgroup, verify_live_identity};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::observe_prepared_scope_exit;
#[cfg(windows)]
pub(crate) use windows::verify_live_identity;
#[cfg(windows)]
pub use windows::{
    CONSOLE_INTERRUPT_ENTRY, Driver, NativeStdio, Scope, console_interrupt_entry,
    initialize_host_console_policy, read_process, read_process_until, uncreated_scope,
};

use crate::{
    EnumerationExtent, Population, ProcessIdentity, ProcessObservation, RemainingScope,
    ScopeExitBasis, ScopeIdentity, ScopeObservation,
};

pub enum Progress {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Pending,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Root(ProcessIdentity),
    Executed(ProcessIdentity, Box<ProcessObservation>),
}

pub fn empty(scope: ScopeIdentity) -> crate::ProcResult<ScopeObservation> {
    Ok(ScopeObservation {
        scope,
        remaining: RemainingScope {
            population: Population::Empty,
            known_live: Vec::new(),
            extent: EnumerationExtent::Complete,
            observed_at_unix_ns: crate::support::now()?,
        },
        exit_basis: Some(ScopeExitBasis::ObservedEmpty),
    })
}
