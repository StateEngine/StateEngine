//! Low-level OS process primitives, platform drivers, native bootstrap, and FFI custody.
//!
//! Extracted from `se-proc` so all process-control `unsafe` FFI is isolated in
//! this crate while `se-proc` stays `unsafe_code = "forbid"`.

#[cfg(windows)]
mod windows_directory;
#[cfg(windows)]
pub use windows_directory::windows_directory;
#[cfg(windows)]
mod windows_package;
#[cfg(windows)]
pub use windows_package::process_has_package_identity;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod allocator;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub use allocator::{reclaim_unused_allocator_pages, release_read_only_mapped_pages};

#[cfg(windows)]
pub(crate) use se_custody::NativeFailure;
pub(crate) use se_custody::checkpoint;
pub(crate) use se_custody::support;
pub(crate) use se_custody::{ProcError, ProcErrorCode, ProcErrorDetail, ProcResult};
pub(crate) use se_native_ipc as native_ipc;
pub(crate) use se_native_ipc::canonicalize_path;
#[cfg(target_os = "linux")]
pub(crate) use se_native_ipc::linux_native;
pub(crate) use se_source_watch::{NativeRootFile, NativeSourceRoot};
pub(crate) use se_state_files::native_error;
#[cfg(windows)]
pub(crate) use se_state_files::random_secret;
pub(crate) use se_state_files::state_files;

mod command;
pub use command::background_command;
mod contained_child;
pub use contained_child::{ContainedChild, ContainedChildSpec, ContainedExit, ContainedKiller};
mod identity;
pub use identity::*;
mod launch;
pub use launch::*;
mod ownership;
pub use ownership::*;
#[cfg(windows)]
mod stdio;
#[cfg(windows)]
pub use stdio::*;

pub mod notify;

#[cfg(windows)]
mod child_pipe;
#[cfg(windows)]
pub use child_pipe::NativeChildPipe;

pub mod file_access;

mod executable;
pub use executable::{NativeExecutableCreation, NativeExecutableInvocation, NativeExecutablePin};

pub mod owner_probe;
#[cfg(target_os = "macos")]
pub use owner_probe::observe_boot_id;
pub use owner_probe::{
    AgentTreeBasis, AgentTreeMatch, AncestryBound, NativeOwner, OwnerObservation, OwnerProbeError,
    OwnerTarget, OwnerTreeObservation, observe_owner, observe_owner_self,
};

#[cfg(target_os = "linux")]
mod user_manager;
#[cfg(target_os = "linux")]
pub use user_manager::{runtime_user_scope_empty, verify_runtime_user_scope};

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub mod bootstrap;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod bootstrap_protocol;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub use bootstrap::{
    NativeRuntimeIdentity, RuntimeAdmission, RuntimeBootRelation, RuntimeBootstrap,
    RuntimeStartupStderr, current_process_identity, current_runtime_identity,
};

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub mod platform;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub mod validate;
#[cfg(target_os = "macos")]
pub use platform::process_attach_entry;
#[cfg(windows)]
pub use platform::{
    CONSOLE_INTERRUPT_ENTRY, console_interrupt_entry, initialize_host_console_policy,
    observe_prepared_scope_exit,
};
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub use platform::{read_process, read_process_until};

#[cfg(target_os = "macos")]
mod macos_process;
#[cfg(windows)]
mod windows_native;

mod monotonic;
pub use monotonic::monotonic_micros;

mod birth_time;
pub use birth_time::{ProcessBirthTime, observe_process_birth};

#[cfg(target_os = "linux")]
mod self_resources;
#[cfg(target_os = "linux")]
pub use self_resources::{SelfResources, observe_self_resources};

#[cfg(windows)]
mod parent_image;
#[cfg(windows)]
pub use parent_image::parent_process_image;

#[cfg(windows)]
mod parent_lifetime;
#[cfg(windows)]
pub use parent_lifetime::retain_package_parent;

#[cfg(all(test, windows))]
pub(crate) use se_state_files::{
    NativeStateFiles, OwnedFile, StateFileErrorCode, initialize_file_creation_owner,
};
#[cfg(all(test, windows))]
#[path = "../../test-support/windows_policy_common.rs"]
mod windows_policy_fixture;
#[cfg(all(test, windows))]
#[path = "../tests/support/windows_policy_fixture.rs"]
mod windows_policy_tests;
