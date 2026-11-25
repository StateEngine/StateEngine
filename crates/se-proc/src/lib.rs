//! Safe process runtime, orchestration, validation, and policy facade.
//!
//! All low-level OS/FFI `unsafe` primitives live in `se-native-proc`,
//! `se-state-files`, `se-native-ipc`, `se-source-watch`, and `se-uninstall`;
//! this crate enforces `unsafe_code = "forbid"` via workspace lints.

// Shared native fixture helpers use the same crate path in unit and integration tests.
#[cfg(test)]
extern crate self as se_proc;

#[cfg(windows)]
pub use se_native_proc::process_has_package_identity;
#[cfg(windows)]
pub use se_native_proc::windows_directory;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub use se_native_proc::{reclaim_unused_allocator_pages, release_read_only_mapped_pages};
#[cfg(unix)]
pub use se_state_files::advisory_lock;

pub use checkpoint::{
    Checkpoint, CheckpointError, CheckpointKind, CheckpointPrincipal, CheckpointSource,
    HistoricalCheckpoint, RootPublication, decode_checkpoint, encode_checkpoint,
};
pub(crate) use se_custody::checkpoint;
pub use se_custody::{NativeFailure, ProcError, ProcErrorCode, ProcErrorDetail, ProcResult};
pub use se_native_ipc::canonicalize_path;
pub use se_native_proc::background_command;
pub use se_state_files::NativeFileIdentity;
mod reboot_proof;
pub use reboot_proof::{
    ObservedBoot, RebootBoot, RebootProof, VerifiedReboot, match_recorded_root,
    observe_reboot_boot, prove_reboot,
};
pub use se_native_ipc as native_ipc;
#[cfg(windows)]
pub use se_uninstall::{
    HelperCleanupOutcome, NativeUninstallCarrier, UNINSTALL_CARRIER_ENTRY, UninstallHelperCleanup,
    UninstallNativeError, uninstall_carrier_entry,
};

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod process_command;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub use process_command::read_process_command;
#[cfg(target_os = "linux")]
mod process_descendants;
#[cfg(target_os = "linux")]
pub use process_descendants::read_process_descendants;

#[cfg(windows)]
pub use se_native_proc::NativeChildPipe;
pub use se_native_proc::file_access;
pub use se_native_proc::{
    NativeExecutableCreation, NativeExecutableInvocation, NativeExecutablePin,
};
#[cfg(target_os = "linux")]
pub use se_source_watch::NativeWatchWake;
pub use se_source_watch::{
    NativeFileRevision, NativeRootDirectory, NativeRootFile, NativeSourceEntry, NativeSourceKind,
    NativeSourceRoot, NativeSourceScan, observe_file_revision,
};
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub use se_source_watch::{
    NativeSourceWatch, NativeWatchAction, NativeWatchDirectory, NativeWatchEvent,
    NativeWatchEvents, NativeWatchRegistration,
};
pub(crate) use se_state_files::state_files;
pub use state_files::{
    NativeProfileFiles, NativeStateFiles, PermissionKind, PermissionProtection,
    PermissionRepairPin, PermissionRepairWitness, PermissionSnapshot, ProtectedStateStaging,
    StateFileError, StateFileErrorCode,
};

mod ownership;
pub use ownership::*;
#[cfg(windows)]
mod stdio;
#[cfg(windows)]
pub use stdio::*;

pub use se_native_proc::{
    AgentTreeBasis, AgentTreeMatch, AncestryBound, ArenaEntry, ArenaSnapshot, BootIdentity,
    Capability, ContainmentGuarantee, ContainmentRequirement, EntryMethod, EnumerationExtent,
    Environment, ExitEvidence, ExitNotice, ExitNoticeKind, ExitSink, ExitStatus,
    ExitStatusUnavailable, GenerationId, HostConfig, HostInstanceId, LaunchMode, LaunchPolicy,
    LaunchReservation, LaunchSpec, LifecycleId, LifecycleState, LinuxDelegation, LiveObservation,
    MachineId, NativeInterest, NativeOwner, NativeProcessApi, NativeReactor, NativeReadiness,
    NativeRegistration, NativeState, NetworkPolicy, OptionalHardening, OwnedObservation,
    OwnerObservation, OwnerProbeError, OwnerTarget, OwnerTreeObservation, PlatformCapabilities,
    Population, ProcessBirthTime, ProcessId, ProcessIdentity, ProcessObservation, ProcessRead,
    ProcessRecord, RecoveryDisposition, RecoveryPlan, RecoverySource, ReleasedOwnership,
    RemainingScope, ReservationParent, ResourceLimits, RootCheckpoint, RootWitness, RuntimeChild,
    RuntimeCommitFailure, RuntimeDetachment, RuntimeExitObservation, RuntimeExitWitness,
    RuntimeLaunch, RuntimeLaunchSpec, RuntimeLifetime, RuntimeReady, RuntimeReadyProof,
    RuntimeSpawnFailure, RuntimeUserScope, ScopeCheckpoint, ScopeExitBasis, ScopeIdentity,
    ScopeObservation, StandardIo, StartIdentity, StopDispatch, StopObservation, StopWitness,
    StreamRole, TerminalAdapter, TrackedObligations, TransferEndpoint, TransferImport,
    TransferReceipt, TransferResource, TransferResourceKind, TransferStream, UncontainedReason,
    UnwitnessedRelease, WindowSpec, WritePolicy, monotonic_micros, observe_owner,
    observe_owner_self, observe_process_birth,
};
#[cfg(windows)]
pub use se_native_proc::{
    CONSOLE_INTERRUPT_ENTRY, StdioBinding, StdioCancel, StdioCloseScope, StdioClosed,
    StdioCompletion, StdioConfig, StdioIdentity, StdioLimits, StdioNotice, StdioNoticeKind,
    StdioOperationId, StdioOutcome, StdioReadStream, StdioSink, StdioWriteRejection,
    console_interrupt_entry, initialize_host_console_policy, observe_prepared_scope_exit,
    parent_process_image, retain_package_parent,
};
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub use se_native_proc::{
    NativeRuntimeIdentity, RuntimeAdmission, RuntimeBootRelation, RuntimeBootstrap,
    RuntimeStartupStderr, current_process_identity, current_runtime_identity,
};
#[cfg(target_os = "linux")]
pub use se_native_proc::{
    SelfResources, observe_self_resources, runtime_user_scope_empty, verify_runtime_user_scope,
};
#[cfg(target_os = "macos")]
pub use se_native_proc::{observe_boot_id, process_attach_entry};

#[cfg(target_os = "linux")]
pub(crate) use se_native_ipc::linux_native;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub(crate) use se_native_proc::bootstrap;
#[cfg(target_os = "macos")]
pub(crate) use se_native_proc::owner_probe;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub(crate) use se_native_proc::platform;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod runtime;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub use runtime::{read_process, read_process_until};
pub(crate) use se_custody::support;

pub use se_state_files::{FileOwnerError, FileOwnerInitialization, initialize_file_creation_owner};
pub use se_state_files::{NativeEntropyError, fill_entropy, random_secret};
pub use state_files::NativeMetadataPin;
#[cfg(windows)]
pub use state_files::effects::remove_held;
pub use state_files::effects::{
    CreatedDirectoryCleanup, DirectoryRemoval, NativeDirectoryCreation, NativeInstallationClaim,
    OwnedFile, installation_claim_path, remove_empty_directory, scan_recovery, scan_temporary,
};
pub use state_files::source::{NativeSourcePin, SourceChunk};
#[cfg(windows)]
pub use state_files::user_path::{
    NativeUserPath, PathKind, PathObservation, PathUpdateError, PathUpdatePhase, PathWriteWitness,
};

mod session_pin;
mod sqlite_path;
pub use session_pin::{
    SessionPinRemoval, publish_session_pin, read_session_pin, remove_session_pin, session_launch_id,
};
pub use sqlite_path::sqlite_path;
