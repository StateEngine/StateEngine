use crate::{
    GenerationId, HostInstanceId, LifecycleId, LifecycleState, ProcessId, ProcessIdentity,
    RemainingScope, StartIdentity,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Internal causes, NOT another public wire-code catalogue. Section 50 owns
/// wire codes, classes, messages and remedies; section 30 specifies the mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ProcErrorCode {
    InvalidInput,
    ExecutableMissing,
    CwdOutsideWorkspace,
    EnvironmentDenied,
    IdentityUnreadable,
    IdentityChanged,
    UnsupportedPlatform,
    ContainmentUnavailable,
    ContainmentChanged,
    ContainmentEscape,
    HardeningUnavailable,
    BreakawayDenied,
    LaunchFailed,
    LaunchTimedOut,
    DuplicateLifecycle,
    HostChanged,
    GenerationChanged,
    ScopeUnreadable,
    StopDispatchFailed,
    StopIncomplete,
    ResourceLimit,
    IllegalTransition,
    StopTokenExpired,
    StopTokenConsumed,
    LockPoisoned,
    OperationPanicked,
    CallbackPanicked,
    RecoveryUnproved,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeFailure {
    pub api: String,
    pub code: Option<i64>,
    /// Sanitized native cause, never parsed to determine a code or detail.
    pub reason: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ProcErrorDetail {
    Input {
        field: String,
        reason: String,
    },
    Executable {
        #[serde(with = "crate::checkpoint::native_path")]
        program: PathBuf,
    },
    Workspace {
        #[serde(with = "crate::checkpoint::native_path")]
        cwd: PathBuf,
        #[serde(with = "crate::checkpoint::native_path")]
        workspace: PathBuf,
    },
    Environment {
        key: String,
    },
    Identity {
        pid: ProcessId,
        expected_start: Option<StartIdentity>,
        found_start: Option<StartIdentity>,
        expected: Option<Box<ProcessIdentity>>,
        found: Option<Box<ProcessIdentity>>,
    },
    Scope {
        lifecycle: Option<LifecycleId>,
        #[serde(with = "crate::checkpoint::optional_native_path")]
        path: Option<PathBuf>,
        reason: String,
    },
    Stop {
        lifecycle: LifecycleId,
        deadline_ms: u64,
        remaining: Box<RemainingScope>,
    },
    State {
        lifecycle: LifecycleId,
        from: LifecycleState,
        operation: String,
    },
    Generation {
        expected: GenerationId,
        current: GenerationId,
    },
    Host {
        expected: HostInstanceId,
        current: HostInstanceId,
    },
    Token {
        lifecycle: LifecycleId,
        consumed: bool,
        expired: bool,
    },
    Capacity {
        resource: String,
        limit: u64,
    },
    Internal {
        location: String,
        report_id: [u8; 16],
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcError {
    pub code: ProcErrorCode,
    pub detail: Box<ProcErrorDetail>,
    pub native: Option<NativeFailure>,
}
pub type ProcResult<T> = std::result::Result<T, ProcError>;
