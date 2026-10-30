/// Every process failure has one stable process-domain code. The host maps
/// these exhaustively to the shared se-types error envelope, preserving cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcErrorCode {
    InvalidInput,
    ProcessAbsent,
    IdentityUnreadable,
    IdentityChanged,
    UnsupportedPlatform,
    ContainmentUnavailable,
    ContainmentChanged,
    ContainmentEscape,
    SandboxUnavailable,
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
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcError {
    pub code: ProcErrorCode,
    pub cause: String,
    pub native_code: Option<i64>,
}
pub type ProcResult<T> = std::result::Result<T, ProcError>;
