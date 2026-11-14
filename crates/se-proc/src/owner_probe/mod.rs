//! Native observations for §70.2.3. These facts do not grant owner authority.
//! Core supplies the complete, successfully read set of unresolved agent records
//! and applies admission policy. An absent host endpoint cannot supply that set.
use crate::{BootIdentity, ProcessId, ProcessIdentity, ProcessRecord, StartIdentity};
use std::io;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
pub(crate) mod macos;
/// Native Darwin boot fact for an owner lease. This observes KERN_BOOTTIME;
/// it does not derive machine identity or grant owner authority.
#[cfg(target_os = "macos")]
pub fn observe_boot_id() -> std::result::Result<se_types::BootId, OwnerProbeError> {
    match macos::boot()? {
        BootIdentity::MacOs {
            seconds,
            microseconds,
        } => se_types::BootId::new(format!("macos-{seconds}-{microseconds}"))
            .map_err(|error| native("encode native boot identity", io::Error::other(error))),
        _ => Err(refuse("read boot identity", "native boot kind differs")),
    }
}
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeOwner {
    Unix { real_uid: u32, effective_uid: u32 },
    Windows { sid: String },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentTreeBasis {
    ExactRoot,
    Ancestor,
    ProcessGroup,
    Session,
    Cgroup,
    WindowsJob,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentTreeMatch {
    /// Index into the exact records supplied to this observation.
    pub record_index: usize,
    pub basis: AgentTreeBasis,
}
/// A native ancestry walk can reach an ancestor whose birth is protected.
/// This explicit read bound grants no agent match or owner authority by itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AncestryBound {
    Complete,
    UnopenableAncestor {
        pid: ProcessId,
        native_code: Option<i32>,
        reason: String,
    },
}
/// Constructible only by the native observer. Callers cannot assert owner or
/// terminal flags. Environment values (including session credentials) are not
/// retained or exposed.
#[derive(Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub struct OwnerObservation {
    owner: NativeOwner,
    stdin_console: bool,
    stdout_console: bool,
    session_present: bool,
    provider_marker_present: bool,
    agent_trees: Vec<AgentTreeMatch>,
    ancestry_bound: AncestryBound,
}
impl OwnerObservation {
    pub fn owner(&self) -> &NativeOwner {
        &self.owner
    }
    pub fn stdin_console(&self) -> bool {
        self.stdin_console
    }
    pub fn stdout_console(&self) -> bool {
        self.stdout_console
    }
    pub fn session_present(&self) -> bool {
        self.session_present
    }
    pub fn provider_marker_present(&self) -> bool {
        self.provider_marker_present
    }
    pub fn ancestry_bound(&self) -> &AncestryBound {
        &self.ancestry_bound
    }
    pub fn agent_trees(&self) -> &[AgentTreeMatch] {
        &self.agent_trees
    }
}
#[derive(Debug)]
pub struct OwnerProbeError {
    pub operation: &'static str,
    pub source: io::Error,
}
crate::native_error::native_error!(OwnerProbeError, |error, out| {
    write!(out, "{}: {}", error.operation, error.source)
}; source Some(&error.source));
type Result<T> = std::result::Result<T, OwnerProbeError>;
fn native(operation: &'static str, source: io::Error) -> OwnerProbeError {
    OwnerProbeError { operation, source }
}
fn refuse(operation: &'static str, reason: &'static str) -> OwnerProbeError {
    native(operation, io::Error::other(reason))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessStamp {
    pid: ProcessId,
    parent: ProcessId,
    group: ProcessId,
    session: ProcessId,
    boot: BootIdentity,
    start: StartIdentity,
}
impl ProcessStamp {
    fn instance_matches(&self, expected: &ProcessIdentity) -> bool {
        self.pid == expected.pid && self.boot == expected.boot && self.start == expected.start
    }
}

/// Selects the current process or a process instance already proved by IPC.
/// A PID alone is never sufficient. The observer checks the supplied start
/// binding before and after the same ancestry and scope walk used for self.
#[derive(Clone, Copy, Debug)]
pub enum OwnerTarget<'a> {
    Current,
    Process {
        pid: ProcessId,
        start: &'a StartIdentity,
    },
}

/// Native owner and managed-tree facts about the selected process. Remote
/// observations do not borrow this host's console or environment as peer facts.
#[derive(Debug)]
pub struct OwnerTreeObservation {
    owner: NativeOwner,
    pid: ProcessId,
    start: StartIdentity,
    agent_trees: Vec<AgentTreeMatch>,
    ancestry_bound: AncestryBound,
}
impl OwnerTreeObservation {
    pub fn owner(&self) -> &NativeOwner {
        &self.owner
    }
    pub fn pid(&self) -> ProcessId {
        self.pid
    }
    pub fn start(&self) -> &StartIdentity {
        &self.start
    }
    pub fn ancestry_bound(&self) -> &AncestryBound {
        &self.ancestry_bound
    }
    pub fn agent_trees(&self) -> &[AgentTreeMatch] {
        &self.agent_trees
    }
}

/// Observe an already-proved process against the complete protected inventory.
/// These facts grant no authority. Unreadable or changed ancestry, scopes or
/// start bindings are errors, never an observation that the peer is outside.
/// Uncontained escape/reparenting has the explicit bound in §70: a descendant
/// which left its session/group and lost its ancestry cannot be recognized.
pub fn observe_owner(
    target: OwnerTarget<'_>,
    records: &[ProcessRecord],
) -> Result<OwnerTreeObservation> {
    if records.len() > 16384 {
        return Err(refuse("observe owner", "agent-record capacity exceeded"));
    }
    let (pid, expected) = match target {
        OwnerTarget::Current => (ProcessId(std::process::id()), None),
        OwnerTarget::Process { pid, start } => (pid, Some(start)),
    };
    if pid.0 == 0 || pid.0 > i32::MAX as u32 {
        return Err(refuse("observe owner", "invalid target process ID"));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unix::observe(pid, expected, records)
    }
    #[cfg(windows)]
    {
        windows::observe(pid, expected, records)
    }
}

/// Self observation also reads actual standard streams and process markers.
/// Kept as a compatible wrapper for hostless owner admission.
pub fn observe_owner_self(records: &[ProcessRecord]) -> Result<OwnerObservation> {
    let observed = observe_owner(OwnerTarget::Current, records)?;
    #[cfg(unix)]
    let (stdin_console, stdout_console) = unix::console()?;
    #[cfg(windows)]
    let (stdin_console, stdout_console) = windows::console_presence()?;
    Ok(OwnerObservation {
        owner: observed.owner,
        stdin_console,
        stdout_console,
        session_present: std::env::var_os("SE_SESSION").is_some(),
        provider_marker_present: ["CLAUDECODE", "CODEX_THREAD_ID", "CODEX_CI"]
            .iter()
            .any(|key| std::env::var_os(key).is_some()),
        agent_trees: observed.agent_trees,
        ancestry_bound: observed.ancestry_bound,
    })
}
