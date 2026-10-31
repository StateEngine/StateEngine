//! Native observations for §70.2.3. These facts do not grant owner authority.
//! Core supplies the complete, successfully read set of unresolved agent records
//! and applies admission policy. An absent host endpoint cannot supply that set.
use crate::{BootIdentity, ProcessId, ProcessIdentity, ProcessRecord, StartIdentity};
use std::io;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
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
/// Constructible only by the native observer. Callers cannot assert owner or
/// terminal flags. Environment values (including session credentials) are not
/// retained or exposed.
#[derive(Debug)]
pub struct OwnerObservation {
    owner: NativeOwner,
    stdin_console: bool,
    stdout_console: bool,
    session_present: bool,
    provider_marker_present: bool,
    agent_trees: Vec<AgentTreeMatch>,
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
    pub fn agent_trees(&self) -> &[AgentTreeMatch] {
        &self.agent_trees
    }
}
#[derive(Debug)]
pub struct OwnerProbeError {
    pub operation: &'static str,
    pub source: io::Error,
}
impl std::fmt::Display for OwnerProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.operation, self.source)
    }
}
impl std::error::Error for OwnerProbeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
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

/// Observes this process without accepting a caller's identity, user, terminal
/// flags or environment claims. All ancestry and scope reads must succeed;
/// access denial, changed identities and capacity limits return an error.
///
/// Uncontained escape/reparenting has the explicit bound in §70: a descendant
/// which has left its recorded session/group and lost the recorded ancestry
/// cannot be recognized by these mistake/drift checks.
pub fn observe_owner_self(records: &[ProcessRecord]) -> Result<OwnerObservation> {
    if records.len() > 16384 {
        return Err(refuse("observe owner", "agent-record capacity exceeded"));
    }
    let session_present = std::env::var_os("SE_SESSION").is_some();
    let provider_marker_present = ["CLAUDECODE", "CODEX_THREAD_ID", "CODEX_CI"]
        .iter()
        .any(|key| std::env::var_os(key).is_some());
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let (owner, stdin_console, stdout_console, agent_trees) = unix::observe(records)?;
    #[cfg(windows)]
    let (owner, stdin_console, stdout_console, agent_trees) = windows::observe(records)?;
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    return Err(refuse("observe owner", "unsupported native platform"));
    Ok(OwnerObservation {
        owner,
        stdin_console,
        stdout_console,
        session_present,
        provider_marker_present,
        agent_trees,
    })
}
