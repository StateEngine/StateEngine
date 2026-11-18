//! One provider process serving several agents on a single login.
//!
//! The process itself is described by an ordinary process record; this is the
//! scope around it. Keeping them apart means custody has one description of a
//! native process and this module has one description of who is attached to it.

use crate::{ProcessState, Revision, StorePosition};
use se_types::{LifecycleId, SessionId};

/// Where a shared scope stands. `Live` is the only phase that accepts another
/// agent; `Stopped` and `Died` are different facts and never collapse.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedScopePhase {
    Starting,
    Live,
    /// The host stopped a scope it owns, after the last agent left.
    Stopped,
    /// The process ended while agents were attached.
    Died,
}

/// How one agent's thread ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadEnd {
    /// The agent was stopped: its turn was interrupted and its thread archived.
    Stopped,
    /// The scope ended first, so the thread could not be archived by us.
    ScopeEnded,
}

/// The shared process one login's agents attach to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedScope {
    pub scope: LifecycleId,
    pub login: String,
    /// The ordinary process record for the server; this scope never owns it.
    pub server_process: LifecycleId,
    pub phase: SharedScopePhase,
    pub revision: Revision,
    pub last: StorePosition,
}

/// One agent's thread on a shared scope.
///
/// An open membership has `detached` absent; this is what answers "may the
/// server be stopped", so it is durable rather than derived from connections.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedThread {
    pub scope: LifecycleId,
    pub session: SessionId,
    pub thread: String,
    pub attached: StorePosition,
    pub detached: Option<ThreadEndRecord>,
    pub revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreadEndRecord {
    pub end: ThreadEnd,
    pub at: StorePosition,
    pub reason: String,
}

/// One scope as a store projection reports it, with its server's process state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedScopeView {
    pub scope: SharedScope,
    pub server_state: ProcessState,
    pub threads: Vec<SharedThread>,
}
