//! Serializes spawner exit, authenticated reclaim and the cleanup fence.
use crate::client::lease::Deadline;
use se_proc::{NativeState, ProcErrorCode, ProcessIdentity, ProcessRead};
use se_types::{Detail, SeError, details::StateConflict};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const RECLAIM_WINDOW: Duration = Duration::from_secs(10 * 60);

fn sessions_reason(sessions: &[(se_types::ProjectId, se_types::SessionId)]) -> String {
    let names = sessions
        .iter()
        .map(|(project, session)| format!("{project}/{session}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("Existing sessions: {names}")
}

fn refuse_home(reason: impl Into<String>) -> SeError {
    SeError::new(Detail::StateConflict(StateConflict {
        subject: "spawner-bound home".into(),
        reason: reason.into(),
        next_step: "Use a fresh --home, or run se up without --spawner for this home.".into(),
    }))
}

impl super::HostedRuntime {
    /// Bind a prepared runtime before reconciliation or listener admission.
    /// The runtime holds the home's exclusive writer lease during this read.
    pub async fn bind_spawner(
        &mut self,
        identity: ProcessIdentity,
        deadline: &Deadline,
    ) -> se_types::Result<()> {
        if self.phase != crate::HostPhase::Prepared
            || self.spawner.is_some()
            || self.retained_custody.is_none()
        {
            return Err(SeError::invalid(
                "spawner binding",
                "one prepared runtime before native reconciliation",
            ));
        }
        let reader = self.execution.reader.clone();
        let lease = self.lease.clone();
        let remaining = deadline.remaining()?;
        let sessions = self
            .execution
            .blocking
            .run_owned(deadline, move || {
                let mut budget = super::start::owner_budget()?;
                budget.deadline = budget.deadline.min(remaining);
                reader
                    .bound_sessions(&lease.files, budget)
                    .map_err(|error| {
                        refuse_home(format!(
                            "The saved sessions could not be fully read: {error}"
                        ))
                    })
            })
            .await?;
        if !sessions.is_empty() {
            return Err(refuse_home(sessions_reason(&sessions)));
        }
        if !self.retained_custody.as_ref().is_some_and(Vec::is_empty) {
            return Err(refuse_home("Existing native custody remains unresolved."));
        }
        self.spawner = Some(Arc::new(Spawner::new(identity)));
        Ok(())
    }
}

pub(super) fn unbound_refusal(
    context: &super::AdmissionContext,
    execution: &super::ExecutionContext,
    deadline: &Deadline,
) -> SeError {
    let result = (|| {
        let lease = context.lease.upgrade().ok_or_else(|| {
            se_core::scope::unreadable(
                "bound home sessions",
                "the original host lease is unavailable",
            )
        })?;
        let mut budget = super::start::owner_budget()?;
        budget.deadline = budget.deadline.min(deadline.remaining()?);
        execution
            .reader
            .bound_sessions(&lease.files, budget)
            .map_err(|error| se_core::scope::unreadable("bound home sessions", &error.to_string()))
    })();
    let reason = match result {
        Ok(sessions) if sessions.is_empty() => "This home already has an unbound runtime.".into(),
        Ok(sessions) => sessions_reason(&sessions),
        Err(error) => format!("The existing sessions could not be read: {error}"),
    };
    refuse_home(reason)
}

/// A read error cannot establish that a process exited. Image changes do not
/// end the same native birth, while PID reuse does.
pub(super) fn exited(identity: &ProcessIdentity, deadline: Instant) -> se_proc::ProcResult<bool> {
    let observed = se_proc::read_process_until(identity.machine.clone(), identity.pid, deadline)?;
    Ok(match observed {
        ProcessRead::Absent { .. } | ProcessRead::ExitedRecord { .. } => true,
        ProcessRead::Present(value) => {
            value.identity.boot != identity.boot
                || value.identity.start != identity.start
                || matches!(
                    value.state,
                    NativeState::Exited | NativeState::ExitedAwaitingReap
                )
        }
    })
}

/// Recheck the connected peer's birth and native parent edge around the
/// claimed spawner. Wire-supplied identity alone never grants reclaim.
pub(super) fn verify_peer(
    identity: &ProcessIdentity,
    peer: &crate::PeerProof,
    deadline: Instant,
) -> se_types::Result<()> {
    let native = peer.native();
    let invalid = || {
        SeError::invalid(
            "spawner reclaim",
            "the authenticated caller's exact live parent",
        )
    };
    let (caller, parent) = se_proc::read_direct_parent_until(
        identity.machine.clone(),
        se_proc::ProcessId(native.pid()),
        identity.pid,
        deadline,
    )
    .map_err(|error| match error.code {
        ProcErrorCode::InvalidInput => invalid(),
        _ => se_core::scope::unreadable("spawner reclaim", &format!("{error:?}")),
    })?;
    let birth_matches = match (&caller.start, native.started()) {
        (
            se_proc::StartIdentity::Linux { start_ticks: a },
            se_types::StartIdentity::Linux { start_ticks: b },
        ) => a == b,
        (
            se_proc::StartIdentity::Windows {
                creation_filetime: a,
            },
            se_types::StartIdentity::Windows {
                creation_filetime: b,
            },
        ) => *a == b.get(),
        _ => false,
    };
    if !birth_matches || parent != *identity {
        return Err(invalid());
    }
    Ok(())
}

enum State {
    Watching(ProcessIdentity),
    Grace {
        previous: ProcessIdentity,
        expires: Instant,
    },
    Stopping,
}

pub(crate) struct Spawner {
    state: Mutex<State>,
    changed: tokio::sync::Notify,
}

impl Spawner {
    pub(super) fn new(identity: ProcessIdentity) -> Self {
        Self {
            state: Mutex::new(State::Watching(identity)),
            changed: tokio::sync::Notify::new(),
        }
    }

    /// A native absence, exit record or replacement is required; an unreadable
    /// observation must never call this method.
    pub(super) fn witnessed_exit(&self, expected: &ProcessIdentity, now: Instant) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if matches!(&*state, State::Watching(identity) if identity == expected) {
            *state = State::Grace {
                previous: expected.clone(),
                expires: now + RECLAIM_WINDOW,
            };
            self.changed.notify_one();
            return true;
        }
        false
    }

    /// The caller has already authenticated the owner and verified its own
    /// native process identity. The same lock arbitrates this against expiry.
    pub(super) fn reclaim(&self, identity: ProcessIdentity, now: Instant) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if matches!(&*state, State::Watching(current)
            if current.machine == identity.machine && current.boot == identity.boot
                && current.pid == identity.pid && current.start == identity.start)
        {
            *state = State::Watching(identity);
            return true;
        }
        if matches!(&*state, State::Grace { previous, expires } if now < *expires && identity.machine == previous.machine)
        {
            *state = State::Watching(identity);
            self.changed.notify_one();
            return true;
        }
        false
    }

    /// Only the winner of the expiry/reclaim race is permitted to fence work.
    pub(super) fn expire(&self, now: Instant) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if matches!(&*state, State::Grace { expires, .. } if now >= *expires) {
            *state = State::Stopping;
            self.changed.notify_one();
            return true;
        }
        false
    }

    pub(crate) fn snapshot(&self) -> Option<(ProcessIdentity, Option<Instant>)> {
        let state = self.state.lock().ok()?;
        match &*state {
            State::Watching(identity) => Some((identity.clone(), None)),
            State::Grace { previous, expires } => Some((previous.clone(), Some(*expires))),
            State::Stopping => None,
        }
    }

    /// Run on the host runtime. Native observations use one bounded blocking
    /// job at a time; unreadable observations leave custody unchanged.
    pub(super) async fn wait(self: Arc<Self>) {
        loop {
            let changed = self.changed.notified();
            let Some((identity, expiry)) = self.snapshot() else {
                return std::future::pending().await;
            };
            if let Some(expiry) = expiry {
                if self.expire(Instant::now()) {
                    return;
                }
                tokio::select! {
                    () = changed => {},
                    () = tokio::time::sleep_until(tokio::time::Instant::from_std(expiry)) => {},
                }
                continue;
            }
            let observed = identity.clone();
            let read = tokio::task::spawn_blocking(move || {
                exited(&observed, Instant::now() + Duration::from_secs(2))
            })
            .await;
            if matches!(read, Ok(Ok(true))) {
                self.witnessed_exit(&identity, Instant::now());
            }
            tokio::select! {
                () = changed => {},
                () = tokio::time::sleep(Duration::from_secs(1)) => {},
            }
        }
    }
}
