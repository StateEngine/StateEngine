//! Turn state an external seat's runner reports, and how it gates `se msg wait`.
//! The state lives on the active lease, so revocation, replacement or expiry of
//! the lease discards it: a crashed runner never leaves its seat held busy.
use super::ActivityState;
use std::sync::{Arc, Weak};
use tokio::sync::watch;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
    Idle,
    Busy,
    /// Idle after a reported turn. The next wait decides from live unread mail:
    /// one batch if any remains, otherwise nothing and it keeps waiting.
    TurnEnded,
}

/// The reported phase plus the number of the turn it belongs to, so a wait
/// consumes exactly the turn end it observed and never a later one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SeatActivity {
    pub(crate) phase: Phase,
    turn: u64,
}

pub(crate) type ActivitySender = Arc<watch::Sender<SeatActivity>>;

pub(crate) fn idle() -> ActivitySender {
    Arc::new(
        watch::channel(SeatActivity {
            phase: Phase::Idle,
            turn: 0,
        })
        .0,
    )
}

/// Apply a runner's report and return the phase it replaced.
pub(crate) fn report(sender: &watch::Sender<SeatActivity>, state: ActivityState) -> Phase {
    let mut previous = Phase::Idle;
    sender.send_if_modified(|current| {
        previous = current.phase;
        let next = match (state, current.phase) {
            (ActivityState::Busy, Phase::Busy) => *current,
            (ActivityState::Busy, _) => SeatActivity {
                phase: Phase::Busy,
                turn: current.turn.wrapping_add(1),
            },
            (ActivityState::Idle, Phase::Busy) => SeatActivity {
                phase: Phase::TurnEnded,
                turn: current.turn,
            },
            (ActivityState::Idle, _) => *current,
        };
        let changed = next != *current;
        *current = next;
        changed
    });
    previous
}

/// What a wait does with the inbox page it just read.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Gate {
    Return,
    Hold,
    /// The seat is busy; a timeout reports `busy` instead of mail or `empty`.
    Busy,
}

/// A wait's view of one external seat's reported turn state. Holds only a
/// weak sender so a retired lease drops its state and wakes the waiter.
pub(crate) struct Watch {
    sender: Weak<watch::Sender<SeatActivity>>,
    receiver: watch::Receiver<SeatActivity>,
}

impl Watch {
    pub(crate) fn new(sender: &ActivitySender) -> Self {
        Self {
            sender: Arc::downgrade(sender),
            receiver: sender.subscribe(),
        }
    }

    /// Sample the state. Call this before reading the inbox, so the page
    /// reflects every read or dismissal that happened before the report.
    pub(crate) fn observe(&mut self) -> SeatActivity {
        *self.receiver.borrow_and_update()
    }

    /// Decide from a page read after `seen` was observed. `None` means the
    /// state moved on: observe again and re-read before deciding.
    pub(crate) fn decide(
        &mut self,
        seen: SeatActivity,
        has_ids: bool,
        fresh: bool,
    ) -> Option<Gate> {
        match seen.phase {
            // The state moved while the page was read: the page may predate an
            // ended turn (Busy) or a started one (Idle), so it decides nothing.
            Phase::Busy | Phase::Idle if self.receiver.has_changed().unwrap_or(true) => None,
            Phase::Busy => Some(Gate::Busy),
            Phase::Idle => Some(untracked(has_ids, fresh)),
            Phase::TurnEnded => {
                let Some(sender) = self.sender.upgrade() else {
                    // The lease retired after the read: retry, so the caller
                    // re-resolves the authoritative lease and refuses.
                    return None;
                };
                let consumed = sender.send_if_modified(|current| {
                    let exact = *current == seen;
                    if exact {
                        current.phase = Phase::Idle;
                    }
                    exact
                });
                if !consumed {
                    return None;
                }
                // Mark only our own write as seen; anything newer means retry.
                let wrote = SeatActivity {
                    phase: Phase::Idle,
                    turn: seen.turn,
                };
                if *self.receiver.borrow_and_update() != wrote {
                    return None;
                }
                Some(if has_ids { Gate::Return } else { Gate::Hold })
            }
        }
    }

    /// The lease that owned this state retired (revoked, replaced or expired).
    pub(crate) fn retired(&self) -> bool {
        self.sender.strong_count() == 0
    }

    /// Resolve when the reported state changes. An error means the lease and
    /// its state are gone; the caller re-reads and its authority check refuses.
    pub(crate) async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        self.receiver.changed().await
    }
}

/// Gate for a seat without reported turn state (managed seats observe turns
/// themselves): return only fresh mail.
pub(crate) fn untracked(has_ids: bool, fresh: bool) -> Gate {
    if has_ids && fresh {
        Gate::Return
    } else {
        Gate::Hold
    }
}
