//! Slot reservation and cleanup custody bookkeeping for ACP `terminal/*`.
//!
//! Keeps still-starting (`pending`), still-settling (`releasing`), and failed
//! (`unsettled`) terminals counted against `MAX_TERMINALS` and reachable by
//! `close_all` and `Drop` until settlement is witnessed, without destructively
//! discarding unresolved cleanup errors.
use super::TerminalEntry;
use crate::acp::client::Refusal;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tokio::sync::Notify;

/// Maximum concurrent unreleased terminals per ACP conversation.
pub(super) const MAX_TERMINALS: usize = 8;

#[derive(Default)]
pub(super) struct TerminalTable {
    pub(super) closed: bool,
    pub(super) pending: usize,
    pub(super) releasing: usize,
    pub(super) active: BTreeMap<String, Arc<TerminalEntry>>,
    /// Terminals whose kill/reap/join failed or aborted; kept counted and
    /// reachable until a subsequent `close_all` or `Drop` witnesses settlement.
    pub(super) unsettled: BTreeMap<String, (Arc<TerminalEntry>, String)>,
}

impl TerminalTable {
    pub(super) fn occupied_slots(&self) -> usize {
        self.active.len() + self.pending + self.releasing + self.unsettled.len()
    }

    pub(super) fn unsettled_summary(&self) -> Option<String> {
        if self.unsettled.is_empty() {
            return None;
        }
        let errors: Vec<&str> = self
            .unsettled
            .values()
            .map(|(_, err)| err.as_str())
            .collect();
        Some(errors.join("; "))
    }
}

/// RAII custody guard for a terminal currently undergoing kill/reap/join.
/// Keeps the terminal counted against `MAX_TERMINALS` and visible to `close_all`
/// until settlement is witnessed; on failure or panic, retains custody and error
/// in `TerminalTable::unsettled`.
pub(super) struct ReleasingSlot {
    pub(super) id: String,
    pub(super) entry: Arc<TerminalEntry>,
    pub(super) table: Arc<Mutex<TerminalTable>>,
    pub(super) settled: Arc<Notify>,
    pub(super) armed: bool,
}

impl ReleasingSlot {
    pub(super) fn new(
        id: String,
        entry: Arc<TerminalEntry>,
        table: Arc<Mutex<TerminalTable>>,
        settled: Arc<Notify>,
    ) -> Self {
        Self {
            id,
            entry,
            table,
            settled,
            armed: true,
        }
    }

    pub(super) fn finish(mut self, result: Result<(), String>) -> Result<(), String> {
        self.armed = false;
        if let Ok(mut table) = self.table.lock() {
            table.releasing = table.releasing.saturating_sub(1);
            match &result {
                Ok(()) => {
                    table.unsettled.remove(&self.id);
                }
                Err(err) => {
                    table
                        .unsettled
                        .insert(self.id.clone(), (Arc::clone(&self.entry), err.clone()));
                }
            }
        }
        self.settled.notify_waiters();
        result
    }
}

impl Drop for ReleasingSlot {
    fn drop(&mut self) {
        if self.armed {
            if let Ok(mut table) = self.table.lock() {
                table.releasing = table.releasing.saturating_sub(1);
                table.unsettled.insert(
                    self.id.clone(),
                    (
                        Arc::clone(&self.entry),
                        "terminal cleanup aborted before settlement".to_owned(),
                    ),
                );
            }
            self.settled.notify_waiters();
        }
    }
}

/// RAII reservation of one slot in `TerminalTable::pending`. Ensures concurrent
/// `terminal/create` calls never spawn more than `MAX_TERMINALS` processes and
/// `close_all` waits for every in-flight spawn and cleanup to settle.
pub(super) struct PendingSlot {
    pub(super) table: Arc<Mutex<TerminalTable>>,
    pub(super) settled: Arc<Notify>,
    pub(super) armed: bool,
}

impl PendingSlot {
    /// Atomically commit `entry` to `active`, or—if the session closed while
    /// spawning—transfer custody to a `ReleasingSlot` so cleanup runs off the
    /// async executor while staying counted and visible to `close_all`.
    pub(super) fn commit(
        mut self,
        id: String,
        entry: Arc<TerminalEntry>,
    ) -> Result<Option<ReleasingSlot>, Refusal> {
        let mut table = self
            .table
            .lock()
            .map_err(|_| Refusal::failed("terminal table is poisoned"))?;
        table.pending = table.pending.saturating_sub(1);
        self.armed = false;
        if table.closed {
            table.releasing += 1;
            let releasing = ReleasingSlot::new(
                id,
                entry,
                Arc::clone(&self.table),
                Arc::clone(&self.settled),
            );
            drop(table);
            return Ok(Some(releasing));
        }
        table.active.insert(id, entry);
        drop(table);
        self.settled.notify_waiters();
        Ok(None)
    }
}

impl Drop for PendingSlot {
    fn drop(&mut self) {
        if self.armed {
            if let Ok(mut table) = self.table.lock() {
                table.pending = table.pending.saturating_sub(1);
            }
            self.settled.notify_waiters();
        }
    }
}
