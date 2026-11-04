//! Bounded canonical notifications and exact thread/turn state. Deltas are
//! transient; only completed items and terminal turns enter the capture queue.
use super::*;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        Weak,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{Notify, oneshot};
type Reply = std::result::Result<Value, se_types::ErrorBody>;
#[derive(Default)]
pub(super) struct State {
    pub sequence: wire::Requests,
    pub pending: BTreeMap<i64, oneshot::Sender<Reply>>,
    pub conversation: Option<ProviderSessionId>,
    pub active_turn: Option<String>,
    pub completed: VecDeque<String>,
    pub canonical: VecDeque<Value>,
    pub canonical_bytes: usize,
    pub failure: Option<se_types::ErrorBody>,
}
#[derive(Default)]
pub struct Completion {
    pending: AtomicBool,
    wake: Mutex<Option<Weak<Notify>>>,
}
impl Completion {
    pub(crate) fn arm(&self, wake: &Arc<Notify>) -> Result<()> {
        *self.wake.lock().map_err(|_| poisoned())? = Some(Arc::downgrade(wake));
        if self.pending.load(Ordering::Acquire) {
            wake.notify_one();
        }
        Ok(())
    }
    pub(crate) fn take(&self) -> bool {
        self.pending.swap(false, Ordering::AcqRel)
    }
    pub(super) fn nudge(&self) {
        self.pending.store(true, Ordering::Release);
        if let Ok(wake) = self.wake.lock()
            && let Some(wake) = wake.as_ref().and_then(Weak::upgrade)
        {
            wake.notify_one();
        }
    }
}
impl Binding {
    pub fn conversation(&self) -> Result<ProviderSessionId> {
        self.state
            .lock()
            .map_err(|_| poisoned())?
            .conversation
            .clone()
            .ok_or_else(|| SeError::invalid("Codex binding", "the actual initialized thread"))
    }
    pub fn active_turn(&self) -> Result<Option<String>> {
        let state = self.state.lock().map_err(|_| poisoned())?;
        if let Some(error) = &state.failure {
            return Err(error.clone().into());
        }
        Ok(state.active_turn.clone())
    }
    /// Capture peeks until its durable commit succeeds, then acknowledges the
    /// exact prefix. A failed consumer never loses provider events on read.
    pub fn notifications(&self) -> Result<Vec<Value>> {
        let state = self.state.lock().map_err(|_| poisoned())?;
        if let Some(error) = &state.failure {
            return Err(error.clone().into());
        }
        Ok(state.canonical.iter().cloned().collect())
    }
    pub fn acknowledge_notifications(&self, committed: &[Value]) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| poisoned())?;
        if committed.len() > state.canonical.len()
            || !state.canonical.iter().take(committed.len()).eq(committed)
        {
            return Err(SeError::invalid(
                "Codex capture acknowledgement",
                "the exact durably committed canonical prefix",
            ));
        }
        for _ in committed {
            if let Some(value) = state.canonical.pop_front() {
                state.canonical_bytes = state.canonical_bytes.saturating_sub(encoded_size(&value)?);
            }
        }
        Ok(())
    }
    pub(super) fn fail(&self, error: SeError) {
        if let Ok(mut state) = self.state.lock() {
            state.failure.get_or_insert_with(|| error.body.clone());
            for (_, reply) in std::mem::take(&mut state.pending) {
                let _ = reply.send(Err(error.body.clone()));
            }
        }
        self.completion.nudge();
    }
    pub(super) fn observe(&self, method: String, params: Value) -> Result<()> {
        if !matches!(
            method.as_str(),
            "turn/started" | "turn/completed" | "item/completed"
        ) {
            return Ok(());
        }
        let thread = params
            .get("threadId")
            .and_then(Value::as_str)
            .ok_or_else(|| SeError::invalid("Codex event", "the actual threadId"))?;
        let mut state = self.state.lock().map_err(|_| poisoned())?;
        if state
            .conversation
            .as_ref()
            .is_none_or(|actual| actual.as_str() != thread)
        {
            return Err(SeError::invalid(
                "Codex event thread",
                "the exact initialized conversation",
            ));
        }
        if method.starts_with("turn/") {
            let id = params
                .pointer("/turn/id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty() && id.len() <= 512)
                .ok_or_else(|| SeError::invalid("Codex event turn", "a bounded actual turn.id"))?
                .to_owned();
            if method == "turn/started" {
                if state
                    .active_turn
                    .as_ref()
                    .is_some_and(|active| active != &id)
                {
                    return Err(SeError::invalid(
                        "Codex turn state",
                        "one exact active turn",
                    ));
                }
                state.active_turn = Some(id);
            } else {
                if !matches!(
                    params.pointer("/turn/status").and_then(Value::as_str),
                    Some("completed" | "interrupted" | "failed")
                ) {
                    return Err(SeError::invalid(
                        "Codex turn completion",
                        "an actual terminal provider status",
                    ));
                }
                if state
                    .active_turn
                    .as_ref()
                    .is_some_and(|active| active != &id)
                {
                    return Err(SeError::invalid(
                        "Codex turn completion",
                        "the exact active turn",
                    ));
                }
                state.active_turn = None;
                if state.completed.len() >= 64 {
                    state.completed.pop_front();
                }
                state.completed.push_back(id);
            }
        }
        if method != "turn/started" {
            let event = serde_json::json!({"method":method,"params":params});
            let size = encoded_size(&event)?;
            if state.canonical.len() >= 128
                || size > (2 * wire::MAX_LINE_BYTES).saturating_sub(state.canonical_bytes)
            {
                return Err(se_core::scope::unreadable(
                    "Codex capture queue",
                    "canonical notification capacity reached; preserve the trusted rollout and committed cursor for catch-up",
                ));
            }
            state.canonical_bytes += size;
            state.canonical.push_back(event);
        }
        drop(state);
        self.completion.nudge();
        Ok(())
    }
}
fn encoded_size(value: &Value) -> Result<usize> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|e| se_core::scope::unreadable("Codex event encoding", &e.to_string()))
}
