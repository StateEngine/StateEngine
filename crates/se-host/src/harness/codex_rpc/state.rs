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
type Reply = std::result::Result<Value, rpc::RequestFailure>;
/// Bounded diagnostics for events which cannot change this retained binding.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IgnoredNotifications {
    pub foreign_threads: u64,
    pub foreign_turns: u64,
    pub untracked_own_turns: u64,
    pub before_binding: u64,
}
#[derive(Default)]
pub(super) struct State {
    pub progress: crate::harness::progress::Progress,
    pub capture: bool,
    pub restoring: bool,
    pub ignored: IgnoredNotifications,
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
    pub(crate) fn activity(&self) -> Result<se_core::ops::ProviderActivityView> {
        Ok(self
            .state
            .lock()
            .map_err(|_| poisoned())?
            .progress
            .view("Codex"))
    }
    pub fn ignored_notifications(&self) -> Result<IgnoredNotifications> {
        Ok(self.state.lock().map_err(|_| poisoned())?.ignored)
    }
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
    /// Retained source bytes only, including after EOF or a failed transport.
    /// Final capture must independently prove them against the pinned rollout
    /// and committed items before acknowledgement. This does not clear failure
    /// or grant authority to issue further input on the broken connection.
    pub fn retained_notifications(&self) -> Result<Vec<Value>> {
        let state = self.state.lock().map_err(|_| poisoned())?;
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
            state.progress.terminal("failed", false);
            state.failure.get_or_insert_with(|| error.body.clone());
            for (_, reply) in std::mem::take(&mut state.pending) {
                let _ = reply.send(Err(SeError::from(error.body.clone()).into()));
            }
        }
        self.completion.nudge();
    }
    pub(super) fn observe_at(
        &self,
        method: String,
        params: Value,
        observed_at: std::time::Instant,
    ) -> Result<()> {
        #[cfg(feature = "remote")]
        self.observe_live(&method, &params, observed_at);
        #[cfg(not(feature = "remote"))]
        let _ = observed_at;
        if self
            .state
            .lock()
            .map_err(|_| poisoned())?
            .observe(method, params)?
        {
            self.completion.nudge();
        }
        Ok(())
    }
}
impl State {
    fn retain(&mut self, event: Value) -> Result<()> {
        let size = encoded_size(&event)?;
        if self.canonical.len() >= 128
            || size > (2 * wire::MAX_LINE_BYTES).saturating_sub(self.canonical_bytes)
        {
            return Err(se_core::scope::unreadable(
                "Codex capture queue",
                "canonical notification capacity reached; preserve the trusted rollout and committed cursor for catch-up",
            ));
        }
        self.canonical_bytes += size;
        self.canonical.push_back(event);
        Ok(())
    }
    #[cfg(any(unix, test))]
    pub(super) fn restore(&mut self, response: &Value) -> Result<()> {
        let invalid = || {
            SeError::invalid(
                "Codex recovery snapshot",
                "the exact original thread with a bounded, consistent current turn",
            )
        };
        if !self.restoring
            || self.conversation.as_ref().map(|id| id.as_str())
                != response.pointer("/thread/id").and_then(Value::as_str)
        {
            return Err(invalid());
        }
        let turns = response
            .pointer("/thread/turns")
            .and_then(Value::as_array)
            .ok_or_else(invalid)?;
        let mut active = None;
        let mut completed = VecDeque::new();
        for turn in turns {
            let id = turn
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty() && id.len() <= 512 && !id.chars().any(char::is_control))
                .ok_or_else(invalid)?;
            match turn.get("status").and_then(Value::as_str) {
                Some("inProgress") if active.is_none() => active = Some(id.to_owned()),
                Some("completed" | "failed" | "interrupted") => {
                    if completed.len() == 64 {
                        completed.pop_front();
                    }
                    completed.push_back(id.to_owned());
                }
                _ => return Err(invalid()),
            }
        }
        match response
            .pointer("/thread/status/type")
            .and_then(Value::as_str)
        {
            Some("active") if active.is_some() => (),
            Some("idle") if active.is_none() => (),
            _ => return Err(invalid()),
        }
        if active.is_some() {
            self.progress.offered();
        } else if let Some(turn) = turns.last() {
            self.progress.terminal(
                turn.get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("failed"),
                crate::harness::progress::codex_authentication(&turn["error"]),
            );
        }
        self.active_turn = active;
        self.completed = completed;
        self.restoring = false;
        let pending = std::mem::take(&mut self.canonical);
        self.canonical_bytes = 0;
        for event in pending {
            let method = event
                .get("method")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?
                .to_owned();
            let params = event.get("params").cloned().ok_or_else(invalid)?;
            self.observe(method, params)?;
        }
        Ok(())
    }
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    fn observe(&mut self, method: String, params: Value) -> Result<bool> {
        if !self.restoring
            && self.conversation.as_ref().is_some_and(|id| {
                params.get("threadId").and_then(Value::as_str) == Some(id.as_str())
            })
            && self
                .active_turn
                .as_deref()
                .is_some_and(|id| params.get("turnId").and_then(Value::as_str) == Some(id))
        {
            if method == "error" {
                let auth = crate::harness::progress::codex_authentication(&params["error"]);
                if auth && params.get("willRetry").and_then(Value::as_bool) == Some(true) {
                    self.progress.retrying_authentication();
                } else if auth || params.get("willRetry").and_then(Value::as_bool) == Some(false) {
                    self.progress.terminal("failed", auth);
                }
            } else if method.starts_with("item/") {
                self.progress.event();
            }
        }
        if !matches!(
            method.as_str(),
            "turn/started" | "turn/completed" | "item/completed"
        ) {
            return Ok(false);
        }
        let thread = params
            .get("threadId")
            .and_then(Value::as_str)
            .ok_or_else(|| SeError::invalid("Codex event", "the actual threadId"))?;
        let state = self;
        match state.conversation.as_ref() {
            None => {
                state.ignored.before_binding = state.ignored.before_binding.saturating_add(1);
                return Ok(false);
            }
            Some(actual) if actual.as_str() != thread => {
                state.ignored.foreign_threads = state.ignored.foreign_threads.saturating_add(1);
                return Ok(false);
            }
            Some(_) => (),
        }
        if state.restoring {
            state.retain(json!({"method":method,"params":params}))?;
            return Ok(false);
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
                    state.ignored.foreign_turns = state.ignored.foreign_turns.saturating_add(1);
                    return Ok(false);
                }
                state.active_turn = Some(id);
                state.progress.offered();
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
                    state.ignored.foreign_turns = state.ignored.foreign_turns.saturating_add(1);
                    return Ok(false);
                }
                if state.active_turn.as_ref() != Some(&id) {
                    state.ignored.untracked_own_turns =
                        state.ignored.untracked_own_turns.saturating_add(1);
                    return Ok(false);
                }
                state.active_turn = None;
                state.progress.terminal(
                    params
                        .pointer("/turn/status")
                        .and_then(Value::as_str)
                        .unwrap_or("failed"),
                    crate::harness::progress::codex_authentication(&params["turn"]["error"]),
                );
                if state.completed.len() >= 64 {
                    state.completed.pop_front();
                }
                state.completed.push_back(id);
            }
        }
        if method == "item/completed" {
            let turn = params
                .get("turnId")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty() && id.len() <= 512)
                .ok_or_else(|| SeError::invalid("Codex item turn", "a bounded actual turnId"))?;
            if state.active_turn.as_deref() != Some(turn)
                && !state.completed.iter().any(|id| id == turn)
            {
                if state.active_turn.is_some() {
                    state.ignored.foreign_turns = state.ignored.foreign_turns.saturating_add(1);
                } else {
                    state.ignored.untracked_own_turns =
                        state.ignored.untracked_own_turns.saturating_add(1);
                }
                return Ok(false);
            }
        }
        if state.capture && method != "turn/started" {
            state.retain(json!({"method":method,"params":params}))?;
        }
        Ok(true)
    }
}
fn encoded_size(value: &Value) -> Result<usize> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|e| se_core::scope::unreadable("Codex event encoding", &e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state(capture: bool) -> Result<State> {
        Ok(State {
            capture,
            conversation: Some(ProviderSessionId::new("main-thread")?),
            active_turn: Some("main-turn".into()),
            ..Default::default()
        })
    }
    #[test]
    fn restart_snapshot_replays_a_completion_received_during_resume() -> Result<()> {
        let mut state = state(true)?;
        state.restoring = true;
        state.active_turn = None;
        state.observe(
            "item/completed".into(),
            json!({"threadId":"main-thread","turnId":"main-turn","item":{"id":"reply"}}),
        )?;
        state.observe(
            "turn/completed".into(),
            json!({"threadId":"main-thread","turn":{"id":"main-turn","status":"completed"}}),
        )?;
        state.restore(&json!({"thread":{"id":"main-thread","status":{"type":"active"},"turns":[{"id":"main-turn","status":"inProgress"}]}}))?;
        assert_eq!(state.active_turn, None);
        assert_eq!(state.canonical.len(), 2);
        assert!(!state.restoring);
        Ok(())
    }
    #[test]
    fn restart_snapshot_keeps_a_later_turn_and_refuses_unknown_activity() -> Result<()> {
        let mut state = state(false)?;
        state.restoring = true;
        state.observe(
            "turn/started".into(),
            json!({"threadId":"main-thread","turn":{"id":"next-turn"}}),
        )?;
        state
            .restore(&json!({"thread":{"id":"main-thread","status":{"type":"idle"},"turns":[]}}))?;
        assert_eq!(state.active_turn.as_deref(), Some("next-turn"));
        assert!(state.canonical.is_empty());
        state.restoring = true;
        for response in [
            json!({"thread":{"id":"another-thread","status":{"type":"idle"},"turns":[]}}),
            json!({"thread":{"id":"main-thread","status":{"type":"active"},"turns":[]}}),
            json!({"thread":{"id":"main-thread","status":{"type":"active"},"turns":[{"id":"a","status":"inProgress"},{"id":"b","status":"inProgress"}]}}),
        ] {
            assert!(state.restore(&response).is_err());
            assert!(state.restoring);
        }
        Ok(())
    }
    #[test]
    fn disabled_capture_does_not_accumulate_items_or_terminal_turns() -> Result<()> {
        let mut state = state(false)?;
        for n in 0..256 {
            assert!(state.observe("item/completed".into(), json!({"threadId":"main-thread","turnId":"main-turn","item":{"id":format!("item-{n}")}}))?);
        }
        state.observe(
            "turn/completed".into(),
            json!({"threadId":"main-thread","turn":{"id":"main-turn","status":"completed"}}),
        )?;
        assert!(state.active_turn.is_none());
        assert_eq!(
            state.completed.back().map(String::as_str),
            Some("main-turn")
        );
        assert!(state.canonical.is_empty() && state.canonical_bytes == 0);
        Ok(())
    }
    #[test]
    fn other_threads_and_turns_cannot_change_the_retained_parent() -> Result<()> {
        let mut state = state(true)?;
        for (method, params) in [
            (
                "turn/started",
                json!({"threadId":"sub-agent","turn":{"id":"child-turn"}}),
            ),
            (
                "turn/completed",
                json!({"threadId":"main-thread","turn":{"id":"another-turn","status":"completed"}}),
            ),
            (
                "item/completed",
                json!({"threadId":"main-thread","turnId":"another-turn","item":{"id":"foreign-item"}}),
            ),
        ] {
            assert!(!state.observe(method.into(), params)?);
        }
        assert_eq!(state.active_turn.as_deref(), Some("main-turn"));
        assert!(state.canonical.is_empty() && state.completed.is_empty());
        assert_eq!(state.ignored.foreign_threads, 1);
        assert_eq!(state.ignored.foreign_turns, 2);
        assert!(state.observe(
            "item/completed".into(),
            json!({"threadId":"main-thread","turnId":"main-turn","item":{"id":"actual-item"}})
        )?);
        assert_eq!(state.canonical.len(), 1);
        Ok(())
    }
    #[test]
    fn own_completion_without_a_tracked_turn_is_counted_and_left_to_native_capture() -> Result<()> {
        let mut state = state(true)?;
        state.active_turn = None;
        assert!(!state.observe(
            "item/completed".into(),
            json!({"threadId":"main-thread","turnId":"resumed-turn","item":{"id":"native-item"}})
        )?);
        assert_eq!(state.ignored.untracked_own_turns, 1);
        assert!(state.canonical.is_empty());
        assert!(state.active_turn.is_none());
        Ok(())
    }
    #[test]
    fn enabled_capture_keeps_its_explicit_unacknowledged_capacity_bound() -> Result<()> {
        let mut state = state(true)?;
        for n in 0..128 {
            state.observe("item/completed".into(), json!({"threadId":"main-thread","turnId":"main-turn","item":{"id":format!("item-{n}")}}))?;
        }
        assert!(
            state
                .observe(
                    "item/completed".into(),
                    json!({"threadId":"main-thread","turnId":"main-turn","item":{"id":"overflow"}})
                )
                .is_err()
        );
        assert_eq!(state.canonical.len(), 128);
        Ok(())
    }
}
