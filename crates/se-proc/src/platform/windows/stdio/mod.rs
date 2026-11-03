mod binding;
mod control;
mod io;
mod pipes;
mod state;
use super::{
    identity::*,
    notify::{Collector, CompletionQueue, CompletionTarget},
};
use crate::{support::*, *};
pub(crate) use state::Budget;
use state::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};
use windows_sys::Win32::Foundation::*;

/// The arena and collector own this object. Public port/ticket references contain
/// only a revocable arena key; dropping one never drops native ownership.
pub(crate) struct NativeStdio {
    state: Mutex<State>,
    queue: OnceLock<CompletionQueue>,
    budget: Arc<Budget>,
}
impl NativeStdio {
    pub(super) fn create(
        collector: &Collector,
        budget: Arc<Budget>,
        config: &StdioConfig,
    ) -> ProcResult<Arc<Self>> {
        let state = State::new(config);
        state.check_limits(config.limits)?;
        let port = Arc::new(Self {
            state: Mutex::new(state),
            queue: OnceLock::new(),
            budget,
        });
        let queue = collector.register_io(port.clone())?;
        // This object is not published until its queue is installed; the
        // collector cannot have any native packets before pipe initialization.
        if port.queue.set(queue).is_err() {
            return Err(input("stdio", "completion queue already installed"));
        }
        Ok(port)
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // No foreign calls happen under this lock. A panic quarantines the
        // port, while cleanup still recovers and drains its retained requests.
        self.state.lock().unwrap_or_else(|e| {
            let mut state = e.into_inner();
            state.failure = Some(error(
                ProcErrorCode::LockPoisoned,
                ProcErrorDetail::Input {
                    field: "provider stdio".into(),
                    reason: "native stream state lock was poisoned".into(),
                },
            ));
            state
        })
    }
    fn queue(&self) -> ProcResult<&CompletionQueue> {
        self.queue
            .get()
            .ok_or_else(|| input("stdio", "completion registration is unavailable"))
    }
    fn nudge(&self) {
        if let Some(queue) = self.queue.get() {
            queue.nudge();
        }
    }
    pub fn initialize(&self) -> ProcResult<StandardIo> {
        pipes::initialize(self)
    }
    pub fn fail(&self, error: ProcError) {
        self.lock().failure = Some(error);
        self.abandon_partial();
    }
    pub fn snapshot(&self) -> (StdioIdentity, u64, Vec<u64>, bool, StdioBinding) {
        let state = self.lock();
        (
            state.identity.clone(),
            state.binding_serial,
            state
                .operations
                .iter()
                .filter_map(|(id, op)| (!matches!(op.kind, Kind::Connect(_))).then_some(*id))
                .collect(),
            state.handles[0].is_none(),
            state.binding_state(),
        )
    }
    pub fn validate(&self, identity: &StdioIdentity, binding: u64) -> ProcResult<()> {
        let state = self.lock();
        if &state.identity != identity || state.binding_serial != binding || state.released {
            return Err(transition("stale stream identity or binding"));
        }
        Ok(())
    }
    pub fn attach(&self, config: &StdioConfig) -> ProcResult<()> {
        let mut state = self.lock();
        if state.released
            || state.abandoned
            || (state.bound && state.binding_state() == StdioBinding::Draining)
        {
            return Err(transition("port cannot bind while released or draining"));
        }
        state.check_limits(config.limits)?;
        let next = state
            .binding_serial
            .checked_add(1)
            .ok_or_else(|| capacity("stream binding identifiers", u64::MAX))?;
        state.binding.disable();
        state.old_binding = Some(state.binding.clone());
        state.binding = binding::Binding::new(config);
        state.identity = config.identity.clone();
        state.limits = config.limits;
        state.binding_serial = next;
        state.bound = true;
        state.binding_notice = true;
        drop(state);
        self.nudge();
        Ok(())
    }
    pub fn fence(&self, generation: GenerationId) -> ProcResult<()> {
        let mut state = self.lock();
        let next = state
            .binding_serial
            .checked_add(1)
            .ok_or_else(|| capacity("stream binding identifiers", u64::MAX))?;
        state.binding.disable();
        state.old_binding = Some(state.binding.clone());
        state.bound = false;
        state.binding_serial = next;
        state.identity.generation = generation;
        Ok(())
    }
    pub fn launch_ready(&self) -> ProcResult<()> {
        let state = self.lock();
        state.ready()?;
        if state.all_gated {
            return Err(transition("stream shutdown began before vendor execution"));
        }
        Ok(())
    }
    pub fn released(&self) -> bool {
        self.lock().released
    }
}
impl CompletionTarget for NativeStdio {
    fn completed(&self, address: usize, bytes: u32, status: u32) {
        if address != 0 {
            self.complete_native(address, bytes, status);
        }
        self.advance_close();
        let (binding, notices) = {
            let mut state = self.lock();
            if state.binding_state() != StdioBinding::Ready {
                return;
            }
            state.old_binding = None;
            let mut notices = std::mem::take(&mut state.notices)
                .into_iter()
                .map(|id| StdioNoticeKind::Operation(StdioOperationId(id)))
                .collect::<Vec<_>>();
            if state.binding_notice {
                state.binding_notice = false;
                notices.push(StdioNoticeKind::BindingChanged);
            }
            (state.binding.clone(), notices)
        };
        for notice in notices {
            if !binding.fire(notice) {
                self.lock().failure = Some(error(
                    ProcErrorCode::CallbackPanicked,
                    ProcErrorDetail::Input {
                        field: "provider stdio".into(),
                        reason: "stream notification callback panicked".into(),
                    },
                ));
                binding.disable();
                break;
            }
        }
        // A callback may have raced a successor binding. Its return is the
        // event that lets that binding become Ready without a polling timer.
        let pending = self.lock().binding_notice;
        if pending {
            self.nudge();
        }
    }
    fn shutdown(&self) {
        {
            let mut state = self.lock();
            state.abandoned = true;
            state.all_gated = true;
            state.write_gated = true;
            state.binding.disable();
        }
        self.cancel_all();
        self.advance_close();
    }
    fn drained(&self) -> bool {
        let state = self.lock();
        state.abandoned && !state.native_pending() && state.handles.iter().all(Option::is_none)
    }
}
