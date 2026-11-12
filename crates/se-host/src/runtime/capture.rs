//! Trusted transcript bindings and the native hook-to-writer consumer. A hook
//! can only signal an existing pin, never create one or replace its identity.
use super::timings::{self, Mode};
use super::*;
use crate::client::lease::Deadline;
use se_types::{Read, Result, SeError, SessionId};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, Weak},
};
mod batch;
mod binding;
mod claude;
mod drain;
mod persistent;
mod signal;
mod source;
mod verification;
use sha2::Digest;
struct BoundTranscript {
    binding: crate::TranscriptPin,
    source: se_store::RecordId,
    pin: se_proc::NativeSourcePin,
    queue: std::collections::VecDeque<(u64, source::queue::Tracker)>,
    tools: std::collections::VecDeque<(u64, crate::harness::tool_capture::claude::Tracker)>,
}
#[derive(Clone)]
pub struct TranscriptBindings {
    maximum: usize,
    pins: Arc<Mutex<Registry>>,
    retirements: Arc<tokio::sync::Mutex<()>>,
    observed_serial: Arc<Mutex<HashMap<SessionId, Weak<tokio::sync::Mutex<()>>>>>,
}
#[derive(Default)]
struct Registry {
    active: HashMap<SessionId, Arc<Mutex<BoundTranscript>>>,
    failed: HashMap<SessionId, se_types::ErrorBody>,
    publishing: HashSet<SessionId>,
    unavailable: Option<se_types::ErrorBody>,
}
#[derive(Clone, Debug)]
pub struct CaptureUnavailable {
    pub session: Option<SessionId>,
    pub error: se_types::ErrorBody,
}
#[derive(Clone, Debug, Default)]
pub struct CaptureRestoreReport {
    pub restored: usize,
    pub unavailable: Vec<CaptureUnavailable>,
}
impl TranscriptBindings {
    pub(crate) fn new(maximum: usize) -> Self {
        Self {
            maximum,
            pins: Arc::new(Mutex::new(Registry::default())),
            retirements: Arc::default(),
            observed_serial: Arc::default(),
        }
    }
    pub(crate) fn identities(&self) -> Result<Vec<crate::SessionIdentity>> {
        self.registry()?
            .active
            .values()
            .map(|source| Ok(try_guard(source)?.binding.identity.clone()))
            .collect()
    }
    pub(crate) fn observed_serial(
        &self,
        session: &SessionId,
    ) -> Result<Arc<tokio::sync::Mutex<()>>> {
        let mut serial = self.observed_serial.lock().map_err(|_| {
            se_core::scope::unreadable(
                "observed session",
                "session scheduling registry is poisoned",
            )
        })?;
        serial.retain(|_, value| value.strong_count() > 0);
        if let Some(value) = serial.get(session).and_then(Weak::upgrade) {
            return Ok(value);
        }
        if serial.len() >= self.maximum {
            return Err(busy());
        }
        let value = Arc::new(tokio::sync::Mutex::new(()));
        serial.insert(session.clone(), Arc::downgrade(&value));
        Ok(value)
    }
    // Only bounded in-memory registry work holds this lock. Per-source scan
    // locks retain their existing nonblocking behavior for the same transcript.
    fn registry(&self) -> Result<std::sync::MutexGuard<'_, Registry>> {
        self.pins.lock().map_err(|_| {
            se_core::scope::unreadable(
                "transcript binding",
                "the binding registry is poisoned; preserve retained custody",
            )
        })
    }
    fn insert(&self, source: BoundTranscript, persist: Option<&HostLease>) -> Result<()> {
        self.insert_published(source, |source| match persist {
            Some(lease) => persistent::publish(lease, source),
            None => Ok(()),
        })
    }
    fn insert_published(
        &self,
        source: BoundTranscript,
        publish: impl FnOnce(&BoundTranscript) -> Result<()>,
    ) -> Result<()> {
        let session = source.binding.identity.session.clone();
        let previous_failure = {
            let mut pins = self.registry()?;
            if pins.active.contains_key(&session) || pins.publishing.contains(&session) {
                return Err(SeError::invalid(
                    "transcript rebind",
                    "an explicit trusted rotation transition; a hook cannot replace a pin",
                ));
            }
            if pins.active.len() + pins.failed.len() + pins.publishing.len() >= self.maximum
                && !pins.failed.contains_key(&session)
            {
                return Err(busy());
            }
            // Reserve this exact session and its capacity before releasing the
            // registry. Durable I/O must not make unrelated launches refuse.
            pins.publishing.insert(session.clone());
            pins.failed.remove(&session)
        };
        let published = publish(&source);
        let mut pins = self.registry()?;
        pins.publishing.remove(&session);
        if let Err(error) = published {
            if let Some(previous) = previous_failure {
                pins.failed.insert(session, previous);
            }
            return Err(error);
        }
        pins.active.insert(session, Arc::new(Mutex::new(source)));
        Ok(())
    }
    fn quarantine(&self, session: Option<SessionId>, error: se_types::ErrorBody) -> Result<()> {
        let mut pins = self.registry()?;
        if let Some(session) = session {
            if pins.active.contains_key(&session) || pins.publishing.contains(&session) {
                return Err(SeError::invalid(
                    "capture quarantine",
                    "an unbound failed restoration, preserving any active pin",
                ));
            }
            if !pins.failed.contains_key(&session)
                && pins.failed.len() + pins.active.len() + pins.publishing.len() >= self.maximum
            {
                return Err(busy());
            }
            pins.failed.insert(session, error);
        } else {
            pins.unavailable = Some(error);
        }
        Ok(())
    }
    fn get(&self, session: &SessionId) -> Result<Arc<Mutex<BoundTranscript>>> {
        let pins = self.registry()?;
        if let Some(pin) = pins.active.get(session) {
            return Ok(Arc::clone(pin));
        }
        if pins.publishing.contains(session) {
            return Err(busy());
        }
        if let Some(error) = pins.failed.get(session).or(pins.unavailable.as_ref()) {
            return Err(error.clone().into());
        }
        Err(se_core::scope::unreadable(
            "transcript pin",
            "no trusted provider/owner binding exists; the hook pathname grants no read authority",
        ))
    }
}
impl HostedRuntime {
    /// Called only by trusted provider launch/owner-adoption code with its
    /// retained native pin. No hook/IPC payload is decoded into this method.
    pub async fn bind_transcript(
        &self,
        binding: crate::TranscriptPin,
        source: se_store::RecordId,
        pin: se_proc::NativeSourcePin,
        deadline: &Deadline,
    ) -> Result<()> {
        self.capture_handle()
            .bind(binding, source, pin, deadline)
            .await
    }
    /// The trusted capture handle the native coordinator retains: transcript
    /// binding at launch and the final catch-up at stop.
    /// Trusted capture never dispatches a native plan, so the handle carries a
    /// detached empty custody slot: a coordinator retaining it holds no strong
    /// path back to itself through the installed custody executor. The handle
    /// borrows the lease between binds; retaining an idle coordinator cannot
    /// extend the runtime lease beyond completed shutdown.
    pub fn capture_handle(&self) -> CaptureHandle {
        CaptureHandle {
            execution: ExecutionContext {
                custody: Arc::default(),
                ..self.execution.clone()
            },
            sources: self.sources.clone(),
            lease: Arc::downgrade(&self.lease),
            fenced: Arc::clone(&self.capture_fenced),
        }
    }
}
impl HostedRuntime {
    /// Reopen only metadata published by a prior trusted bind. Hook paths never
    /// enter this recovery reader, and every protected session/source is checked.
    pub async fn restore_transcripts(&self, deadline: &Deadline) -> Result<CaptureRestoreReport> {
        let context = self.execution.clone();
        let lease = Arc::clone(&self.lease);
        let pins = self.sources.clone();
        let bound = deadline.clone();
        self.execution
            .blocking
            .run_owned(deadline, move || {
                persistent::restore(&context, &lease, &pins, &bound)
            })
            .await
    }
}
impl HostedRouter {
    pub async fn execute_call(
        &self,
        call: RoutedCall,
        deadline: &Deadline,
    ) -> Result<ExecutedCall> {
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        let _memory_reclaim = self
            .memory_reclaim
            .as_ref()
            .map(super::memory::MemoryReclaim::after_work);
        self.check_open()?;
        let (admitted, hook) = match call {
            RoutedCall::Prepared(prepared) => {
                return prepared
                    .execute(self.execution.clone(), Default::default())
                    .await;
            }
            RoutedCall::Deferred { admitted, hook } => (*admitted, hook.map(|hook| *hook)),
        };
        if matches!(
            &admitted.input,
            HostedInput::Operation(se_core::ops::AnyOp::ClientWatch(_))
        ) {
            return super::local_client::watch(self, admitted, deadline).await;
        }
        let Some(hook) = hook else {
            return execute(
                self.execution.clone(),
                ExecutionCall {
                    admitted,
                    deadline: deadline.clone(),
                },
            )
            .await;
        };
        let HostedCall {
            admission,
            terminal,
            selections,
            ..
        } = admitted;
        self.capturing()
            .signal(admission, terminal, selections, hook, deadline)
            .await
    }
    fn capturing(&self) -> Capturing<'_> {
        Capturing {
            execution: &self.execution,
            sources: &self.sources,
            fenced: &self.fenced,
            final_capture: false,
            recovery_owner: None,
            retry_busy: true,
        }
    }
}
fn native_error(error: se_proc::StateFileError) -> SeError {
    se_core::scope::unreadable("retained transcript source", &error.to_string()).with_cause(error)
}
fn busy() -> SeError {
    SeError::new(se_types::Detail::StoreBusy(se_types::details::StoreBusy {
        waited_ms: 0,
        replay: None,
        reason: "transcript binding or bounded source capacity is occupied".into(),
        next_step:
            "Wait for the current bounded capture to finish and retry the original hook identity."
                .into(),
    }))
}

fn try_guard<T>(value: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>> {
    match value.try_lock() {
        Ok(guard) => Ok(guard),
        Err(std::sync::TryLockError::WouldBlock) => Err(busy()),
        Err(std::sync::TryLockError::Poisoned(_)) => Err(se_core::scope::unreadable(
            "transcript binding",
            "a prior source worker failed; preserve the retained pin and committed cursor",
        )),
    }
}

fn empty_capture(kind: crate::ClaudeHookKind) -> ExecutedCall {
    let checked = if matches!(kind, crate::ClaudeHookKind::SessionStart) {
        "Session-start validated the trusted binding and protected session; it performs no capture scan."
    } else {
        "No complete new text record at the verified pinned source; an incomplete final line remains pending a real provider signal."
    };
    ExecutedCall {
        host_phases: Default::default(),
        output: se_core::ops::HookResult {
            stdout: String::new(),
            captured: Read::Absent {
                checked: checked.into(),
            },
            failure: None,
            receipt: None,
        }
        .into(),
        write_timings: None,
        committed: None,
        capture_commits: Vec::new(),
        capture_keys: Vec::new(),
    }
}

/// Capture through one retained source pin, shared by the hook route and the
/// coordinator's handle; the drain fence stops it like any admitted call.
struct Capturing<'a> {
    execution: &'a ExecutionContext,
    sources: &'a TranscriptBindings,
    fenced: &'a std::sync::atomic::AtomicBool,
    final_capture: bool,
    recovery_owner: Option<se_types::HumanId>,
    retry_busy: bool,
}
impl Capturing<'_> {
    fn check_open(&self) -> Result<()> {
        if self.fenced.load(std::sync::atomic::Ordering::Acquire) {
            return Err(SeError::invalid(
                "host admission",
                "a ready runtime before its drain fence",
            ));
        }
        Ok(())
    }
}

/// Held by the native coordinator; valid for this hosted generation only.
#[derive(Clone)]
pub struct CaptureHandle {
    execution: ExecutionContext,
    sources: TranscriptBindings,
    lease: Weak<HostLease>,
    fenced: Arc<std::sync::atomic::AtomicBool>,
}
impl CaptureHandle {
    pub(crate) fn identities(&self) -> Result<Vec<crate::SessionIdentity>> {
        self.sources.identities()
    }
    pub(crate) fn from_router(router: &HostedRouter) -> Self {
        Self {
            execution: router.execution.clone(),
            sources: router.sources.clone(),
            lease: router.context.lease.clone(),
            fenced: router.fenced.clone(),
        }
    }
}
impl CaptureHandle {
    pub(crate) fn in_background(&self) -> Self {
        let mut handle = self.clone();
        handle.execution.blocking = self.execution.blocking.background_handle();
        handle
    }
    /// Called only by trusted provider launch/owner-adoption code with its
    /// retained native pin. No hook/IPC payload is decoded into this method.
    pub async fn bind(
        &self,
        binding: crate::TranscriptPin,
        source: se_store::RecordId,
        pin: se_proc::NativeSourcePin,
        deadline: &Deadline,
    ) -> Result<()> {
        let pins = self.sources.clone();
        let lease = self.lease.upgrade().ok_or_else(|| {
            SeError::new(se_types::Detail::RuntimeNotRunning(
                se_types::details::RuntimeNotRunning {
                    op: "trusted transcript bind".into(),
                    reason: "this retained handle's original host lease has been released".into(),
                },
            ))
        })?;
        let context = self.execution.clone();
        let bound = deadline.clone();
        self.execution
            .blocking
            .run_owned(deadline, move || {
                let mut source = BoundTranscript {
                    binding,
                    source,
                    pin,
                    queue: Default::default(),
                    tools: Default::default(),
                };
                let path = source.binding.path.to_local()?;
                if path != source.pin.path()
                    || source.binding.file_identity
                        != se_types::Sha256::from_bytes(source.pin.identity())
                {
                    return Err(SeError::invalid(
                        "trusted transcript bind",
                        "the exact native path and retained file identity",
                    ));
                }
                source.pin.validate_path(&path).map_err(native_error)?;
                source::validate(&context, &mut source, &bound)?;
                pins.insert(source, Some(&lease))
            })
            .await
    }
    /// Read complete records from the bound source. A live writer may still
    /// be appending its last line, so an incomplete tail remains pending.
    pub async fn catch_up(
        &self,
        admission: se_store::Admission,
        conversation: se_types::ProviderSessionId,
        transcript: se_types::NativePath,
        deadline: &Deadline,
    ) -> Result<ExecutedCall> {
        self.catch_up_inner(admission, conversation, transcript, deadline, None)
            .await
    }
    /// Used only after native exit and empty-scope proof: a partial final line
    /// is broken framing, not a successfully flushed transcript.
    pub(crate) async fn catch_up_final(
        &self,
        admission: se_store::Admission,
        conversation: se_types::ProviderSessionId,
        transcript: se_types::NativePath,
        owner: se_types::HumanId,
        deadline: &Deadline,
    ) -> Result<ExecutedCall> {
        self.catch_up_inner(admission, conversation, transcript, deadline, Some(owner))
            .await
    }
    async fn catch_up_inner(
        &self,
        admission: se_store::Admission,
        conversation: se_types::ProviderSessionId,
        transcript: se_types::NativePath,
        deadline: &Deadline,
        recovery_owner: Option<se_types::HumanId>,
    ) -> Result<ExecutedCall> {
        let capturing = Capturing {
            execution: &self.execution,
            sources: &self.sources,
            fenced: &self.fenced,
            final_capture: recovery_owner.is_some(),
            recovery_owner,
            retry_busy: false,
        };
        let terminal = se_core::admission::HumanTerminal::Refused {
            reason: "a coordinator capture is not an owner terminal".into(),
        };
        let stop = crate::ClaudeHookInput {
            kind: crate::ClaudeHookKind::Stop,
            conversation,
            claimed_transcript: transcript,
            payload: serde_json::Value::Null,
        };
        capturing.drain(admission, terminal, stop, deadline).await
    }
}

#[cfg(test)]
mod registry_tests;

#[cfg(all(test, target_os = "linux"))]
mod retirement_tests;
