//! Trusted transcript bindings and the native hook-to-writer consumer. A hook
//! can only signal an existing pin, never create one or replace its identity.
use super::*;
use crate::client::lease::Deadline;
use se_types::{Read, Result, SeError, SessionId};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
mod claude;
mod persistent;
mod source;
use sha2::Digest;
struct BoundTranscript {
    binding: crate::TranscriptPin,
    source: se_store::RecordId,
    pin: se_proc::NativeSourcePin,
}
#[derive(Clone)]
pub struct TranscriptBindings {
    maximum: usize,
    pins: Arc<Mutex<Registry>>,
}
#[derive(Default)]
struct Registry {
    active: HashMap<SessionId, Arc<Mutex<BoundTranscript>>>,
    failed: HashMap<SessionId, se_types::ErrorBody>,
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
        }
    }
    fn insert(&self, source: BoundTranscript, persist: Option<&HostLease>) -> Result<()> {
        let mut pins = try_guard(&self.pins)?;
        if pins.active.contains_key(&source.binding.identity.session) {
            return Err(SeError::invalid(
                "transcript rebind",
                "an explicit trusted rotation transition; a hook cannot replace a pin",
            ));
        }
        if pins.active.len() + pins.failed.len() >= self.maximum
            && !pins.failed.contains_key(&source.binding.identity.session)
        {
            return Err(busy());
        }
        if let Some(lease) = persist {
            persistent::publish(lease, &source)?;
        }
        pins.failed.remove(&source.binding.identity.session);
        pins.active.insert(
            source.binding.identity.session.clone(),
            Arc::new(Mutex::new(source)),
        );
        Ok(())
    }
    fn quarantine(&self, session: Option<SessionId>, error: se_types::ErrorBody) -> Result<()> {
        let mut pins = try_guard(&self.pins)?;
        if let Some(session) = session {
            if pins.active.contains_key(&session) {
                return Err(SeError::invalid(
                    "capture quarantine",
                    "an unbound failed restoration, preserving any active pin",
                ));
            }
            if !pins.failed.contains_key(&session)
                && pins.failed.len() + pins.active.len() >= self.maximum
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
        let pins = try_guard(&self.pins)?;
        if let Some(pin) = pins.active.get(session) {
            return Ok(Arc::clone(pin));
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
        let pins = self.sources.clone();
        let lease = Arc::clone(&self.lease);
        let context = self.execution.clone();
        let bound = deadline.clone();
        self.execution
            .blocking
            .run_owned(deadline, move || {
                let mut source = BoundTranscript {
                    binding,
                    source,
                    pin,
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
        self.check_open()?;
        let Some(hook) = call.hook else {
            return execute(
                self.execution.clone(),
                ExecutionCall {
                    admitted: call.admitted,
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
        } = call.admitted;
        if selections.is_some() || admission.generation != self.execution.generation.get() {
            return Err(SeError::invalid(
                "capture admission",
                "the exact generation with no CLI selection metadata",
            ));
        }
        let session = admission
            .session
            .as_ref()
            .ok_or_else(|| SeError::invalid("capture session", "an admitted session"))?;
        let pin = self.sources.get(session)?;
        let mut last = None;
        loop {
            self.check_open()?;
            let context = self.execution.clone();
            let admitted = admission.clone();
            let source = Arc::clone(&pin);
            let signal = crate::ClaudeHookInput {
                kind: hook.kind,
                conversation: hook.conversation.clone(),
                claimed_transcript: hook.claimed_transcript.clone(),
                payload: serde_json::Value::Null,
            };
            let bound = deadline.clone();
            let replay = last.is_none();
            let next = self
                .execution
                .blocking
                .run(BlockingClass::Foreground, deadline, move || {
                    let mut pin = try_guard(&source)?;
                    source::next(&context, &admitted, &mut pin, &signal, &bound, replay)
                })
                .await?;
            let Some((capture, replayed)) = next else {
                return Ok(last.unwrap_or_else(|| ExecutedCall {
                    output:se_core::ops::HookResult {
                        stdout:String::new(),captured:Read::Absent {checked:if matches!(hook.kind,crate::ClaudeHookKind::SessionStart) {"Session-start validated the trusted binding and protected session; it performs no capture scan."} else {"No complete new text record at the verified pinned source; an incomplete final line remains pending a real provider signal."}.into()},failure:None,receipt:None,
                    }.into(),write_timings:None,
                }));
            };
            let result = execute(
                self.execution.clone(),
                ExecutionCall {
                    admitted: HostedCall {
                        input: HostedInput::Capture(Box::new(capture)),
                        kernel: se_core::dispatch::Kernel::read_only(),
                        admission: admission.clone(),
                        terminal: terminal.clone(),
                        selections: None,
                    },
                    deadline: deadline.clone(),
                },
            )
            .await?;
            if replayed {
                return Ok(result);
            }
            last = Some(result);
        }
    }
}
fn native_error(error: se_proc::StateFileError) -> SeError {
    se_core::scope::unreadable("retained transcript source", &error.to_string()).with_cause(error)
}
fn busy() -> SeError {
    SeError::new(se_types::Detail::StoreBusy(se_types::details::StoreBusy {
        waited_ms: 0,
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
