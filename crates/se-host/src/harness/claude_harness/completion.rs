//! Stream results are coalesced wakeups only. Captured bodies and vendor turn
//! identities still come exclusively from the retained transcript pin.
use super::*;
use std::{sync::Weak, time::Instant};
use tokio::sync::Notify;

pub(crate) const MAX_LINE: usize = 4 * 1024 * 1024;
#[derive(Default)]
pub(crate) struct Completion {
    progress: Mutex<crate::harness::progress::Progress>,
    pending: Mutex<Option<Instant>>,
    wake: Mutex<Option<Weak<Notify>>>,
    failure: Mutex<Option<se_types::ErrorBody>>,
}
impl Completion {
    pub(crate) fn offered(&self) -> Result<()> {
        self.progress.lock().map_err(|_| poisoned())?.offered();
        Ok(())
    }
    pub(crate) fn activity(&self) -> Result<se_core::ops::ProviderActivityView> {
        Ok(self.progress.lock().map_err(|_| poisoned())?.view("Claude"))
    }
    pub(super) fn inspect(&self, line: &[u8], conversation: &ProviderSessionId) {
        self.inspect_at(line, conversation, Instant::now());
    }
    fn inspect_at(&self, line: &[u8], conversation: &ProviderSessionId, observed_at: Instant) {
        #[derive(serde::Deserialize)]
        struct Frame {
            #[serde(rename = "type")]
            kind: String,
            session_id: Option<String>,
            #[serde(default)]
            is_error: bool,
        }
        let result = serde_json::from_slice::<Frame>(line)
            .map_err(|_| {
                SeError::invalid(
                    "Claude completion signal",
                    "a bounded complete stream-json frame",
                )
            })
            .and_then(|frame| {
                if frame.kind != "result" {
                    if frame.session_id.as_deref() == Some(conversation.as_str()) {
                        self.progress.lock().map_err(|_| poisoned())?.event();
                    }
                    return Ok(false);
                }
                if frame.session_id.as_deref() != Some(conversation.as_str()) {
                    return Err(SeError::invalid(
                        "Claude completion signal",
                        "the exact bound provider conversation",
                    ));
                }
                self.progress.lock().map_err(|_| poisoned())?.terminal(
                    if frame.is_error {
                        "failed"
                    } else {
                        "completed"
                    },
                    false,
                );
                Ok(true)
            });
        match result {
            Ok(false) => return,
            Ok(true) => (),
            Err(error) => {
                self.fail(error);
                return;
            }
        }
        self.nudge(observed_at);
    }
    fn nudge(&self, observed_at: Instant) {
        if let Ok(mut pending) = self.pending.lock() {
            *pending = Some(pending.map_or(observed_at, |old| old.min(observed_at)));
        }
        if let Ok(wake) = self.wake.lock()
            && let Some(wake) = wake.as_ref().and_then(Weak::upgrade)
        {
            wake.notify_one();
        }
    }
    pub(super) fn fail(&self, error: SeError) {
        if let Ok(mut progress) = self.progress.lock() {
            progress.terminal("failed", false);
        }
        if let Ok(mut failure) = self.failure.lock() {
            *failure = Some(error.body);
        }
        self.nudge(Instant::now());
    }
    pub(crate) fn arm(&self, wake: &Arc<Notify>) -> Result<()> {
        *self.wake.lock().map_err(|_| poisoned())? = Some(Arc::downgrade(wake));
        if self.pending.lock().map_err(|_| poisoned())?.is_some() {
            wake.notify_one();
        }
        Ok(())
    }
    pub(crate) fn take(&self) -> Result<Option<Instant>> {
        let pending = self.pending.lock().map_err(|_| poisoned())?.take();
        if let Some(error) = self.failure.lock().map_err(|_| poisoned())?.take() {
            return Err(error.into());
        }
        Ok(pending)
    }
}

#[derive(Default)]
pub(super) struct Frames {
    pending: Vec<u8>,
    skipping: bool,
    observed_at: Option<Instant>,
}
impl Frames {
    pub(super) fn push(&mut self, bytes: &[u8], binding: &Binding) {
        let observed_at = Instant::now();
        for part in bytes.split_inclusive(|byte| *byte == b'\n') {
            let complete = part.last() == Some(&b'\n');
            if !self.skipping {
                let first_byte = *self.observed_at.get_or_insert(observed_at);
                if self.pending.len().saturating_add(part.len()) > MAX_LINE {
                    let observed = self.pending.len().saturating_add(part.len());
                    self.pending = Vec::new();
                    self.skipping = true;
                    binding.completion.fail(SeError::too_large(
                        "Claude completion frame",
                        MAX_LINE,
                        observed,
                    ));
                } else {
                    self.pending.extend_from_slice(part);
                    if complete {
                        binding.completion.inspect_at(
                            &self.pending,
                            &binding.conversation,
                            first_byte,
                        );
                        self.pending.clear();
                        if self.pending.capacity() > 64 * 1024 {
                            self.pending = Vec::new();
                        }
                    }
                }
            }
            if complete {
                self.skipping = false;
                self.observed_at = None;
            }
        }
    }
}
