//! Stream results are coalesced wakeups only. Captured bodies and vendor turn
//! identities still come exclusively from the retained transcript pin.
use super::*;
use std::sync::{
    Weak,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Notify;

pub(crate) const MAX_LINE: usize = 4 * 1024 * 1024;
#[derive(Default)]
pub(crate) struct Completion {
    pending: AtomicBool,
    wake: Mutex<Option<Weak<Notify>>>,
    failure: Mutex<Option<se_types::ErrorBody>>,
}
impl Completion {
    pub(super) fn inspect(&self, line: &[u8], conversation: &ProviderSessionId) {
        #[derive(serde::Deserialize)]
        struct Frame {
            #[serde(rename = "type")]
            kind: String,
            session_id: Option<String>,
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
                    return Ok(false);
                }
                if frame.session_id.as_deref() != Some(conversation.as_str()) {
                    return Err(SeError::invalid(
                        "Claude completion signal",
                        "the exact bound provider conversation",
                    ));
                }
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
        self.nudge();
    }
    fn nudge(&self) {
        self.pending.store(true, Ordering::Release);
        if let Ok(wake) = self.wake.lock()
            && let Some(wake) = wake.as_ref().and_then(Weak::upgrade)
        {
            wake.notify_one();
        }
    }
    pub(super) fn fail(&self, error: SeError) {
        if let Ok(mut failure) = self.failure.lock() {
            *failure = Some(error.body);
        }
        self.nudge();
    }
    pub(crate) fn arm(&self, wake: &Arc<Notify>) -> Result<()> {
        *self.wake.lock().map_err(|_| poisoned())? = Some(Arc::downgrade(wake));
        if self.pending.load(Ordering::Acquire) {
            wake.notify_one();
        }
        Ok(())
    }
    pub(crate) fn take(&self) -> Result<bool> {
        let pending = self.pending.swap(false, Ordering::AcqRel);
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
}
impl Frames {
    pub(super) fn push(&mut self, bytes: &[u8], binding: &Binding) {
        for part in bytes.split_inclusive(|byte| *byte == b'\n') {
            let complete = part.last() == Some(&b'\n');
            if !self.skipping {
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
                        binding
                            .completion
                            .inspect(&self.pending, &binding.conversation);
                        self.pending.clear();
                        if self.pending.capacity() > 64 * 1024 {
                            self.pending = Vec::new();
                        }
                    }
                }
            }
            if complete {
                self.skipping = false;
            }
        }
    }
}
