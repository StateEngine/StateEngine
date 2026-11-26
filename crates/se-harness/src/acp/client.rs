//! Methods an ACP agent calls back on its client. StateEngine answers
//! `fs/read_text_file` for files inside the folder the conversation opened in; it
//! does not offer writes or terminals. This bound is the client's own; it does not
//! sandbox the agent process.
mod fs;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// The most bytes of encoded result one reply may carry, leaving room in the
/// protocol's frame for the reply's envelope and request identity.
const RESPONSE_BYTES: usize = super::wire::MAX_FRAME - 4096;
/// The most client calls one conversation runs at once.
const MAX_CALLS: u32 = 16;
/// The one client method StateEngine answers.
const READ: &str = "fs/read_text_file";

/// A refused client call, answered as a JSON-RPC error with this code and message.
#[derive(Debug)]
pub(super) struct Refusal {
    pub code: i64,
    pub message: String,
}

impl Refusal {
    /// The call names something malformed, absent, outside the workspace or too large.
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: message.into(),
        }
    }
    /// A named file does not exist.
    fn missing(message: impl Into<String>) -> Self {
        Self {
            code: -32002,
            message: message.into(),
        }
    }
    /// The call was well formed but could not be carried out.
    fn failed(message: impl Into<String>) -> Self {
        Self {
            code: -32603,
            message: message.into(),
        }
    }
}

type Outcome = Result<Value, Refusal>;

/// The client side of one ACP conversation.
pub(super) struct Client {
    /// The conversation's directory, as the agent was told it.
    root: Mutex<Option<PathBuf>>,
    /// One permit per running call.
    calls: Arc<Semaphore>,
    /// Set once the conversation closes; no call is admitted after it.
    closed: AtomicBool,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            root: Mutex::new(None),
            calls: Arc::new(Semaphore::new(MAX_CALLS as usize)),
            closed: AtomicBool::new(false),
        }
    }
}

impl Client {
    /// The `clientCapabilities` to advertise.
    pub(super) fn capabilities() -> Value {
        json!({"fs":{"readTextFile":true,"writeTextFile":false},"terminal":false})
    }

    /// Whether `method` is the client method this answers. Other methods get the
    /// connection's standard unavailable reply.
    pub(super) fn handles(method: &str) -> bool {
        method == READ
    }

    /// Records the directory the conversation opens in as the workspace. It is
    /// resolved on each call, so a workspace that cannot be resolved refuses only
    /// that call.
    pub(super) fn bind(&self, cwd: &str) {
        if let Ok(mut root) = self.root.lock() {
            *root = Some(PathBuf::from(cwd));
        }
    }

    /// Admits one call, or names why it cannot run now.
    pub(super) fn admit(&self) -> Result<OwnedSemaphorePermit, Refusal> {
        let closing =
            || Refusal::invalid("this conversation is closing, so StateEngine takes no more calls");
        if self.closed.load(Ordering::Acquire) {
            return Err(closing());
        }
        self.calls
            .clone()
            .try_acquire_owned()
            .map_err(|error| match error {
                tokio::sync::TryAcquireError::Closed => closing(),
                tokio::sync::TryAcquireError::NoPermits => Refusal::failed(format!(
                    "this conversation already has {MAX_CALLS} calls running; retry when one finishes"
                )),
            })
    }

    /// Admits no more calls, then waits until `until` for admitted ones to answer.
    /// A read changes nothing, so one still running afterwards only loses its
    /// answer. Calling this again waits again.
    pub(super) async fn close(&self, until: tokio::time::Instant) {
        self.closed.store(true, Ordering::Release);
        let _ = tokio::time::timeout_at(until, self.calls.acquire_many(MAX_CALLS)).await;
    }

    /// Answers one admitted call. Resolution and file I/O block, so they run off
    /// the async workers.
    pub(super) async fn call(&self, params: Value) -> Outcome {
        let workspace = self
            .root
            .lock()
            .ok()
            .and_then(|root| root.clone())
            .ok_or_else(|| {
                Refusal::invalid("no conversation is open yet, so there is no workspace to use")
            })?;
        tokio::task::spawn_blocking(move || {
            let root = se_proc::canonicalize_path(&workspace).map_err(|error| {
                Refusal::failed(format!(
                    "the workspace {} could not be resolved: {error}",
                    workspace.display()
                ))
            })?;
            fs::read(&workspace, &root, &params)
        })
        .await
        .map_err(|_| Refusal::failed("the call stopped before it finished"))?
    }
}
