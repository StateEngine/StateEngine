//! Methods an ACP agent calls back on its client. StateEngine answers
//! `fs/read_text_file` for files inside the folder the conversation opened in,
//! and `fs/write_text_file` inside that same folder only when the saved profile
//! permits workspace writes; it does not offer terminals. This bound is the
//! client's own; it does not sandbox the agent process.
mod fs;
use super::permission::WorkspaceAccess;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// The most bytes of encoded result one reply may carry, leaving room in the
/// protocol's frame for the reply's envelope and request identity.
const RESPONSE_BYTES: usize = super::wire::MAX_FRAME - 4096;
/// The most client calls one conversation runs at once.
const MAX_CALLS: u32 = 16;
/// Client filesystem methods StateEngine answers.
const READ: &str = "fs/read_text_file";
const WRITE: &str = "fs/write_text_file";

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
    /// Whether this session's profile permits workspace writes.
    access: WorkspaceAccess,
    /// The workspace held since the conversation opened, or why it could not be.
    workspace: Mutex<Option<Result<Arc<fs::Workspace>, String>>>,
    /// Owned contained terminals for this conversation.
    terminals: terminal::Terminals,
    /// One permit per running call.
    calls: Arc<Semaphore>,
    /// Set once the conversation closes; no call is admitted and no queued
    /// workspace write starts after it.
    closed: Arc<AtomicBool>,
    /// Count of workspace writes currently in flight on blocking workers.
    active_writes: Arc<AtomicUsize>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new(WorkspaceAccess::ReadOnly)
    }
}

impl Client {
    pub(super) fn new(access: WorkspaceAccess) -> Self {
        Self {
            access,
            workspace: Mutex::new(None),
            calls: Arc::new(Semaphore::new(MAX_CALLS as usize)),
            closed: Arc::new(AtomicBool::new(false)),
            active_writes: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// The `clientCapabilities` to advertise.
    pub(super) fn capabilities(&self) -> Value {
        json!({"fs":{"readTextFile":true,"writeTextFile":self.access.allows_write()},"terminal":false})
    }

    /// Whether `method` is a client method this session answers. Other methods
    /// get the connection's standard unavailable reply.
    pub(super) fn handles(&self, method: &str) -> bool {
        method == READ || (self.access.allows_write() && method == WRITE)
    }

    /// Opens and holds the directory the conversation opens in as the workspace,
    /// within the session-open bound `until`. If it cannot be held, every read
    /// refuses with that reason. An open that misses the bound changes nothing:
    /// its late result is discarded, and the caller refuses the session open.
    pub(super) async fn bind(&self, cwd: &str, until: tokio::time::Instant) -> Result<(), String> {
        let told = PathBuf::from(cwd);
        let opened = tokio::time::timeout_at(
            until,
            tokio::task::spawn_blocking(move || fs::Workspace::open(told)),
        )
        .await
        .map_err(|_| {
            "opening the workspace did not finish before the session-open deadline".to_owned()
        })?
        .unwrap_or_else(|_| Err("opening the workspace stopped before it finished".into()))
        .map(Arc::new);
        *self.workspace.lock().map_err(|_| {
            "the workspace record was left unusable by an earlier failure; start the agent again"
                .to_owned()
        })? = Some(opened);
        Ok(())
    }

    /// Admits one call, or names why it cannot run now.
    /// The permit is taken before the closed check, so once `close` holds every
    /// permit no call can slip in after it.
    pub(super) fn admit(&self) -> Result<OwnedSemaphorePermit, Refusal> {
        let closing =
            || Refusal::invalid("this conversation is closing, so StateEngine takes no more calls");
        let permit = self
            .calls
            .clone()
            .try_acquire_owned()
            .map_err(|error| match error {
                tokio::sync::TryAcquireError::Closed => closing(),
                tokio::sync::TryAcquireError::NoPermits => Refusal::failed(format!(
                    "this conversation already has {MAX_CALLS} calls running; retry when one finishes"
                )),
            })?;
        if self.closed.load(Ordering::Acquire) {
            return Err(closing());
        }
        Ok(permit)
    }

    /// Admits no more calls, cancels queued workspace writes before they begin,
    /// then waits until `until` for admitted ones to finish. Reports an error
    /// if an in-flight workspace write outlives the close deadline.
    pub(super) async fn close(&self, until: tokio::time::Instant) -> Result<(), String> {
        self.closed.store(true, Ordering::Release);
        if tokio::time::timeout_at(until, self.calls.acquire_many(MAX_CALLS))
            .await
            .is_err()
            && self.active_writes.load(Ordering::Acquire) > 0
        {
            return Err(
                "an admitted workspace write is still running after the close deadline; its final persistence outcome is uncertain"
                    .into(),
            );
        }
        Ok(())
    }

    /// Answers one admitted call. File I/O blocks, so it runs off the async workers.
    pub(super) async fn call(&self, method: String, params: Value) -> Outcome {
        let workspace = self
            .workspace
            .lock()
            .ok()
            .and_then(|workspace| workspace.clone())
            .ok_or_else(|| {
                Refusal::invalid("no conversation is open yet, so there is no workspace to use")
            })?
            .map_err(Refusal::failed)?;
        match method.as_str() {
            READ => tokio::task::spawn_blocking(move || fs::read(&workspace, &params))
                .await
                .map_err(|_| Refusal::failed("the call stopped before it finished"))?,
            WRITE => {
                if !self.access.allows_write() {
                    return Err(Refusal::invalid(
                        "this session's profile does not permit workspace writes",
                    ));
                }
                if self.closed.load(Ordering::Acquire) {
                    return Err(Refusal::invalid(
                        "this conversation is closing, so no new workspace write was started",
                    ));
                }
                let closed = self.closed.clone();
                let active = self.active_writes.clone();
                active.fetch_add(1, Ordering::AcqRel);
                struct ActiveWrite(Arc<AtomicUsize>);
                impl Drop for ActiveWrite {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::AcqRel);
                    }
                }
                let _guard = ActiveWrite(active);
                tokio::task::spawn_blocking(move || fs::write(&workspace, &params, &closed))
                    .await
                    .map_err(|_| Refusal::failed("the call stopped before it finished"))?
            }
            _ => Err(Refusal::invalid(format!(
                "unsupported client method {method}"
            ))),
        }
    }
}
