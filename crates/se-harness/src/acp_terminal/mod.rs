//! Workspace-scoped ACP `terminal/*` client implementation layered on
//! `se_proc::ContainedChild`.
//!
//! Enforces strict workspace `cwd` binding (no symlink/junction escapes),
//! atomic slot reservation for bounded concurrent terminals per session,
//! bounded tail output ring with an honest `truncated` flag, owned worker
//! threads with explicit error propagation, and deterministic tree kill on
//! `terminal/kill`, `terminal/release`, and session close.
mod custody;
mod params;
use crate::acp::client::{Outcome, Refusal, fs::Workspace};
use custody::{MAX_TERMINALS, PendingSlot, ReleasingSlot, TerminalTable};
use params::{
    exit_json, fit_response, optional_str, parse_args, parse_env, parse_output_limit, required_str,
};
use se_proc::{ContainedChild, ContainedChildSpec, ContainedExit, ContainedKiller};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    ffi::OsString,
    fs::File,
    io::Read,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use tokio::sync::Notify;

/// Maximum time `terminal/release` waits for stdout/stderr readers to drain
/// after the contained process tree has been terminated.
const RELEASE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
/// Maximum time synchronous `Drop for Terminals` waits per terminal.
const DROP_CLEANUP_TIMEOUT: Duration = Duration::from_millis(250);

pub(super) const CREATE: &str = "terminal/create";
pub(super) const OUTPUT: &str = "terminal/output";
pub(super) const WAIT_FOR_EXIT: &str = "terminal/wait_for_exit";
pub(super) const KILL: &str = "terminal/kill";
pub(super) const RELEASE: &str = "terminal/release";

pub(crate) fn is_terminal_method(method: &str) -> bool {
    matches!(method, CREATE | OUTPUT | WAIT_FOR_EXIT | KILL | RELEASE)
}

struct OutputRing {
    bytes: VecDeque<u8>,
    limit: usize,
    truncated: bool,
    io_error: Option<String>,
}

impl OutputRing {
    fn new(limit: usize) -> Self {
        Self {
            bytes: VecDeque::new(),
            limit,
            truncated: false,
            io_error: None,
        }
    }

    fn push(&mut self, chunk: &[u8]) {
        if self.limit == 0 {
            if !chunk.is_empty() {
                self.truncated = true;
            }
            return;
        }
        if chunk.len() >= self.limit {
            if !self.bytes.is_empty() || chunk.len() > self.limit {
                self.truncated = true;
            }
            self.bytes.clear();
            let keep_from = chunk.len() - self.limit;
            self.bytes.extend(&chunk[keep_from..]);
            return;
        }
        let excess = (self.bytes.len() + chunk.len()).saturating_sub(self.limit);
        if excess > 0 {
            self.bytes.drain(..excess);
            self.truncated = true;
        }
        self.bytes.extend(chunk);
    }

    fn record_error(&mut self, err: std::io::Error) {
        if self.io_error.is_none() {
            self.io_error = Some(err.to_string());
        }
    }

    fn snapshot(&self) -> Result<(String, bool), String> {
        if let Some(err) = &self.io_error {
            return Err(err.clone());
        }
        let raw: Vec<u8> = self.bytes.iter().copied().collect();
        let start = if self.truncated {
            raw.iter()
                .position(|&b| (b & 0xC0) != 0x80)
                .unwrap_or(raw.len())
        } else {
            0
        };
        let text = String::from_utf8_lossy(&raw[start..]).into_owned();
        Ok((text, self.truncated))
    }
}

struct IoWorker {
    handle: JoinHandle<()>,
    done: mpsc::Receiver<()>,
}

enum WorkerJoin<T> {
    Settled(Result<T, String>),
    TimedOut(IoWorker),
}

impl IoWorker {
    fn try_join(self, deadline: Instant) -> WorkerJoin<()> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match self.done.recv_timeout(remaining) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => WorkerJoin::Settled(
                self.handle
                    .join()
                    .map_err(|_| "terminal output reader thread panicked".to_owned()),
            ),
            Err(mpsc::RecvTimeoutError::Timeout) => WorkerJoin::TimedOut(self),
        }
    }
}

struct WaitWorker {
    handle: JoinHandle<ContainedChild>,
    done: mpsc::Receiver<()>,
}

impl WaitWorker {
    fn try_join(self, deadline: Instant) -> Result<Result<ContainedChild, String>, Self> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match self.done.recv_timeout(remaining) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => Ok(self
                .handle
                .join()
                .map_err(|_| "terminal exit waiter thread panicked".to_owned())),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(self),
        }
    }
}

pub(super) struct TerminalEntry {
    killer: ContainedKiller,
    output: Arc<Mutex<OutputRing>>,
    exit: Arc<Mutex<Option<Result<ContainedExit, String>>>>,
    notify: Arc<Notify>,
    released: AtomicBool,
    wait_worker: Mutex<Option<WaitWorker>>,
    /// Retained child owner once `wait_worker` settles, held across retries
    /// until `terminate_and_reap_until` succeeds.
    child: Mutex<Option<ContainedChild>>,
    io_workers: Mutex<Vec<IoWorker>>,
}

impl TerminalEntry {
    fn terminate_and_join(&self, deadline: Instant) -> Result<(), String> {
        let mut errors = Vec::new();
        if let Err(err) = self.killer.kill_tree_until(deadline) {
            errors.push(err.to_string());
        }
        self.notify.notify_waiters();

        if let Some(wait_worker) = self.wait_worker.lock().ok().and_then(|mut w| w.take()) {
            match wait_worker.try_join(deadline) {
                Ok(Ok(child)) => {
                    if let Ok(mut slot) = self.child.lock() {
                        *slot = Some(child);
                    }
                }
                Ok(Err(err)) => errors.push(err),
                Err(still_waiting) => {
                    if let Ok(mut slot) = self.wait_worker.lock() {
                        *slot = Some(still_waiting);
                    }
                    errors.push(
                        "terminal exit waiter did not settle before cleanup deadline".to_owned(),
                    );
                }
            }
        }

        if let Some(mut child) = self.child.lock().ok().and_then(|mut c| c.take())
            && let Err(err) = child.terminate_and_reap_until(deadline)
        {
            if let Ok(mut slot) = self.child.lock() {
                *slot = Some(child);
            }
            errors.push(err.to_string());
        }

        let workers: Vec<IoWorker> = self
            .io_workers
            .lock()
            .map(|mut w| std::mem::take(&mut *w))
            .unwrap_or_default();
        let mut still_reading = Vec::new();
        for worker in workers {
            match worker.try_join(deadline) {
                WorkerJoin::Settled(Ok(())) => {}
                WorkerJoin::Settled(Err(err)) => errors.push(err),
                WorkerJoin::TimedOut(pending) => {
                    still_reading.push(pending);
                    errors.push(
                        "terminal output stream did not close before cleanup deadline (an escaped descendant may still hold stdout/stderr open)"
                            .to_owned(),
                    );
                }
            }
        }
        if !still_reading.is_empty()
            && let Ok(mut slot) = self.io_workers.lock()
        {
            slot.extend(still_reading);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

/// Owned terminal table for one ACP conversation.
#[derive(Default)]
pub(crate) struct Terminals {
    next_id: AtomicU64,
    table: Arc<Mutex<TerminalTable>>,
    settled: Arc<Notify>,
}

impl Drop for Terminals {
    fn drop(&mut self) {
        let entries: Vec<Arc<TerminalEntry>> = match self.table.lock() {
            Ok(mut table) => {
                table.closed = true;
                let mut drained: Vec<Arc<TerminalEntry>> = table.active.values().cloned().collect();
                table.active.clear();
                drained.extend(table.unsettled.values().map(|(e, _)| Arc::clone(e)));
                table.unsettled.clear();
                drained
            }
            Err(_) => Vec::new(),
        };
        let deadline = Instant::now() + DROP_CLEANUP_TIMEOUT;
        for entry in entries {
            entry.released.store(true, Ordering::Release);
            let _ = entry.terminate_and_join(deadline);
        }
    }
}

impl Terminals {
    pub(crate) async fn call(
        &self,
        workspace: Arc<Workspace>,
        method: &str,
        params: Value,
    ) -> Outcome {
        match method {
            CREATE => self.create(workspace, params).await,
            OUTPUT => self.output(&params),
            WAIT_FOR_EXIT => self.wait_for_exit(&params).await,
            KILL => self.kill(&params).await,
            RELEASE => self.release(&params).await,
            _ => Err(Refusal::invalid(format!(
                "unknown terminal method {method}"
            ))),
        }
    }

    /// Deterministically kill and release every terminal owned by this session
    /// (including any previously unsettled terminals), bounded by `until`. If
    /// `until` expires before all terminals settle, returns an explicit
    /// deadline error while detached blocking workers retain custody and any
    /// unresolved errors remain recorded in `TerminalTable::unsettled`.
    pub(crate) async fn close_all(&self, until: tokio::time::Instant) -> Result<(), String> {
        let entries: Vec<(Arc<TerminalEntry>, ReleasingSlot)> = {
            let mut table = self
                .table
                .lock()
                .map_err(|_| "terminal table is poisoned".to_owned())?;
            table.closed = true;
            let mut drained: Vec<(String, Arc<TerminalEntry>)> =
                std::mem::take(&mut table.active).into_iter().collect();
            for (id, (entry, _)) in std::mem::take(&mut table.unsettled) {
                drained.push((id, entry));
            }
            table.releasing += drained.len();
            drained
                .into_iter()
                .map(|(id, entry)| {
                    let slot = ReleasingSlot::new(
                        id,
                        Arc::clone(&entry),
                        Arc::clone(&self.table),
                        Arc::clone(&self.settled),
                    );
                    (entry, slot)
                })
                .collect()
        };

        let deadline = until.into_std();
        for (entry, slot) in entries {
            entry.released.store(true, Ordering::Release);
            entry.notify.notify_waiters();
            tokio::task::spawn_blocking(move || {
                let res = entry.terminate_and_join(deadline);
                let _ = slot.finish(res);
            });
        }

        loop {
            let notified = self.settled.notified();
            let remaining = {
                let table = self
                    .table
                    .lock()
                    .map_err(|_| "terminal table is poisoned".to_owned())?;
                let remaining = table.pending + table.releasing;
                if remaining == 0 {
                    return match table.unsettled_summary() {
                        None => Ok(()),
                        Some(summary) => Err(summary),
                    };
                }
                remaining
            };
            if tokio::time::timeout_at(until, notified).await.is_err() {
                let existing = self.table.lock().ok().and_then(|t| t.unsettled_summary());
                let timeout_msg =
                    format!("{remaining} terminal(s) did not settle before close deadline");
                return match existing {
                    Some(prev) => Err(format!("{prev}; {timeout_msg}")),
                    None => Err(timeout_msg),
                };
            }
        }
    }

    fn reserve_slot(&self) -> Result<PendingSlot, Refusal> {
        let mut table = self
            .table
            .lock()
            .map_err(|_| Refusal::failed("terminal table is poisoned"))?;
        if table.closed {
            return Err(Refusal::invalid(
                "this conversation is closing, so StateEngine takes no more terminals",
            ));
        }
        if table.occupied_slots() >= MAX_TERMINALS {
            return Err(Refusal::failed(format!(
                "this conversation already has {MAX_TERMINALS} active terminals; release one before creating another"
            )));
        }
        table.pending += 1;
        Ok(PendingSlot {
            table: Arc::clone(&self.table),
            settled: Arc::clone(&self.settled),
            armed: true,
        })
    }

    async fn create(&self, workspace: Arc<Workspace>, params: Value) -> Outcome {
        let command = required_str(&params, "command", 4096)?.to_owned();
        let args = parse_args(&params)?;
        let env = parse_env(&params)?;
        let cwd_param = optional_str(&params, "cwd", 4096)?.map(str::to_owned);
        let output_limit = parse_output_limit(&params)?;

        // Atomically reserve a slot BEFORE resolving dirs or spawning any process.
        let slot = self.reserve_slot()?;

        let entry = tokio::task::spawn_blocking(move || {
            let cwd = workspace.resolve_dir(cwd_param.as_deref())?;
            let spec = ContainedChildSpec {
                command: OsString::from(command),
                args,
                cwd,
                env,
            };
            let spawned = ContainedChild::spawn(spec).map_err(|err| {
                Refusal::failed(format!("failed to start terminal command: {err}"))
            })?;
            start_entry(spawned, output_limit)
        })
        .await
        .map_err(|_| {
            Refusal::failed("starting the terminal command stopped before it finished")
        })??;

        let seq = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let id = format!("term_{seq}");
        if let Some(releasing) = slot.commit(id.clone(), Arc::clone(&entry))? {
            entry.released.store(true, Ordering::Release);
            entry.notify.notify_waiters();
            tokio::task::spawn_blocking(move || {
                let res = entry.terminate_and_join(Instant::now() + RELEASE_CLEANUP_TIMEOUT);
                let _ = releasing.finish(res);
            });
            return Err(Refusal::invalid(
                "this conversation is closing, so StateEngine takes no more terminals",
            ));
        }
        Ok(json!({ "terminalId": id }))
    }

    fn output(&self, params: &Value) -> Outcome {
        let entry = self.lookup(params)?;
        let (text, mut truncated) = entry
            .output
            .lock()
            .map_err(|_| Refusal::failed("terminal output buffer is poisoned"))?
            .snapshot()
            .map_err(|err| Refusal::failed(format!("terminal output stream failed: {err}")))?;
        let exit_status = match entry
            .exit
            .lock()
            .map_err(|_| Refusal::failed("terminal exit state is poisoned"))?
            .clone()
        {
            None => None,
            Some(Ok(status)) => Some(exit_json(status)),
            Some(Err(err)) => {
                return Err(Refusal::failed(format!(
                    "observing terminal exit status failed: {err}"
                )));
            }
        };
        let text = fit_response(text, &mut truncated)?;
        Ok(json!({
            "output": text,
            "truncated": truncated,
            "exitStatus": exit_status,
        }))
    }

    async fn wait_for_exit(&self, params: &Value) -> Outcome {
        let entry = self.lookup(params)?;
        loop {
            let notified = entry.notify.notified();
            if let Some(result) = entry
                .exit
                .lock()
                .map_err(|_| Refusal::failed("terminal exit state is poisoned"))?
                .clone()
            {
                return match result {
                    Ok(status) => Ok(exit_json(status)),
                    Err(err) => Err(Refusal::failed(format!(
                        "observing terminal exit status failed: {err}"
                    ))),
                };
            }
            if entry.released.load(Ordering::Acquire) {
                return Err(Refusal::missing(
                    "terminal was released or session closed while waiting for exit",
                ));
            }
            notified.await;
        }
    }

    async fn kill(&self, params: &Value) -> Outcome {
        let entry = self.lookup(params)?;
        tokio::task::spawn_blocking(move || entry.killer.kill_tree())
            .await
            .map_err(|_| Refusal::failed("terminal kill task stopped before finishing"))?
            .map_err(|err| Refusal::failed(format!("failed to kill terminal tree: {err}")))?;
        Ok(json!({}))
    }

    async fn release(&self, params: &Value) -> Outcome {
        let id = required_str(params, "terminalId", 128)?.to_owned();
        let (entry, releasing) = {
            let mut table = self
                .table
                .lock()
                .map_err(|_| Refusal::failed("terminal table is poisoned"))?;
            let entry = table
                .active
                .remove(&id)
                .ok_or_else(|| Refusal::missing(format!("terminal {id} does not exist")))?;
            table.releasing += 1;
            let releasing = ReleasingSlot::new(
                id.clone(),
                Arc::clone(&entry),
                Arc::clone(&self.table),
                Arc::clone(&self.settled),
            );
            (entry, releasing)
        };
        entry.released.store(true, Ordering::Release);
        entry.notify.notify_waiters();
        tokio::task::spawn_blocking(move || {
            let res = entry.terminate_and_join(Instant::now() + RELEASE_CLEANUP_TIMEOUT);
            releasing.finish(res)
        })
        .await
        .map_err(|_| Refusal::failed("terminal release cleanup stopped before finishing"))?
        .map_err(|err| {
            Refusal::failed(format!(
                "terminal {id} cleanup did not settle (retained for session close): {err}"
            ))
        })?;
        Ok(json!({}))
    }

    fn lookup(&self, params: &Value) -> Result<Arc<TerminalEntry>, Refusal> {
        let id = required_str(params, "terminalId", 128)?;
        self.table
            .lock()
            .map_err(|_| Refusal::failed("terminal table is poisoned"))?
            .active
            .get(id)
            .cloned()
            .ok_or_else(|| Refusal::missing(format!("terminal {id} does not exist")))
    }
}

fn start_entry(
    (mut child, stdout, stderr): (ContainedChild, File, File),
    output_limit: usize,
) -> Result<Arc<TerminalEntry>, Refusal> {
    let killer = child.killer();
    let output = Arc::new(Mutex::new(OutputRing::new(output_limit)));
    let exit = Arc::new(Mutex::new(None));
    let notify = Arc::new(Notify::new());

    let stdout_handle = match spawn_pipe_reader(stdout, Arc::clone(&output)) {
        Ok(h) => h,
        Err(err) => {
            let _ = child.kill_tree();
            let _ = child.wait();
            return Err(Refusal::failed(format!(
                "failed to start terminal stdout reader: {err}"
            )));
        }
    };
    let stderr_handle = match spawn_pipe_reader(stderr, Arc::clone(&output)) {
        Ok(h) => h,
        Err(err) => {
            let deadline = Instant::now() + DROP_CLEANUP_TIMEOUT;
            let _ = child.terminate_and_reap_until(deadline);
            let _ = stdout_handle.try_join(deadline);
            return Err(Refusal::failed(format!(
                "failed to start terminal stderr reader: {err}"
            )));
        }
    };

    let exit_slot = Arc::clone(&exit);
    let exit_notify = Arc::clone(&notify);
    let (wait_done_tx, wait_done_rx) = mpsc::channel();
    let wait_handle = match std::thread::Builder::new()
        .name("acp-terminal-wait".into())
        .spawn(move || {
            let outcome = child.wait().map_err(|err| err.to_string());
            if let Ok(mut slot) = exit_slot.lock() {
                *slot = Some(outcome);
            }
            exit_notify.notify_waiters();
            let _ = wait_done_tx.send(());
            child
        }) {
        Ok(h) => WaitWorker {
            handle: h,
            done: wait_done_rx,
        },
        Err(err) => {
            let deadline = Instant::now() + DROP_CLEANUP_TIMEOUT;
            let _ = killer.kill_tree_until(deadline);
            let _ = stdout_handle.try_join(deadline);
            let _ = stderr_handle.try_join(deadline);
            return Err(Refusal::failed(format!(
                "failed to start terminal exit waiter: {err}"
            )));
        }
    };

    Ok(Arc::new(TerminalEntry {
        killer,
        output,
        exit,
        notify,
        released: AtomicBool::new(false),
        wait_worker: Mutex::new(Some(wait_handle)),
        child: Mutex::new(None),
        io_workers: Mutex::new(vec![stdout_handle, stderr_handle]),
    }))
}

fn spawn_pipe_reader<R: Read + Send + 'static>(
    mut reader: R,
    ring: Arc<Mutex<OutputRing>>,
) -> std::io::Result<IoWorker> {
    let (done_tx, done_rx) = mpsc::channel();
    let handle = std::thread::Builder::new()
        .name("acp-terminal-io".into())
        .spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Ok(mut guard) = ring.lock() {
                            guard.push(&buf[..n]);
                        }
                    }
                    Err(err) => {
                        if let Ok(mut guard) = ring.lock() {
                            guard.record_error(err);
                        }
                        break;
                    }
                }
            }
            let _ = done_tx.send(());
        })?;
    Ok(IoWorker {
        handle,
        done: done_rx,
    })
}

#[cfg(test)]
mod tests {
    use super::OutputRing;

    #[test]
    fn replacing_full_tail_with_exact_limit_chunk_marks_truncated() {
        let mut ring = OutputRing::new(4);
        ring.push(b"ab");
        assert_eq!(ring.snapshot(), Ok(("ab".into(), false)));
        ring.push(b"WXYZ");
        assert_eq!(ring.snapshot(), Ok(("WXYZ".into(), true)));
    }
}
