//! Workspace-scoped ACP `terminal/*` client implementation layered on
//! `se_proc::ContainedChild`.
//!
//! Enforces strict workspace `cwd` binding (no symlink/junction escapes),
//! atomic slot reservation for bounded concurrent terminals per session,
//! bounded tail output ring with an honest `truncated` flag, owned worker
//! threads with explicit error propagation, and deterministic tree kill on
//! `terminal/kill`, `terminal/release`, and session close.
use super::{Outcome, RESPONSE_BYTES, Refusal, fs::Workspace};
use se_proc::{ContainedChild, ContainedChildSpec, ContainedExit, ContainedKiller};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    ffi::OsString,
    fs::File,
    io::Read,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::JoinHandle,
};
use tokio::sync::Notify;

/// Maximum concurrent unreleased terminals per ACP conversation.
const MAX_TERMINALS: usize = 8;
/// Default retained tail output bytes per terminal.
const DEFAULT_OUTPUT_BYTES: usize = 256 * 1024;
/// Hard ceiling on retained tail output bytes per terminal (fits inside one reply).
const MAX_OUTPUT_BYTES: usize = {
    let reply_room = RESPONSE_BYTES.saturating_sub(1024);
    let one_mib = 1024 * 1024;
    if reply_room < one_mib {
        reply_room
    } else {
        one_mib
    }
};
/// Maximum arguments accepted by `terminal/create`.
const MAX_ARGS: usize = 256;
/// Maximum environment overrides accepted by `terminal/create`.
const MAX_ENV: usize = 128;

pub(super) const CREATE: &str = "terminal/create";
pub(super) const OUTPUT: &str = "terminal/output";
pub(super) const WAIT_FOR_EXIT: &str = "terminal/wait_for_exit";
pub(super) const KILL: &str = "terminal/kill";
pub(super) const RELEASE: &str = "terminal/release";

pub(super) fn is_terminal_method(method: &str) -> bool {
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

struct TerminalEntry {
    killer: ContainedKiller,
    output: Arc<Mutex<OutputRing>>,
    exit: Arc<Mutex<Option<Result<ContainedExit, String>>>>,
    notify: Arc<Notify>,
    released: AtomicBool,
    workers: Mutex<Vec<JoinHandle<()>>>,
}

impl TerminalEntry {
    fn terminate_and_join(&self) -> Result<(), String> {
        let kill_res = self.killer.kill_tree().map_err(|e| e.to_string());
        self.notify.notify_waiters();
        let handles: Vec<JoinHandle<()>> = self
            .workers
            .lock()
            .map(|mut w| std::mem::take(&mut *w))
            .unwrap_or_default();
        for handle in handles {
            let _ = handle.join();
        }
        kill_res
    }
}

#[derive(Default)]
struct TerminalTable {
    closed: bool,
    pending: usize,
    active: BTreeMap<String, Arc<TerminalEntry>>,
}

/// Owned terminal table for one ACP conversation.
#[derive(Default)]
pub(super) struct Terminals {
    next_id: AtomicU64,
    table: Arc<Mutex<TerminalTable>>,
    pending_done: Arc<Notify>,
}

/// RAII reservation of one slot in `TerminalTable::pending`. Ensures concurrent
/// `terminal/create` calls never spawn more than `MAX_TERMINALS` processes and
/// `close_all` can wait for any in-flight spawn to settle.
struct PendingSlot {
    table: Arc<Mutex<TerminalTable>>,
    pending_done: Arc<Notify>,
    armed: bool,
}

impl PendingSlot {
    fn commit(mut self, id: String, entry: Arc<TerminalEntry>) -> Result<(), Refusal> {
        let mut table = self
            .table
            .lock()
            .map_err(|_| Refusal::failed("terminal table is poisoned"))?;
        table.pending = table.pending.saturating_sub(1);
        self.armed = false;
        if table.closed {
            drop(table);
            self.pending_done.notify_waiters();
            entry.released.store(true, Ordering::Release);
            let _ = entry.terminate_and_join();
            return Err(Refusal::invalid(
                "this conversation is closing, so StateEngine takes no more terminals",
            ));
        }
        table.active.insert(id, entry);
        drop(table);
        self.pending_done.notify_waiters();
        Ok(())
    }
}

impl Drop for PendingSlot {
    fn drop(&mut self) {
        if self.armed {
            if let Ok(mut table) = self.table.lock() {
                table.pending = table.pending.saturating_sub(1);
            }
            self.pending_done.notify_waiters();
        }
    }
}

impl Drop for Terminals {
    fn drop(&mut self) {
        let entries: Vec<Arc<TerminalEntry>> = match self.table.lock() {
            Ok(mut table) => {
                table.closed = true;
                let drained = table.active.values().cloned().collect();
                table.active.clear();
                drained
            }
            Err(_) => Vec::new(),
        };
        for entry in entries {
            entry.released.store(true, Ordering::Release);
            let _ = entry.terminate_and_join();
        }
    }
}

impl Terminals {
    pub(super) async fn call(
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

    /// Deterministically kill and release every terminal owned by this session,
    /// waiting up to `until` for any in-flight `create` to settle. Returns an
    /// error if any terminal's process tree could not be witnessed empty.
    pub(super) async fn close_all(&self, until: tokio::time::Instant) -> Result<(), String> {
        let entries: Vec<Arc<TerminalEntry>> = {
            let mut table = self
                .table
                .lock()
                .map_err(|_| "terminal table is poisoned".to_owned())?;
            table.closed = true;
            let drained = table.active.values().cloned().collect();
            table.active.clear();
            drained
        };

        let mut errors = Vec::new();
        if !entries.is_empty() {
            let cleanup = tokio::task::spawn_blocking(move || {
                let mut errs = Vec::new();
                for entry in entries {
                    entry.released.store(true, Ordering::Release);
                    if let Err(err) = entry.terminate_and_join() {
                        errs.push(err);
                    }
                }
                errs
            })
            .await
            .map_err(|_| "terminal cleanup task stopped before finishing".to_owned())?;
            errors.extend(cleanup);
        }

        // Wait for any in-flight `create` reservations to observe `closed = true`
        // and clean up their child before returning.
        loop {
            let notified = self.pending_done.notified();
            let pending = self.table.lock().map(|t| t.pending).unwrap_or(0);
            if pending == 0 {
                break;
            }
            if tokio::time::timeout_at(until, notified).await.is_err() {
                errors.push(format!(
                    "{pending} in-flight terminal start(s) did not settle before close deadline"
                ));
                break;
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
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
        if table.active.len() + table.pending >= MAX_TERMINALS {
            return Err(Refusal::failed(format!(
                "this conversation already has {MAX_TERMINALS} active terminals; release one before creating another"
            )));
        }
        table.pending += 1;
        Ok(PendingSlot {
            table: Arc::clone(&self.table),
            pending_done: Arc::clone(&self.pending_done),
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
        slot.commit(id.clone(), entry)?;
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
        let entry = self
            .table
            .lock()
            .map_err(|_| Refusal::failed("terminal table is poisoned"))?
            .active
            .remove(&id)
            .ok_or_else(|| Refusal::missing(format!("terminal {id} does not exist")))?;
        entry.released.store(true, Ordering::Release);
        tokio::task::spawn_blocking(move || entry.terminate_and_join())
            .await
            .map_err(|_| Refusal::failed("terminal release cleanup stopped before finishing"))?
            .map_err(|err| {
                Refusal::failed(format!(
                    "terminal {id} was removed from table, but cleanup was uncertain: {err}"
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
            let _ = child.kill_tree();
            let _ = child.wait();
            let _ = stdout_handle.join();
            return Err(Refusal::failed(format!(
                "failed to start terminal stderr reader: {err}"
            )));
        }
    };

    let exit_slot = Arc::clone(&exit);
    let exit_notify = Arc::clone(&notify);
    let wait_handle = match std::thread::Builder::new()
        .name("acp-terminal-wait".into())
        .spawn(move || {
            let outcome = child.wait().map_err(|err| err.to_string());
            if let Ok(mut slot) = exit_slot.lock() {
                *slot = Some(outcome);
            }
            exit_notify.notify_waiters();
        }) {
        Ok(h) => h,
        Err(err) => {
            let _ = killer.kill_tree();
            let _ = stdout_handle.join();
            let _ = stderr_handle.join();
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
        workers: Mutex::new(vec![stdout_handle, stderr_handle, wait_handle]),
    }))
}

fn spawn_pipe_reader<R: Read + Send + 'static>(
    mut reader: R,
    ring: Arc<Mutex<OutputRing>>,
) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
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
        })
}

fn exit_json(exit: ContainedExit) -> Value {
    json!({
        "exitCode": exit.exit_code,
        "signal": exit.signal,
    })
}

fn fit_response(mut text: String, truncated: &mut bool) -> Result<String, Refusal> {
    let limit = RESPONSE_BYTES.saturating_sub(256);
    while serde_json::to_string(&text)
        .map_err(|_| Refusal::failed("terminal output could not be encoded"))?
        .len()
        > limit
    {
        *truncated = true;
        let drop_bytes = (text.len() / 4).max(1);
        let mut cut = drop_bytes.min(text.len());
        while cut < text.len() && !text.is_char_boundary(cut) {
            cut += 1;
        }
        text.drain(..cut);
    }
    Ok(text)
}

fn required_str<'a>(params: &'a Value, field: &str, max_len: usize) -> Result<&'a str, Refusal> {
    params
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= max_len && !s.contains('\0'))
        .ok_or_else(|| {
            Refusal::invalid(format!(
                "`{field}` must be a non-empty string (<= {max_len} bytes, no NUL)"
            ))
        })
}

fn optional_str<'a>(
    params: &'a Value,
    field: &str,
    max_len: usize,
) -> Result<Option<&'a str>, Refusal> {
    match params.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if !s.is_empty() && s.len() <= max_len && !s.contains('\0') => {
            Ok(Some(s.as_str()))
        }
        _ => Err(Refusal::invalid(format!(
            "`{field}` must be a non-empty string (<= {max_len} bytes, no NUL)"
        ))),
    }
}

fn parse_args(params: &Value) -> Result<Vec<OsString>, Refusal> {
    let Some(value) = params.get("args") else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let arr = value
        .as_array()
        .ok_or_else(|| Refusal::invalid("`args` must be an array of strings"))?;
    if arr.len() > MAX_ARGS {
        return Err(Refusal::invalid(format!(
            "`args` exceeds maximum of {MAX_ARGS} entries"
        )));
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item
            .as_str()
            .filter(|s| s.len() <= 65536 && !s.contains('\0'))
            .ok_or_else(|| Refusal::invalid("each element of `args` must be a valid string"))?;
        out.push(OsString::from(s));
    }
    Ok(out)
}

fn is_forbidden_env_key(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.starts_with("SE_")
        || upper.starts_with("STATEENGINE_")
        || upper.starts_with("LD_")
        || upper.starts_with("DYLD_")
}

fn parse_env(params: &Value) -> Result<Vec<(OsString, OsString)>, Refusal> {
    let Some(value) = params.get("env") else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let arr = value
        .as_array()
        .ok_or_else(|| Refusal::invalid("`env` must be an array of {name, value} objects"))?;
    if arr.len() > MAX_ENV {
        return Err(Refusal::invalid(format!(
            "`env` exceeds maximum of {MAX_ENV} entries"
        )));
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 256 && !s.contains('=') && !s.contains('\0'))
            .ok_or_else(|| Refusal::invalid("`env[].name` must be a valid environment key"))?;
        if is_forbidden_env_key(name) {
            return Err(Refusal::invalid(format!(
                "`env[].name` '{name}' is reserved and cannot be overridden by terminal/create"
            )));
        }
        let val = item
            .get("value")
            .and_then(Value::as_str)
            .filter(|s| s.len() <= 65536 && !s.contains('\0'))
            .ok_or_else(|| Refusal::invalid("`env[].value` must be a valid string"))?;
        out.push((OsString::from(name), OsString::from(val)));
    }
    Ok(out)
}

fn parse_output_limit(params: &Value) -> Result<usize, Refusal> {
    match params.get("outputByteLimit") {
        None | Some(Value::Null) => Ok(DEFAULT_OUTPUT_BYTES),
        Some(value) => {
            let requested = value.as_u64().ok_or_else(|| {
                Refusal::invalid("`outputByteLimit` must be a nonnegative integer")
            })?;
            let clamped = usize::try_from(requested)
                .unwrap_or(MAX_OUTPUT_BYTES)
                .min(MAX_OUTPUT_BYTES);
            Ok(clamped)
        }
    }
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
