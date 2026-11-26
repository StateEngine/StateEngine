//! Workspace-scoped ACP `terminal/*` client implementation layered on
//! `se_proc::ContainedChild`.
//!
//! Enforces strict workspace `cwd` binding (no symlink/junction escapes),
//! bounded concurrent terminals per session, bounded tail output ring with an
//! honest `truncated` flag, and deterministic tree kill on `terminal/kill`,
//! `terminal/release`, and session close.
use super::{Outcome, RESPONSE_BYTES, Refusal, fs::Workspace};
use se_proc::{ContainedChild, ContainedChildSpec, ContainedExit, ContainedKiller};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    ffi::OsString,
    io::Read,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
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
}

impl OutputRing {
    fn new(limit: usize) -> Self {
        Self {
            bytes: VecDeque::new(),
            limit,
            truncated: false,
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
            self.bytes.clear();
            let keep_from = chunk.len() - self.limit;
            if keep_from > 0 {
                self.truncated = true;
            }
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

    fn snapshot(&self) -> (String, bool) {
        let raw: Vec<u8> = self.bytes.iter().copied().collect();
        // If we dropped bytes from the front, skip any leading UTF-8 continuation
        // bytes so the retained tail starts on a clean character boundary.
        let start = if self.truncated {
            raw.iter()
                .position(|&b| (b & 0xC0) != 0x80)
                .unwrap_or(raw.len())
        } else {
            0
        };
        let text = String::from_utf8_lossy(&raw[start..]).into_owned();
        (text, self.truncated)
    }
}

struct TerminalEntry {
    killer: ContainedKiller,
    output: Arc<Mutex<OutputRing>>,
    exit: Arc<Mutex<Option<ContainedExit>>>,
    notify: Arc<Notify>,
    released: AtomicBool,
}

impl TerminalEntry {
    fn terminate(&self) {
        let _ = self.killer.kill_tree();
        self.notify.notify_waiters();
    }
}

#[derive(Default)]
struct TerminalTable {
    closed: bool,
    active: BTreeMap<String, Arc<TerminalEntry>>,
}

/// Owned terminal table for one ACP conversation.
#[derive(Default)]
pub(super) struct Terminals {
    next_id: AtomicU64,
    table: Mutex<TerminalTable>,
}

impl Drop for Terminals {
    fn drop(&mut self) {
        self.close_all();
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
            KILL => self.kill(&params),
            RELEASE => self.release(&params),
            _ => Err(Refusal::invalid(format!(
                "unknown terminal method {method}"
            ))),
        }
    }

    /// Deterministically kill and release every terminal owned by this session.
    pub(super) fn close_all(&self) {
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
            entry.terminate();
        }
    }

    async fn create(&self, workspace: Arc<Workspace>, params: Value) -> Outcome {
        let command = required_str(&params, "command", 4096)?.to_owned();
        let args = parse_args(&params)?;
        let env = parse_env(&params)?;
        let cwd_param = optional_str(&params, "cwd", 4096)?.map(str::to_owned);
        let output_limit = parse_output_limit(&params)?;

        self.check_capacity()?;

        let spawned = tokio::task::spawn_blocking(move || {
            let cwd = workspace.resolve_dir(cwd_param.as_deref())?;
            let spec = ContainedChildSpec {
                command: OsString::from(command),
                args,
                cwd,
                env,
            };
            ContainedChild::spawn(spec)
                .map_err(|err| Refusal::failed(format!("failed to start terminal command: {err}")))
        })
        .await
        .map_err(|_| {
            Refusal::failed("starting the terminal command stopped before it finished")
        })??;

        let entry = start_entry(spawned, output_limit);
        let seq = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let id = format!("term_{seq}");

        let mut table = self
            .table
            .lock()
            .map_err(|_| Refusal::failed("terminal table is poisoned"))?;
        if table.closed {
            entry.released.store(true, Ordering::Release);
            entry.terminate();
            return Err(Refusal::invalid(
                "this conversation is closing, so StateEngine takes no more terminals",
            ));
        }
        if table.active.len() >= MAX_TERMINALS {
            entry.released.store(true, Ordering::Release);
            entry.terminate();
            return Err(Refusal::failed(format!(
                "this conversation already has {MAX_TERMINALS} active terminals; release one before creating another"
            )));
        }
        table.active.insert(id.clone(), entry);
        Ok(json!({ "terminalId": id }))
    }

    fn check_capacity(&self) -> Result<(), Refusal> {
        let table = self
            .table
            .lock()
            .map_err(|_| Refusal::failed("terminal table is poisoned"))?;
        if table.closed {
            return Err(Refusal::invalid(
                "this conversation is closing, so StateEngine takes no more terminals",
            ));
        }
        if table.active.len() >= MAX_TERMINALS {
            return Err(Refusal::failed(format!(
                "this conversation already has {MAX_TERMINALS} active terminals; release one before creating another"
            )));
        }
        Ok(())
    }

    fn output(&self, params: &Value) -> Outcome {
        let entry = self.lookup(params)?;
        let (text, mut truncated) = entry
            .output
            .lock()
            .map_err(|_| Refusal::failed("terminal output buffer is poisoned"))?
            .snapshot();
        let exit_status = entry
            .exit
            .lock()
            .map_err(|_| Refusal::failed("terminal exit state is poisoned"))?
            .clone()
            .map(exit_json);
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
            if let Some(status) = entry
                .exit
                .lock()
                .map_err(|_| Refusal::failed("terminal exit state is poisoned"))?
                .clone()
            {
                return Ok(exit_json(status));
            }
            if entry.released.load(Ordering::Acquire) {
                return Err(Refusal::missing(
                    "terminal was released or session closed while waiting for exit",
                ));
            }
            notified.await;
        }
    }

    fn kill(&self, params: &Value) -> Outcome {
        let entry = self.lookup(params)?;
        entry
            .killer
            .kill_tree()
            .map_err(|err| Refusal::failed(format!("failed to kill terminal tree: {err}")))?;
        Ok(json!({}))
    }

    fn release(&self, params: &Value) -> Outcome {
        let id = required_str(params, "terminalId", 128)?;
        let entry = self
            .table
            .lock()
            .map_err(|_| Refusal::failed("terminal table is poisoned"))?
            .active
            .remove(id)
            .ok_or_else(|| Refusal::missing(format!("terminal {id} does not exist")))?;
        entry.released.store(true, Ordering::Release);
        entry.terminate();
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
    (mut child, stdout, stderr): (
        ContainedChild,
        std::process::ChildStdout,
        std::process::ChildStderr,
    ),
    output_limit: usize,
) -> Arc<TerminalEntry> {
    let killer = child.killer();
    let output = Arc::new(Mutex::new(OutputRing::new(output_limit)));
    let exit = Arc::new(Mutex::new(None));
    let notify = Arc::new(Notify::new());

    spawn_pipe_reader(stdout, Arc::clone(&output));
    spawn_pipe_reader(stderr, Arc::clone(&output));

    let exit_slot = Arc::clone(&exit);
    let exit_notify = Arc::clone(&notify);
    let _ = std::thread::Builder::new()
        .name("acp-terminal-wait".into())
        .spawn(move || {
            let status = child.wait().unwrap_or(ContainedExit {
                exit_code: None,
                signal: None,
            });
            if let Ok(mut slot) = exit_slot.lock() {
                *slot = Some(status);
            }
            exit_notify.notify_waiters();
        });

    Arc::new(TerminalEntry {
        killer,
        output,
        exit,
        notify,
        released: AtomicBool::new(false),
    })
}

fn spawn_pipe_reader<R: Read + Send + 'static>(mut reader: R, ring: Arc<Mutex<OutputRing>>) {
    let _ = std::thread::Builder::new()
        .name("acp-terminal-io".into())
        .spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if let Ok(mut guard) = ring.lock() {
                            guard.push(&buf[..n]);
                        }
                    }
                }
            }
        });
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
