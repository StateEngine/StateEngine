use super::*;
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
};

pub(super) const CAPACITY: usize = 16 * 1024;

/// Startup-only public diagnostics. Bytes are native stderr, not necessarily UTF-8.
/// An empty incomplete result is pending, never proof of an empty stderr stream.
#[derive(Clone, Debug)]
pub struct RuntimeStartupStderr {
    pub bytes: Vec<u8>,
    pub truncated: bool,
    /// True only after the native reader witnesses EOF.
    pub complete: bool,
    /// A read failure preserves the collected tail and remains distinct from EOF.
    pub failure: Option<ProcError>,
}

pub(super) enum ReadResult {
    Bytes(usize),
    Pending,
    Eof,
}

type Shared = Arc<(Mutex<RuntimeStartupStderr>, Condvar)>;

pub(super) struct Capture {
    shared: Shared,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Capture {
    pub(super) fn start(mut reader: File, deadline: Instant) -> ProcResult<Self> {
        let shared = Arc::new((
            Mutex::new(RuntimeStartupStderr {
                bytes: Vec::with_capacity(CAPACITY),
                truncated: false,
                complete: false,
                failure: None,
            }),
            Condvar::new(),
        ));
        let stop = Arc::new(AtomicBool::new(false));
        let state = Arc::clone(&shared);
        let cancelled = Arc::clone(&stop);
        // One finite startup reader, not an executor or an agent-process worker.
        // It keeps draining after truncation so a verbose child cannot block startup.
        let thread = std::thread::Builder::new()
            .name("runtime-startup-stderr".into())
            .stack_size(128 * 1024)
            .spawn(move || {
                let end = deadline + Duration::from_secs(1);
                let mut buffer = [0u8; 4096];
                while !cancelled.load(Ordering::Acquire) {
                    let read = os::read_diagnostics(&mut reader, &mut buffer);
                    let Ok(mut value) = state.0.lock() else {
                        state.1.notify_all();
                        return;
                    };
                    match read {
                        Ok(ReadResult::Bytes(length)) => {
                            let excess = (value.bytes.len() + length).saturating_sub(CAPACITY);
                            if excess != 0 {
                                value.bytes.drain(..excess);
                                value.truncated = true;
                            }
                            value.bytes.extend_from_slice(&buffer[..length]);
                        }
                        Ok(ReadResult::Eof) => value.complete = true,
                        Err(error) => value.failure = Some(error),
                        Ok(ReadResult::Pending) => {}
                    }
                    if Instant::now() >= end && !value.complete && value.failure.is_none() {
                        value.failure = Some(error(
                            ProcErrorCode::LaunchTimedOut,
                            ProcErrorDetail::Input {
                                field: "runtime startup stderr".into(),
                                reason: "stream remained open beyond the bounded startup window"
                                    .into(),
                            },
                        ));
                    }
                    let finished = value.complete || value.failure.is_some();
                    state.1.notify_all();
                    drop(value);
                    if finished {
                        return;
                    }
                    // Both native readers are nonblocking. Drop joins after at
                    // most this scheduler wait, without waiting for the child.
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
            .map_err(|e| {
                native(
                    ProcErrorCode::LaunchFailed,
                    "start bounded stderr reader",
                    e,
                )
            })?;
        Ok(Self {
            shared,
            stop,
            thread: Some(thread),
        })
    }

    pub(super) fn readback(&self, deadline: Instant) -> ProcResult<RuntimeStartupStderr> {
        // Diagnostics never extend startup admission or wait indefinitely for a
        // live child. A caller may use an already elapsed deadline for a snapshot.
        let deadline = deadline.min(Instant::now() + Duration::from_millis(250));
        let poison = || {
            error(
                ProcErrorCode::LockPoisoned,
                ProcErrorDetail::Input {
                    field: "runtime startup stderr".into(),
                    reason: "collector state lock poisoned".into(),
                },
            )
        };
        let mut value = self.shared.0.lock().map_err(|_| poison())?;
        while !value.complete && value.failure.is_none() {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            let (next, timeout) = self
                .shared
                .1
                .wait_timeout(value, remaining)
                .map_err(|_| poison())?;
            value = next;
            if timeout.timed_out() {
                break;
            }
        }
        Ok(value.clone())
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(super) fn public_line(stage: &str, refusal: &str) -> ProcResult<Vec<u8>> {
    if stage.is_empty() || stage.len() > 128 || !stage.bytes().all(|b| (b' '..=b'~').contains(&b)) {
        return Err(input(
            "startup failure stage",
            "1..128 printable ASCII bytes required",
        ));
    }
    let mut text = format!("[{stage}] ");
    let remaining = CAPACITY - text.len() - 1;
    let mut start = 0;
    if refusal.len() > remaining {
        text.push_str("[earlier public refusal text omitted] ");
        start = refusal.len().saturating_sub(CAPACITY - text.len() - 1);
        while !refusal.is_char_boundary(start) {
            start += 1;
        }
    }
    for character in refusal[start..].chars() {
        if character.is_control() && character != '\n' && character != '\t' {
            text.push('?');
        } else {
            text.push(character);
        }
    }
    text.push('\n');
    Ok(text.into_bytes())
}
