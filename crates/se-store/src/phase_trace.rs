//! Temporary synchronous host diagnostics; never an authority or cache.
use std::{cell::RefCell, fmt::Write as _, io::Write as _, path::PathBuf, time::Instant};

struct Trace {
    scope: &'static str,
    path: PathBuf,
    started: Instant,
    records: Vec<(&'static str, &'static str, u128, usize, usize)>,
    next_id: usize,
    stack: Vec<usize>,
}
thread_local! {
    static CURRENT: RefCell<Option<Trace>> = const { RefCell::new(None) };
}
/// Own one synchronous diagnostic scope, restoring any enclosing scope on drop.
pub struct Scope(Option<Option<Trace>>);
impl Scope {
    /// Enable only when the private diagnostic destination was supplied.
    pub fn new(scope: &'static str) -> Self {
        let Some(path) = std::env::var_os("SE_HOST_PHASE_PROFILE") else {
            return Self(None);
        };
        let trace = Trace {
            scope,
            path: path.into(),
            started: Instant::now(),
            records: Vec::new(),
            next_id: 1,
            stack: Vec::new(),
        };
        Self(Some(CURRENT.with(|current| current.replace(Some(trace)))))
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        let Some(previous) = self.0.take() else {
            return;
        };
        let Some(mut trace) = CURRENT.with(|current| current.replace(previous)) else {
            return;
        };
        trace
            .records
            .push(("phase", "total", trace.started.elapsed().as_nanos(), 0, 0));
        trace
            .records
            .push(("count", "unclosed_spans", trace.stack.len() as u128, 0, 0));
        let mut text = String::new();
        for (kind, name, value, id, parent) in trace.records {
            let _ = writeln!(
                text,
                "host.{kind} {} {} {name} {value} {id} {parent}",
                std::process::id(),
                trace.scope
            );
        }
        // No creation or authority changes. Missing/partial logs fail the collector.
        if let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(trace.path) {
            let _ = file.write_all(text.as_bytes());
        }
    }
}
/// A nested inclusive duration, recorded in memory until its root scope ends.
pub struct Span {
    name: &'static str,
    started: Option<(Instant, usize, usize)>,
}
impl Span {
    /// Begin a span only inside an active synchronous diagnostic scope.
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            started: CURRENT.with(|current| {
                current.borrow_mut().as_mut().map(|trace| {
                    let id = trace.next_id;
                    trace.next_id += 1;
                    let parent = trace.stack.last().copied().unwrap_or(0);
                    trace.stack.push(id);
                    (Instant::now(), id, parent)
                })
            }),
        }
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        if let Some((started, id, parent)) = self.started {
            let elapsed = started.elapsed().as_nanos();
            CURRENT.with(|current| {
                if let Some(trace) = current.borrow_mut().as_mut() {
                    if trace.stack.pop() != Some(id) {
                        trace.records.push(("count", "stack_mismatch", 1, 0, 0));
                    }
                    trace
                        .records
                        .push(("phase", self.name, elapsed, id, parent));
                }
            });
        }
    }
}
fn record(kind: &'static str, name: &'static str, value: u128) {
    CURRENT.with(|current| {
        if let Some(trace) = current.borrow_mut().as_mut() {
            trace.records.push((kind, name, value, 0, 0));
        }
    });
}
/// Record an explicit count, including a witnessed zero.
pub fn count(name: &'static str, value: u128) {
    record("count", name, value);
}
/// Measure a synchronous operation without changing its result or error.
pub fn measure<T>(name: &'static str, operation: impl FnOnce() -> T) -> T {
    let _span = Span::new(name);
    operation()
}
