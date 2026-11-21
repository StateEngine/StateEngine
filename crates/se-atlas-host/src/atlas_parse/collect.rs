//! Bound decoded rows before publication; no worker output can mutate SQL.
use super::*;
use se_types::code::AtlasText;
use std::mem::size_of;
struct Rows {
    bytes: usize,
    rows: u32,
    maximum: u32,
}
impl Rows {
    fn push<T>(&mut self, into: &mut Vec<T>, row: T, strings: usize) -> AtlasResult<()> {
        if self.rows >= self.maximum {
            return Err(failure("parse result exceeds row reservation"));
        }
        let growth = if into.len() == into.capacity() {
            into.capacity().max(4)
        } else {
            0
        };
        let charge = growth
            .saturating_mul(size_of::<T>())
            .saturating_add(strings);
        self.bytes = self
            .bytes
            .checked_sub(charge)
            .ok_or_else(|| failure("parse result exceeds extraction reservation"))?;
        if growth > 0 {
            into.try_reserve_exact(growth).map_err(failure)?;
        }
        into.push(row);
        self.rows += 1;
        Ok(())
    }
}
struct CpuClock {
    start: Duration,
    spent: Duration,
    limit: Duration,
}
impl CpuClock {
    fn observe(&mut self, worker: &AtlasWorker) -> AtlasResult<()> {
        let current = worker.cpu_time().map_err(failure)?;
        self.spent = current
            .checked_sub(self.start)
            .ok_or_else(|| failure("worker CPU clock moved backwards"))?;
        if self.spent >= self.limit {
            return Err(cpu_expired(self.limit));
        }
        Ok(())
    }
}
fn reply(
    worker: &mut AtlasWorker,
    deadline: Instant,
    mut cpu: Option<&mut CpuClock>,
) -> AtlasResult<protocol::Reply> {
    loop {
        if let Some(cpu) = &mut cpu {
            cpu.observe(worker)?;
        }
        if Instant::now() >= deadline {
            return Err(expired());
        }
        let received = worker.receive();
        if let Some(bytes) = received.map_err(|error| channel_lost(worker, error, deadline))? {
            return serde_json::from_slice(&bytes).map_err(failure);
        }
        let reaped = worker.try_reap();
        if reaped
            .map_err(|error| worker_lost(worker, error))?
            .is_some()
        {
            return Err(worker_lost(
                worker,
                "parse child exited before complete output",
            ));
        }
        let ready = worker.wait_ready(deadline.min(Instant::now() + Duration::from_millis(10)));
        ready.map_err(|error| worker_lost(worker, error))?;
    }
}
/// A lost parse worker, with what is known about it: its exit and the tail of
/// its stderr, so one lost connection can be diagnosed without a reproduction.
fn worker_lost(worker: &mut AtlasWorker, reason: impl std::fmt::Display) -> SeError {
    let exit = match worker.try_reap() {
        Ok(Some(status)) => format!("worker exited ({status})"),
        Ok(None) => "worker still running".to_string(),
        Err(error) => format!("worker exit unreadable: {error}"),
    };
    #[cfg(target_os = "linux")]
    let stderr = worker.stderr_report();
    #[cfg(windows)]
    let stderr = worker
        .failure_diagnostic()
        .unwrap_or_else(|error| format!("stderr unreadable: {error}"));
    failure(format!("{reason}; {exit}; {stderr}"))
}
/// A channel error on a live worker: past the deadline a timeout is expiry,
/// anything else is a lost worker.
pub(super) fn channel_lost(
    worker: &mut AtlasWorker,
    error: std::io::Error,
    deadline: Instant,
) -> SeError {
    if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) && Instant::now() >= deadline
    {
        expired()
    } else {
        worker_lost(worker, error)
    }
}
#[derive(Clone, Copy)]
pub(super) struct Context<'a> {
    pub source: &'a Source,
    pub snapshot: &'a SourceSnapshot,
    pub language: Language,
    pub budget: ParseBudget,
    pub profile: ParserProfile,
    pub deadline: Instant,
}
pub(super) fn read(
    worker: &mut AtlasWorker,
    context: Context<'_>,
    remaining: Duration,
    consumed: &mut Duration,
) -> AtlasResult<ParsedFile> {
    let deadline = context.deadline;
    match reply(worker, deadline, None)? {
        protocol::Reply::Ready => (),
        protocol::Reply::Failed { error } => return Err(SeError::from(error)),
        _ => return Err(failure("parse worker readiness absent")),
    }
    let mut cpu = CpuClock {
        start: worker.cpu_time().map_err(failure)?,
        spent: Duration::ZERO,
        limit: remaining,
    };
    let sent = worker.send_control(b"source", deadline);
    sent.map_err(|error| channel_lost(worker, error, deadline))?;
    let result = read_rows(worker, context, &mut cpu);
    *consumed = cpu.spent;
    result
}
fn read_rows(
    worker: &mut AtlasWorker,
    context: Context<'_>,
    cpu: &mut CpuClock,
) -> AtlasResult<ParsedFile> {
    let Context {
        source,
        snapshot,
        language,
        budget,
        profile,
        deadline,
    } = context;
    let first = reply(worker, deadline, Some(cpu))?;
    let coverage = match first {
        protocol::Reply::Start {
            file,
            language: got,
            hash,
            coverage,
        } if file == source.scope.file_id(&snapshot.path)
            && got == language
            && hash == snapshot.content_hash =>
        {
            coverage
        }
        protocol::Reply::Failed { error } => return Err(SeError::from(error)),
        _ => return Err(failure("parse result does not match bound source")),
    };
    let mut parsed = ParsedFile {
        file: source.scope.file_id(&snapshot.path),
        language,
        content_hash: snapshot.content_hash,
        coverage,
        symbols: Vec::new(),
        imports: Vec::new(),
        references: Vec::new(),
        scopes: Vec::new(),
    };
    let mut rows = Rows {
        bytes: profile.extraction_bytes as usize,
        rows: 0,
        maximum: budget.max_rows.min(profile.max_rows),
    };
    loop {
        match reply(worker, deadline, Some(cpu))? {
            protocol::Reply::Symbol(row) => {
                span(&row.span, snapshot)?;
                let strings = row.name.capacity()
                    + row.doc_line.capacity()
                    + row.export_alias.as_ref().map_or(0, String::capacity);
                rows.push(&mut parsed.symbols, row, strings)?;
            }
            protocol::Reply::Import(row) => {
                span(&row.span, snapshot)?;
                let strings = row.spelling.capacity()
                    + row.local_name.as_ref().map_or(0, String::capacity)
                    + row.imported_name.as_ref().map_or(0, String::capacity);
                rows.push(&mut parsed.imports, row, strings)?;
            }
            protocol::Reply::Reference(row) => {
                if row.site.site.file != parsed.file
                    || row.site.site.path != snapshot.path
                    || row.site.site.content_hash != Some(snapshot.content_hash)
                {
                    return Err(failure("parse reference belongs to another source"));
                }
                if let Some(value) = &row.site.site.span {
                    span(value, snapshot)?;
                }
                let qualifiers = match &row.qualifier {
                    ReferenceQualifier::Namespace(parts) => {
                        parts.capacity() * size_of::<String>()
                            + parts.iter().map(String::capacity).sum::<usize>()
                    }
                    _ => 0,
                };
                let strings =
                    row.site.spelling.capacity() + row.site.site.path.as_str().len() + qualifiers;
                rows.push(&mut parsed.references, row, strings)?;
            }
            protocol::Reply::Scope(row) => {
                span(&row.span, snapshot)?;
                rows.push(&mut parsed.scopes, row, 0)?;
            }
            protocol::Reply::Done => {
                if Instant::now() >= deadline {
                    return Err(expired());
                }
                return Ok(parsed);
            }
            protocol::Reply::Failed { error } => return Err(SeError::from(error)),
            protocol::Reply::Start { .. } | protocol::Reply::Ready => {
                return Err(failure("duplicate parse result header"));
            }
        }
    }
}
fn span(value: &Span, snapshot: &SourceSnapshot) -> AtlasResult<()> {
    if value.start_byte > value.end_byte || value.end_byte > snapshot.bytes.len() as u64 {
        return Err(failure("parse span exceeds its verified source"));
    }
    Ok(())
}
