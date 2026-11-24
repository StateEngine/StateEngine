//! A bounded source scan and replay of durable forward references.
use super::{rows, *};
pub(super) struct FileResult {
    pub receipt: ImportFamilyReceipt,
    pub counts: ImportCounts,
    pub resume: Vec<ImportResume>,
}
enum OpenedSource {
    Ready(Box<source::SourceFile>),
    Finished(Box<FileResult>),
}

struct ScanState {
    counts: ImportCounts,
    want: Expected,
    reason: Option<String>,
    resume: Vec<ImportResume>,
}

pub(super) async fn file(
    context: &ExecutionContext,
    cx: NodeContext,
    file: plan::File,
    deadline: &Deadline,
) -> Result<FileResult> {
    if let Some(observation) = &file.observation {
        let (state, reason) = match observation {
            Read::Present { .. } => ("present", None),
            Read::Absent { checked } => ("absent", Some(checked.clone())),
            Read::Unreadable { reason, .. } => ("unreadable", Some(reason.clone())),
            Read::Unknown { what } => ("unknown", Some(what.clone())),
        };
        return Ok(FileResult {
            receipt: receipt(&file, state, &ImportCounts::default(), reason, 0)?,
            counts: ImportCounts::default(),
            resume: Vec::new(),
        });
    }
    let path = NativePath::from_local(file.path.clone())?;
    let key = source::SourceFile::source_key(&path)?;
    let progress = read_progress(context, &cx, file.family, &key, deadline).await?;
    let want = progress
        .checkpoint
        .as_ref()
        .map(|p| p.expected)
        .unwrap_or(Expected::Absent);
    let counts = progress.counts.clone();
    let source = match open_source(context, &cx, &file, &key, progress, deadline).await? {
        OpenedSource::Ready(source) => *source,
        OpenedSource::Finished(result) => return Ok(*result),
    };
    if matches!(file.kind, NodeKind::Profiles) && !matches!(cx.owner_profiles, Read::Present { .. })
    {
        let reason = match &cx.owner_profiles {
            Read::Unknown { what } => what.clone(),
            Read::Absent { checked } => checked.clone(),
            Read::Unreadable { reason, .. } => reason.clone(),
            Read::Present { .. } => String::new(),
        };
        return Ok(FileResult {
            receipt: receipt(&file, "blocked", &ImportCounts::default(), Some(reason), 0)?,
            counts: ImportCounts::default(),
            resume: Vec::new(),
        });
    }
    let mut state = ScanState {
        counts,
        want,
        reason: None,
        resume: Vec::new(),
    };
    if let Some(failure) =
        scan_forward(context, &cx, &file, &key, source, &mut state, deadline).await?
    {
        return Ok(failure);
    }
    let progress = read_progress(context, &cx, file.family, &key, deadline).await?;
    let mut deferred = progress.deferred;
    if deferred > 0 {
        let checkpoint = progress.checkpoint.ok_or_else(|| {
            scope::unreadable("staged source", "its durable checkpoint is absent")
        })?;
        replay_deferred(context, &cx, &file, &key, &checkpoint, &mut state, deadline).await?;
        deferred = read_progress(context, &cx, file.family, &key, deadline)
            .await?
            .deferred;
    }
    let reason = finalize_reason(&state.counts, deferred, state.reason);
    Ok(FileResult {
        receipt: receipt(&file, "present", &state.counts, reason, deferred)?,
        counts: state.counts,
        resume: state.resume,
    })
}

async fn read_progress(
    context: &ExecutionContext,
    cx: &NodeContext,
    family: ImportFamily,
    key: &[u8],
    deadline: &Deadline,
) -> Result<state::Progress> {
    let readcx = cx.clone();
    let readkey = key.to_vec();
    job(context, deadline, move |context| {
        state::progress(context, &readcx, family, &readkey)
    })
    .await
}

async fn open_source(
    context: &ExecutionContext,
    cx: &NodeContext,
    file: &plan::File,
    key: &[u8],
    progress: state::Progress,
    deadline: &Deadline,
) -> Result<OpenedSource> {
    let open = progress.checkpoint.clone();
    let source_path = file.path.clone();
    let bound = deadline.clone();
    let ledger = matches!(file.kind, NodeKind::Ledger);
    let anchor = file.anchor.clone();
    let opened = job(context, deadline, move |_| {
        if ledger {
            chain::validate(&source_path, &bound)?;
        }
        let mut source = source::SourceFile::open(source_path, open.as_ref(), &bound)?;
        if let (Some(anchor), Read::Present { value }) = (&anchor, &mut source) {
            value.verify_anchor(anchor, &bound)?;
        }
        Ok(source)
    })
    .await;
    match opened {
        Ok(Read::Present { value }) => Ok(OpenedSource::Ready(Box::new(value))),
        Ok(Read::Absent { checked }) => Ok(OpenedSource::Finished(Box::new(FileResult {
            receipt: receipt(
                file,
                "absent",
                &progress.counts,
                Some(checked),
                progress.deferred,
            )?,
            counts: progress.counts,
            resume: Vec::new(),
        }))),
        Ok(Read::Unreadable { reason, .. }) => Ok(OpenedSource::Finished(Box::new(
            failed(context, cx, file, key, reason, deadline).await?,
        ))),
        Ok(Read::Unknown { what }) => Ok(OpenedSource::Finished(Box::new(
            failed(context, cx, file, key, what, deadline).await?,
        ))),
        Err(error) => {
            deadline.remaining()?;
            Ok(OpenedSource::Finished(Box::new(
                failed(context, cx, file, key, error.to_string(), deadline).await?,
            )))
        }
    }
}

async fn scan_forward(
    context: &ExecutionContext,
    cx: &NodeContext,
    file: &plan::File,
    key: &[u8],
    mut source: source::SourceFile,
    state: &mut ScanState,
    deadline: &Deadline,
) -> Result<Option<FileResult>> {
    loop {
        if file
            .anchor
            .as_ref()
            .is_some_and(|anchor| source.evidence().length >= anchor.length)
        {
            return Ok(None);
        }
        let bound = deadline.clone();
        let next = job(context, deadline, move |_| {
            let row = source.next(&bound)?;
            source.verify(&bound)?;
            Ok((source, row))
        })
        .await;
        let next = match next {
            Ok(value) => value,
            Err(error) => {
                deadline.remaining()?;
                return Ok(Some(
                    failed(context, cx, file, key, error.to_string(), deadline).await?,
                ));
            }
        };
        source = next.0;
        let Some(row) = next.1 else {
            return Ok(None);
        };
        let mut rowcx = cx.clone();
        rowcx.source = row.evidence.clone();
        let row_state = rows::RowState {
            kind: file.kind,
            family: file.family,
            key: key.to_vec(),
            counts: state.counts.clone(),
            want: state.want,
            replay: None,
        };
        let (planned, row, rowcx, row_state) = job(context, deadline, move |context| {
            let plan = rows::plan(context, &rowcx, &row, row_state.clone())?;
            match plan {
                rows::RowPlan::Commit(planned) => Ok((planned, row, rowcx, row_state)),
                _ => Err(scope::unreadable(
                    "import row",
                    "an advancing row was skipped",
                )),
            }
        })
        .await?;
        let planned = commit::row(context, rowcx, row, row_state, planned, deadline).await?;
        state.counts = planned.counts;
        if planned.reason.is_some() {
            state.reason = planned.reason;
        }
        add_resume(&mut state.resume, planned.resume);
        state.want = increment(state.want)?;
    }
}

async fn replay_deferred(
    context: &ExecutionContext,
    cx: &NodeContext,
    file: &plan::File,
    key: &[u8],
    checkpoint: &ImportCheckpoint,
    state: &mut ScanState,
    deadline: &Deadline,
) -> Result<()> {
    let path = file.path.clone();
    let bound = deadline.clone();
    let opened = job(context, deadline, move |_| {
        source::SourceFile::open(path, None, &bound)
    })
    .await?;
    let mut replay = batch::required(opened, "retained source for staged references")?;
    loop {
        let bound = deadline.clone();
        let next = job(context, deadline, move |_| {
            let row = replay.next(&bound)?;
            replay.verify(&bound)?;
            Ok((replay, row))
        })
        .await?;
        replay = next.0;
        let Some(row) = next.1 else {
            return Ok(());
        };
        if row.next_row > checkpoint.row_offset {
            return Ok(());
        }
        let mut rowcx = cx.clone();
        rowcx.source = row.evidence.clone();
        let row_state = rows::RowState {
            kind: file.kind,
            family: file.family,
            key: key.to_vec(),
            counts: state.counts.clone(),
            want: state.want,
            replay: Some(checkpoint.clone()),
        };
        let (planned, row, rowcx, row_state) = job(context, deadline, move |context| {
            let plan = rows::plan(context, &rowcx, &row, row_state.clone())?;
            Ok((plan, row, rowcx, row_state))
        })
        .await?;
        let planned = match planned {
            rows::RowPlan::Skipped => continue,
            rows::RowPlan::Deferred(cause) => {
                state.reason = Some(cause);
                continue;
            }
            rows::RowPlan::Commit(planned) => planned,
        };
        let planned = commit::row(context, rowcx, row, row_state, planned, deadline).await?;
        state.counts = planned.counts;
        add_resume(&mut state.resume, planned.resume);
        if planned.reason.is_some() {
            state.reason = planned.reason;
        }
        state.want = increment(state.want)?;
    }
}

fn finalize_reason(counts: &ImportCounts, deferred: u64, reason: Option<String>) -> Option<String> {
    if deferred > 0 {
        let cause = reason.unwrap_or_else(|| "referenced objects are not yet available".into());
        Some(format!(
            "{deferred} source rows remain deferred: {cause}; their exact original ranges and checkpoint are retained"
        ))
    } else if counts.unreadable > 0 && reason.is_none() {
        Some(format!(
            "{} source omissions remain; history --kind import.unreadable retains their original ranges",
            counts.unreadable
        ))
    } else if counts.unreadable == 0 {
        None
    } else {
        reason
    }
}

fn increment(want: Expected) -> Result<Expected> {
    let value = match want {
        Expected::Absent => 1,
        Expected::Revision(r) => r
            .value
            .get()
            .checked_add(1)
            .ok_or_else(|| scope::unreadable("import revision", "counter overflow"))?,
    };
    Ok(Expected::Revision(Revision {
        value: std::num::NonZeroU64::new(value)
            .ok_or_else(|| scope::unreadable("import revision", "zero revision"))?,
    }))
}
fn add_resume(into: &mut Vec<ImportResume>, facts: Vec<node::ResumeFact>) {
    for fact in facts {
        let provider = match fact.provider {
            Provider::Claude => "claude",
            Provider::Codex => "codex",
            Provider::SeCode => "secode",
            Provider::Acp => "acp",
        };
        let state = if fact.unsupported {
            "unsupported"
        } else if fact.native_reference.is_some() {
            "retained"
        } else {
            "missing"
        };
        if !into.iter().any(|old| {
            old.session == fact.session.as_str()
                && old.agent == fact.agent.as_str()
                && old.provider == provider
                && old.native_reference == fact.native_reference
                && old.state == state
        }) {
            into.push(ImportResume {
                session: fact.session.to_string(),
                agent: fact.agent.to_string(),
                provider: provider.into(),
                native_reference: fact.native_reference,
                state: state.into(),
            });
        }
    }
}

async fn failed(
    context: &ExecutionContext,
    cx: &NodeContext,
    file: &plan::File,
    key: &[u8],
    reason: String,
    deadline: &Deadline,
) -> Result<FileResult> {
    let progress = read_progress(context, cx, file.family, key, deadline).await?;
    Ok(FileResult {
        receipt: receipt(
            file,
            "unreadable",
            &progress.counts,
            Some(reason),
            progress.deferred,
        )?,
        counts: progress.counts,
        resume: Vec::new(),
    })
}
