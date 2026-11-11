//! A bounded source scan and replay of durable forward references.
use super::{rows, *};
pub(super) struct FileResult {
    pub receipt: ImportFamilyReceipt,
    pub counts: ImportCounts,
    pub resume: Vec<ImportResume>,
}
#[expect(
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
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
    let readcx = cx.clone();
    let readkey = key.clone();
    let family = file.family;
    let progress = job(context, deadline, move |context| {
        state::progress(context, &readcx, family, &readkey)
    })
    .await?;
    let checkpoint = progress.checkpoint;
    let open = checkpoint.clone();
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
    let mut source = match opened {
        Ok(Read::Present { value }) => value,
        Ok(Read::Absent { checked }) => {
            return Ok(FileResult {
                receipt: receipt(
                    &file,
                    "absent",
                    &progress.counts,
                    Some(checked),
                    progress.deferred,
                )?,
                counts: progress.counts,
                resume: Vec::new(),
            });
        }
        Ok(Read::Unreadable { reason, .. }) => {
            return failed(context, &cx, &file, &key, reason, deadline).await;
        }
        Ok(Read::Unknown { what }) => {
            return failed(context, &cx, &file, &key, what, deadline).await;
        }
        Err(error) => {
            deadline.remaining()?;
            return failed(context, &cx, &file, &key, error.to_string(), deadline).await;
        }
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
    let mut counts = progress.counts;
    let mut want = checkpoint.map(|p| p.expected).unwrap_or(Expected::Absent);
    let mut reason = None;
    let mut deferred;
    let mut resume = Vec::new();
    loop {
        if file
            .anchor
            .as_ref()
            .is_some_and(|anchor| source.evidence().length >= anchor.length)
        {
            break;
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
                return failed(context, &cx, &file, &key, error.to_string(), deadline).await;
            }
        };
        source = next.0;
        let Some(row) = next.1 else {
            break;
        };
        let mut rowcx = cx.clone();
        rowcx.source = row.evidence.clone();
        let rowkey = key.clone();
        let rowcounts = counts.clone();
        let kind = file.kind;
        let (planned, row, rowcx, state) = job(context, deadline, move |context| {
            let state = rows::RowState {
                kind,
                family,
                key: rowkey,
                counts: rowcounts,
                want,
                replay: None,
            };
            let plan = rows::plan(context, &rowcx, &row, state.clone())?;
            match plan {
                rows::RowPlan::Commit(planned) => Ok((planned, row, rowcx, state)),
                _ => Err(scope::unreadable(
                    "import row",
                    "an advancing row was skipped",
                )),
            }
        })
        .await?;
        let planned = commit::row(context, rowcx, row, state, planned, deadline).await?;
        counts = planned.counts;
        if planned.reason.is_some() {
            reason = planned.reason;
        }
        add_resume(&mut resume, planned.resume);
        want = increment(want)?;
    }
    let readcx = cx.clone();
    let readkey = key.clone();
    let progress = job(context, deadline, move |context| {
        state::progress(context, &readcx, family, &readkey)
    })
    .await?;
    deferred = progress.deferred;
    if deferred > 0 {
        let checkpoint = progress.checkpoint.ok_or_else(|| {
            scope::unreadable("staged source", "its durable checkpoint is absent")
        })?;
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
                break;
            };
            if row.next_row > checkpoint.row_offset {
                break;
            }
            let mut rowcx = cx.clone();
            rowcx.source = row.evidence.clone();
            let rowkey = key.clone();
            let rowcounts = counts.clone();
            let kind = file.kind;
            let end = checkpoint.clone();
            let (planned, row, rowcx, state) = job(context, deadline, move |context| {
                let state = rows::RowState {
                    kind,
                    family,
                    key: rowkey,
                    counts: rowcounts,
                    want,
                    replay: Some(end),
                };
                let plan = rows::plan(context, &rowcx, &row, state.clone())?;
                Ok((plan, row, rowcx, state))
            })
            .await?;
            let planned = match planned {
                rows::RowPlan::Skipped => continue,
                rows::RowPlan::Deferred(cause) => {
                    reason = Some(cause);
                    continue;
                }
                rows::RowPlan::Commit(planned) => planned,
            };
            {
                let planned = commit::row(context, rowcx, row, state, planned, deadline).await?;
                counts = planned.counts;
                add_resume(&mut resume, planned.resume);
                if planned.reason.is_some() {
                    reason = planned.reason;
                }
                want = increment(want)?;
            }
        }
        let readcx = cx.clone();
        let readkey = key.clone();
        deferred = job(context, deadline, move |context| {
            state::progress(context, &readcx, family, &readkey)
        })
        .await?
        .deferred;
    }
    if deferred > 0 {
        let cause = reason.unwrap_or_else(|| "referenced objects are not yet available".into());
        reason = Some(format!(
            "{deferred} source rows remain deferred: {cause}; their exact original ranges and checkpoint are retained"
        ));
    } else if counts.unreadable > 0 && reason.is_none() {
        reason = Some(format!(
            "{} source omissions remain; history --kind import.unreadable retains their original ranges",
            counts.unreadable
        ));
    } else if counts.unreadable == 0 {
        reason = None;
    }
    Ok(FileResult {
        receipt: receipt(&file, "present", &counts, reason, deferred)?,
        counts,
        resume,
    })
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
    let cx_read = cx.clone();
    let key = key.to_vec();
    let family = file.family;
    let progress = job(context, deadline, move |context| {
        state::progress(context, &cx_read, family, &key)
    })
    .await?;
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
