//! Development load: pinned provider capture and the ordinary native Atlas owner.
use super::*;
use se_types::{AgentId, NativePath, ProviderSessionId, SessionId, Sha256};
use std::{
    fs::OpenOptions,
    io::Write,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

pub struct Source {
    agent: AgentId,
    session: SessionId,
    conversation: ProviderSessionId,
    path: NativePath,
    source: RecordId,
    pin: Option<se_proc::NativeSourcePin>,
}
pub fn prepare(
    f: &Fixture,
    writer: &mut SqliteDirect,
    lease: &Lease,
    agent: AgentId,
    session: SessionId,
) -> Result<Source, Box<dyn std::error::Error>> {
    let path = f.home.join(format!("capture-{session}.jsonl"));
    std::fs::write(&path, b"")?;
    let pin = se_proc::NativeSourcePin::open(&path)?.ok_or("capture file absent")?;
    let source = support::session::record()?;
    writer.append(
        f.batch(
            f.owner_project(),
            None,
            vec![support::session::source(
                source,
                &session,
                &pin.identity(),
                Expected::Absent,
            )],
        )?,
        lease,
    )?;
    Ok(Source {
        conversation: ProviderSessionId::new(format!("provider-{agent}"))?,
        agent,
        session,
        path: NativePath::from_local(path)?,
        source,
        pin: Some(pin),
    })
}
impl Source {
    pub async fn bind(&mut self, capture: &CaptureHandle, f: &Fixture) -> Check {
        let pin = self.pin.take().ok_or("capture pin already bound")?;
        capture
            .bind(
                TranscriptPin {
                    identity: SessionIdentity {
                        project: f.project.clone(),
                        agent: self.agent.clone(),
                        session: self.session.clone(),
                    },
                    conversation: self.conversation.clone(),
                    path: self.path.clone(),
                    file_identity: Sha256::from_bytes(pin.identity()),
                },
                self.source,
                pin,
                &bound()?,
            )
            .await?;
        Ok(())
    }
}
pub fn register_root(f: &Fixture, writer: &mut SqliteDirect, lease: &Lease) -> Check {
    // Index the actual checked-out Rust project, including its Git history.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let mut batch = f.batch(
        f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
        None,
        vec![EventBody::ProjectUpdated {
            project: f.project.clone(),
            name: "Measured project".into(),
            roots: vec![Root {
                path: NativePath::from_local(root.clone())?,
                canonical_key: root.as_os_str().as_encoded_bytes().to_vec(),
            }],
            expected: revision(1)?,
        }],
    )?;
    for event in &mut batch.events {
        event.header.door = Door::Import;
    }
    writer.append(batch, lease)?;
    Ok(())
}
async fn counts(
    context: &ExecutionContext,
    project: &se_types::ProjectId,
) -> Result<Value, se_types::SeError> {
    let context = context.clone();
    let pool = context.blocking.clone();
    let project = project.clone();
    pool.run(BlockingClass::Foreground, &bound().map_err(|e| se_types::SeError::invalid("measurement deadline", &e.to_string()))?, move || {
        let summary = context.atlas.summary(&project, None)?;
        let ticket = context.atlas.records.ticket()?;
        let mut observed = None;
        context.atlas.with_reader(&project, None, ticket, &mut |cache, _, fresh| {
            cache.read(Instant::now() + Duration::from_secs(1), |sql| {
                let mut read_count = |table: &str| -> se_types::Result<i64> {
                    sql.prepare(&format!("SELECT count(*) FROM {table}"))?.query_row([], |r| r.get(0)).map_err(|e| se_core::scope::unreadable("development Atlas count", &e.to_string()))
                };
                observed = Some(json!({"unix_ms":now().map_err(|e| se_types::SeError::invalid("measurement clock", &e.to_string()))? as f64/1000.0,"records":read_count("records")?,"files":read_count("files")?,"fresh":fresh,"summary":summary}));
                Ok(())
            })
        })?;
        observed.ok_or_else(|| se_types::SeError::invalid("Atlas observation", "a cache read"))
    }).await
}
pub async fn ready(context: &ExecutionContext, project: &se_types::ProjectId) -> Check {
    let end = Instant::now() + Duration::from_secs(180);
    loop {
        let observed = counts(context, project).await;
        if matches!(&observed, Ok(value) if value["files"].as_i64().is_some_and(|n| n>0)) {
            return Ok(());
        }
        if Instant::now() >= end {
            return Err(format!("native Atlas root not indexed: {observed:?}").into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
pub async fn run(
    f: &Fixture,
    context: &ExecutionContext,
    capture: &CaptureHandle,
    sources: &[Source],
    done: &AtomicBool,
) -> Check {
    // The caller supplies the observed real-session p95 active-minute event rate.
    let per_minute: f64 = std::env::var("SE_MEASURE_CAPTURE_PER_MINUTE")?.parse()?;
    require(
        per_minute.is_finite() && per_minute > 0.0,
        "measured capture rate absent or invalid",
    )?;
    let interval = Duration::from_secs_f64(60.0 / (per_minute * sources.len() as f64));
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut hooks = Vec::new();
    let mut atlas = Vec::new();
    let mut failures = Vec::new();
    let mut n = 0usize;
    while !done.load(Ordering::Relaxed) {
        tick.tick().await;
        let source = &sources[n % sources.len()];
        let row = json!({"type":"assistant","uuid":format!("measured-{n}"),"sessionId":source.conversation.as_str(),"message":{"role":"assistant","content":format!("provider capture record {n}")}});
        let mut bytes = serde_json::to_vec(&row)?;
        bytes.push(b'\n');
        let mut file = OpenOptions::new()
            .append(true)
            .open(source.path.to_local()?)?;
        file.write_all(&bytes)?;
        let mut admission = f.self_scope(&source.agent).admission;
        admission.session = Some(source.session.clone());
        let started = now()? as f64 / 1000.0;
        let receipt = capture
            .catch_up(
                admission,
                source.conversation.clone(),
                source.path.clone(),
                &bound()?,
            )
            .await?;
        require(
            !receipt.capture_commits.is_empty(),
            "paced provider record did not commit",
        )?;
        hooks.push(json!({"started_unix_ms":started,"finished_unix_ms":now()? as f64/1000.0,"source_index":n % sources.len(),"commits":receipt.capture_commits}));
        match counts(context, &f.project).await {
            Ok(value) => atlas.push(value),
            Err(error) => {
                failures.push(json!({"unix_ms":now()? as f64/1000.0,"error":error.to_string()}))
            }
        }
        n += 1;
    }
    let report = json!({"capture_events_per_session_minute":per_minute,"sources":sources.len(),"hooks":hooks,"atlas":atlas,"atlas_read_refusals":failures});
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/judge-diagnostics");
    std::fs::create_dir_all(&root)?;
    std::fs::write(
        root.join("mixed-background.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    let writes: Value = serde_json::from_slice(&std::fs::read(root.join("mcp-writers.json"))?)?;
    let clients = writes["cohorts"]["8"]
        .as_array()
        .ok_or("eight-writer observations absent")?;
    for name in ["stateengine_msg_send", "stateengine_working_state_set"] {
        // Use the intersection of all eight timed windows to prove concurrent load.
        let mut first = 0.0f64;
        let mut last = f64::INFINITY;
        for client in clients {
            let rows = client["samples"][name]
                .as_array()
                .ok_or("timed writes absent")?;
            first = first.max(
                rows.first().ok_or("empty timed writes")?["started_unix_ms"]
                    .as_f64()
                    .ok_or("write timestamp absent")?,
            );
            let row = rows.last().ok_or("empty timed writes")?;
            last = last.min(
                row["started_unix_ms"]
                    .as_f64()
                    .ok_or("write timestamp absent")?
                    + row["ms"].as_f64().ok_or("write timing absent")?,
            );
        }
        require(
            last - first >= 9_000.0,
            "eight simultaneous writers did not span the capture-rate window",
        )?;
        let overlapping_hooks = hooks
            .iter()
            .filter(|row| {
                row["started_unix_ms"].as_f64().is_some_and(|t| t >= first)
                    && row["finished_unix_ms"].as_f64().is_some_and(|t| t <= last)
            })
            .count();
        require(
            overlapping_hooks >= 8,
            "too few provider captures during the timed write window",
        )?;
        let counts: Vec<i64> = atlas
            .iter()
            .filter(|row| {
                row["unix_ms"]
                    .as_f64()
                    .is_some_and(|t| t >= first && t <= last)
            })
            .filter_map(|row| row["records"].as_i64())
            .collect();
        require(
            counts.windows(2).filter(|pair| pair[1] > pair[0]).count() >= 2,
            "native Atlas record indexing did not advance alongside timed writers",
        )?;
    }
    Ok(())
}
