//! Protects: high-volume native metadata is counted and batched without payload retention or cursor loss.
#![cfg(all(feature = "listener", target_os = "linux"))]
use se_core::{
    commit::Cx,
    ops::{AgentShow, agent_status},
};
use se_host::*;
use se_store::*;
use se_types::{NativePath, ProviderSessionId, Sha256};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs::OpenOptions, io::Write, time::Instant};
#[path = "support/wave2_host_fixture.rs"]
mod support;
use support::*;

fn line(value: Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = serde_json::to_vec(&value)?;
    bytes.push(b'\n');
    Ok(bytes)
}
fn noise(kind: &str) -> Value {
    if matches!(kind, "api-request-blob" | "queue-operation") {
        json!({"type":kind,"operation":"dequeue","hash":"ab".repeat(32),"content":"PRIVATE_NOISE_PAYLOAD"})
    } else {
        json!({"type":kind,"hash":"ab".repeat(32)})
    }
}
fn measured(bytes: &mut Vec<u8>, kind: &str, expected: &mut BTreeMap<String, Value>) -> Check {
    let raw = line(noise(kind))?;
    let position = json!({"offset":bytes.len(),"length":raw.len()});
    let summary = expected
        .entry(kind.into())
        .or_insert_with(|| json!({"count":0,"first_position":position,"last_position":position}));
    summary["count"] = json!(summary["count"].as_u64().ok_or("count")? + 1);
    summary["last_position"] = position;
    bytes.extend(raw);
    Ok(())
}
fn check_summary(body: &Value, want: &Value) -> Check {
    require(
        body["schema"] == "se.transcript-event/v1",
        "aggregate schema missing",
    )?;
    for field in ["count", "first_position", "last_position"] {
        require(
            body[field] == want[field],
            format!("wrong aggregate {field}: {body}"),
        )?;
    }
    require(
        body["position"] == want["last_position"],
        "aggregate position is not its last native record",
    )?;
    require(
        !body.to_string().contains("PRIVATE_NOISE_PAYLOAD"),
        "noise payload leaked",
    )?;
    Ok(())
}

struct NoiseSeed {
    path: std::path::PathBuf,
    bytes: Vec<u8>,
    expected: BTreeMap<String, Value>,
    source: RecordId,
}

fn seed_noise_session(
    f: &Fixture,
    s: &se_types::SessionId,
    conversation: &ProviderSessionId,
) -> Result<(NoiseSeed, se_proc::NativeSourcePin), Box<dyn std::error::Error>> {
    let mut bytes = line(
        json!({"type":"user","sessionId":conversation.as_str(),"uuid":"noise-before","message":{"role":"user","content":"real user"}}),
    )?;
    let mut expected = BTreeMap::new();
    for n in 0..1000 {
        measured(
            &mut bytes,
            if n % 2 == 0 {
                "queue-operation"
            } else {
                "api-request-blob"
            },
            &mut expected,
        )?;
    }
    bytes.extend(line(json!({"type":"assistant","sessionId":conversation.as_str(),"uuid":"noise-after","message":{"role":"assistant","content":"real assistant"}}))?);
    let path = f.home.join("transcript.jsonl");
    std::fs::write(&path, &bytes)?;
    let pin = se_proc::NativeSourcePin::open(&path)?.ok_or("source absent")?;
    let source = session::record()?;
    let (mut direct, lease) = direct(f)?;
    direct.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request(&format!(
                "fixture-claude_noise_independent-92-{}",
                serial()
            ))?),
            vec![
                EventBody::ProfileSaved {
                    agent: f.a.clone(),
                    profile: Profile {
                        provider_settings: Default::default(),
                        provider: Provider::Claude,
                        model: None,
                        permission: PermissionProfile::WorkspaceWrite,
                        harness: None,
                        named_profile: "default".into(),
                        effort: None,
                        external: false,
                    },
                    expected: Expected::Absent,
                },
                session::prepared(f, s, &f.a),
                session::activated(s)?,
                session::source(source, s, &pin.identity(), Expected::Absent),
            ],
        )?,
        &*lease,
    )?;
    direct.close()?;
    drop(lease);
    Ok((
        NoiseSeed {
            path,
            bytes,
            expected,
            source,
        },
        pin,
    ))
}

fn verify_initial_noise_rows(rows: &[StoredEvent], expected: &BTreeMap<String, Value>) -> Check {
    require(
        rows.len() == 4,
        "noise aggregate or real chat count differs",
    )?;
    let mut counts = BTreeMap::new();
    let mut chat = Vec::new();
    for row in rows {
        let EventBody::SessionTurn {
            role,
            text: StoredText::Present(text),
            ..
        } = &row.body
        else {
            return Err("unexpected captured body".into());
        };
        if *role == Role::System {
            let body: Value = serde_json::from_str(text)?;
            let kind = body["kind"].as_str().ok_or("aggregate kind")?;
            check_summary(&body, expected.get(kind).ok_or("unexpected noise kind")?)?;
            counts.insert(
                kind.to_owned(),
                body["count"].as_u64().ok_or("aggregate count")?,
            );
        } else {
            require(
                matches!(role, Role::User | Role::Assistant),
                "noise became tool/chat",
            )?;
            chat.push(text.clone());
        }
    }
    require(
        counts.len() == 2 && counts.values().all(|n| *n == 500),
        "noise count not exact",
    )?;
    chat.sort();
    require(
        chat == vec!["real assistant", "real user"],
        "noise replaced chat",
    )
}

struct NoiseCx<'a> {
    f: &'a Fixture,
    capture: &'a CaptureHandle,
    execution: &'a ExecutionContext,
    scope: &'a ReadScope,
    admission: &'a Admission,
    conversation: ProviderSessionId,
    native: NativePath,
}

async fn verify_tail_queue_and_refusal(
    cx: &NoiseCx<'_>,
    seeded: &NoiseSeed,
    before: ProjectionRecord,
) -> Check {
    let (f, capture, execution, scope, admission) =
        (cx.f, cx.capture, cx.execution, cx.scope, cx.admission);
    let (conversation, native) = (cx.conversation.clone(), cx.native.clone());
    let (path, initial_bytes_len, source) = (&seeded.path, seeded.bytes.len(), seeded.source);
    let mut tail = Vec::new();
    let mut tail_expected = BTreeMap::new();
    for _ in 0..4 {
        measured(&mut tail, "file-history-snapshot", &mut tail_expected)?;
    }
    let mut file = OpenOptions::new().append(true).open(path)?;
    file.write_all(&tail)?;
    file.sync_all()?;
    capture
        .catch_up(
            admission.clone(),
            conversation.clone(),
            native.clone(),
            &bound()?,
        )
        .await?;
    let mut pending = execution.reader.snapshot(scope.clone())?;
    let current = present(pending.capture_source(source)?)?;
    require(
        current.revision == before.revision
            && current.current.header.event == before.current.header.event,
        "live noise-only EOF advanced capture progress",
    )?;
    require(
        pending
            .turns(f.a.clone(), budget(100, 200_000, None)?)?
            .items()
            .len()
            == 4,
        "live noise-only tail created a standalone commit",
    )?;
    pending.close()?;
    file.write_all(&line(
        json!({"type":"mode","content":"PRIVATE_NOISE_PAYLOAD"}),
    )?)?;
    file.sync_all()?;
    let final_batch = capture
        .catch_up(
            admission.clone(),
            conversation.clone(),
            native.clone(),
            &bound()?,
        )
        .await?;
    require(
        final_batch.capture_commits.len() == 1,
        "individual continuity record did not batch preceding noise",
    )?;
    let mut after = execution.reader.snapshot(scope.clone())?;
    verify_tail_status_view(f, &mut after, admission, &tail_expected, initial_bytes_len)?;
    after.close()?;
    verify_queue_and_refusal(cx, seeded, &mut file).await
}

fn verify_tail_status_view(
    f: &Fixture,
    after: &mut impl Snapshot,
    admission: &Admission,
    tail_expected: &BTreeMap<String, Value>,
    initial_bytes_len: usize,
) -> Check {
    let shown = serde_json::to_value(agent_status::show(
        AgentShow {
            target_agent_id: Some(f.a.clone()),
        },
        &mut Cx {
            read: after,
            admission,
        },
    )?)?;
    let view = &shown["agent"]["value"]["session"]["transcript_events"];
    require(view["state"] == "present", "noise view unavailable")?;
    let values = view["value"].as_array().ok_or("noise view not an array")?;
    require(
        values.len() == 4,
        "wrong number of aggregate and individual metadata records",
    )?;
    let mode = values
        .iter()
        .find(|v| v["kind"] == "mode")
        .ok_or("mode missing")?;
    require(
        mode.get("count").is_none()
            && mode.get("first_position").is_none()
            && mode.get("last_position").is_none(),
        "individual record carried aggregate fields",
    )?;
    let tail_summary = values
        .iter()
        .find(|v| v["kind"] == "file-history-snapshot" && v["count"] == 4)
        .ok_or("live tail count lost")?;
    let mut expected_tail = tail_expected
        .get("file-history-snapshot")
        .ok_or("tail expectation missing")?
        .clone();
    for name in ["first_position", "last_position"] {
        let offset = expected_tail[name]["offset"]
            .as_u64()
            .ok_or("tail offset")?;
        expected_tail[name]["offset"] = json!(offset + initial_bytes_len as u64);
    }
    check_summary(tail_summary, &expected_tail)?;
    require(
        after
            .turns(f.a.clone(), budget(100, 200_000, None)?)?
            .items()
            .len()
            == 6,
        "tail batch lost records",
    )
}

async fn verify_queue_and_refusal(
    cx: &NoiseCx<'_>,
    seeded: &NoiseSeed,
    file: &mut std::fs::File,
) -> Check {
    let (f, capture, execution, scope, admission) =
        (cx.f, cx.capture, cx.execution, cx.scope, cx.admission);
    let (conversation, native, source) =
        (cx.conversation.clone(), cx.native.clone(), seeded.source);
    file.write_all(&line(json!({"type":"queue-operation","operation":"enqueue","sessionId":conversation.as_str(),"timestamp":"2026-11-04T00:00:00.000Z","content":"QUEUED_INPUT_MUST_SURVIVE"}))?)?;
    file.sync_all()?;
    capture
        .catch_up(
            admission.clone(),
            conversation.clone(),
            native.clone(),
            &bound()?,
        )
        .await?;
    let mut enqueued = execution.reader.snapshot(scope.clone())?;
    let queued_rows = enqueued.turns(f.a.clone(), budget(100, 200_000, None)?)?;
    require(
        queued_rows.items().len() >= 7,
        "standalone queue enqueue was dropped",
    )?;
    let queued = queued_rows
        .items()
        .iter()
        .find(|row| matches!(&row.body, EventBody::SessionTurn { text: StoredText::Present(text), .. } if text.contains("QUEUED_INPUT_MUST_SURVIVE")))
        .ok_or("queued input disappeared without a later user record")?;
    let queued_id = queued.header.event.clone();
    enqueued.close()?;
    file.write_all(&line(json!({"type":"user","sessionId":conversation.as_str(),"uuid":"queue-consumed-user","message":{"role":"user","content":"QUEUED_INPUT_MUST_SURVIVE"}}))?)?;
    file.sync_all()?;
    capture
        .catch_up(
            admission.clone(),
            conversation.clone(),
            native.clone(),
            &bound()?,
        )
        .await?;
    let mut both = execution.reader.snapshot(scope.clone())?;
    let both_rows = both.turns(f.a.clone(), budget(100, 200_000, None)?)?;
    require(
        both_rows.items().len() >= 8
            && both_rows
                .items()
                .iter()
                .any(|row| row.header.event == queued_id),
        "native user replaced or erased its prior queue provenance",
    )?;
    require(
        both_rows.items().iter().any(|row| matches!(&row.body, EventBody::SessionTurn { vendor_ref, role: Role::User, text: StoredText::Present(text), .. } if vendor_ref == "queue-consumed-user" && text == "QUEUED_INPUT_MUST_SURVIVE")),
        "native user UUID was lost after its queue input was captured",
    )?;
    let before_refusal = present(both.capture_source(source)?)?;
    let retained_rows = both_rows.items().len();
    both.close()?;
    file.write_all(&line(
        json!({"type":"file-history-snapshot","content":"PRIVATE_NOISE_PAYLOAD"}),
    )?)?;
    file.sync_all()?;
    require(
        capture
            .catch_up(admission.clone(), conversation, native, &bound()?)
            .await
            .is_err(),
        "content-bearing non-allowlisted noise was silently dropped",
    )?;
    let mut refused = execution.reader.snapshot(scope.clone())?;
    let unchanged = present(refused.capture_source(source)?)?;
    require(
        unchanged.revision == before_refusal.revision
            && unchanged.current.header.event == before_refusal.current.header.event,
        "refused noise advanced the capture cursor",
    )?;
    require(
        refused
            .turns(f.a.clone(), budget(100, 200_000, None)?)?
            .items()
            .len()
            == retained_rows,
        "refused noise changed captured history",
    )?;
    refused.close()?;
    Ok(())
}

/// Protects: a thousand noise records take two capture submissions, exact per-kind counts, and one cursor advance per batch.
#[test]
fn noise_accompanies_real_turns_and_a_live_noise_only_tail_waits() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let s = session::session()?;
    let conversation = ProviderSessionId::new(format!("provider-{}", f.a.as_str()))?;
    let (seeded, pin) = seed_noise_session(&f, &s, &conversation)?;
    let native = NativePath::from_local(seeded.path.clone())?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut host =
            HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        let capture = host.capture_handle();
        capture
            .bind(
                TranscriptPin {
                    identity: SessionIdentity {
                        project: f.project.clone(),
                        agent: f.a.clone(),
                        session: s.clone(),
                    },
                    conversation: conversation.clone(),
                    path: native.clone(),
                    file_identity: Sha256::from_bytes(pin.identity()),
                },
                seeded.source,
                pin,
                &bound()?,
            )
            .await?;
        let execution = host.execution_context();
        let mut scope = f.self_scope(&f.a);
        scope.admission.session = Some(s);
        let admission = scope.admission.clone();
        let stop = host.local_stop();
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let consumer = async {
            let result: Check = async {
                let began = Instant::now();
                let drain = capture
                    .catch_up(admission.clone(), conversation.clone(), native.clone(), &bound()?)
                    .await;
                let elapsed = began.elapsed();
                match &drain {
                    Ok(value) => eprintln!(
                        "noise_bytes={} native_noise_records=1000 capture_writer_submissions={} drain_seconds={:.6} complete=true",
                        seeded.bytes.len(),
                        value.capture_commits.len(),
                        elapsed.as_secs_f64()
                    ),
                    Err(error) => {
                        let committed = match error.body.detail() {
                            se_types::Detail::CaptureIncomplete(detail) => Some(detail.committed_events.len()),
                            _ => None,
                        };
                        eprintln!(
                            "noise_bytes={} native_noise_records=1000 capture_writer_submissions={committed:?} drain_seconds={:.6} complete=false",
                            seeded.bytes.len(),
                            elapsed.as_secs_f64()
                        );
                    }
                }
                let drained = drain?;
                require(
                    drained.capture_commits.len() == 2,
                    "noise was committed individually instead of with its accompanying turn",
                )?;
                let mut snapshot = execution.reader.snapshot(scope.clone())?;
                let rows = snapshot.turns(f.a.clone(), budget(100, 200_000, None)?)?;
                verify_initial_noise_rows(rows.items(), &seeded.expected)?;
                let before = present(snapshot.capture_source(seeded.source)?)?;
                snapshot.close()?;
                let cx = NoiseCx {
                    f: &f,
                    capture: &capture,
                    execution: &execution,
                    scope: &scope,
                    admission: &admission,
                    conversation,
                    native,
                };
                verify_tail_queue_and_refusal(&cx, &seeded, before).await
            }
            .await;
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), consumer).await;
        drop(capture);
        drop(execution);
        let report = exit.finish(&bound()?).await;
        require(
            report.transport_closed && report.endpoint_retired,
            "noise host cleanup incomplete",
        )?;
        result
    })
}
