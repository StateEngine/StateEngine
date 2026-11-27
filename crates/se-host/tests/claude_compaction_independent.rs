//! Protects: native compaction and future metadata retain evidence without becoming chat or blocking capture.
#![cfg(all(feature = "listener", target_os = "linux"))]
use se_core::{
    commit::Cx,
    ops::{
        AgentShow,
        continuity::{Resume, resume},
    },
};
use se_host::*;
use se_store::*;
use se_types::{NativePath, ProviderSessionId, Sha256, UnixMicros};
use serde_json::{Value, json};
use sha2::{Digest, Sha256 as Hasher};
use std::{fs::OpenOptions, io::Write};
#[path = "support/wave2_host_fixture.rs"]
mod support;
use support::*;

const COMPACT: &[u8] = include_bytes!("fixtures/claude-2.1.317-compact-boundary.jsonl");
const CONVERSATION: &str = "00000000-0000-4000-8000-000000000001";

fn line(value: Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = serde_json::to_vec(&value)?;
    bytes.push(b'\n');
    Ok(bytes)
}
fn chat(kind: &str, id: &str, text: &str) -> Value {
    json!({"type":kind,"sessionId":CONVERSATION,"uuid":id,"message":{"role":kind,"content":text}})
}
fn read_value(value: &Value) -> Result<&Value, Box<dyn std::error::Error>> {
    require(
        value["state"] == "present",
        format!("unmeasured metadata read: {value}"),
    )?;
    value
        .get("value")
        .ok_or_else(|| "Read value missing".into())
}
fn summary(value: &Value, offset: u64) -> Check {
    let events = read_value(&value["transcript_events"])?;
    let items = events.as_array().ok_or("metadata array absent")?;
    require(
        items.len() == 20,
        "metadata window must retain newest twenty",
    )?;
    require(
        read_value(&value["transcript_events_omitted"])? == &json!(6),
        "metadata omission count is not exact",
    )?;
    require(
        items.iter().all(|v| v["kind"] == "future-provider-record"),
        "newest window contains displaced compaction",
    )?;
    let compact = read_value(&value["last_compaction"])?;
    require(
        compact["kind"] == "system" && compact["subtype"] == "compact_boundary",
        "last compaction disappeared outside newest window",
    )?;
    require(
        compact["position"] == json!({"offset":offset,"length":COMPACT.len()}),
        "compaction native position changed",
    )?;
    require(
        compact["event_id"].is_string() && compact["session_id"].is_string(),
        "metadata identity absent",
    )?;
    Ok(())
}

struct CompactionSeed {
    path: std::path::PathBuf,
    bytes: Vec<u8>,
    compact_offset: u64,
    source: RecordId,
}

fn seed_compaction_session(
    f: &Fixture,
    s: &se_types::SessionId,
    broken: bool,
) -> Result<(CompactionSeed, se_proc::NativeSourcePin), Box<dyn std::error::Error>> {
    let path = f.home.join("transcript.jsonl");
    let mut bytes = line(chat(
        "user",
        "before-compact",
        "real user before compaction",
    ))?;
    let compact_offset = bytes.len() as u64;
    if !broken {
        require(
            format!("{:x}", Hasher::digest(COMPACT))
                == "0219f726a87e8a3783d814608f2758f69ea9aadb591e15d7321cfa7f1c0167b1",
            "retained stock compaction record changed",
        )?;
        bytes.extend_from_slice(COMPACT);
        for n in 0..25 {
            bytes.extend(line(json!({"type":"future-provider-record","sessionId":CONVERSATION,"uuid":format!("future-{n}"),"content":"PRIVATE_PROVIDER_PAYLOAD","opaque":"PRIVATE_PROVIDER_PAYLOAD"}))?);
        }
        bytes.extend(line(chat(
            "assistant",
            "after-compact",
            "real assistant after compaction",
        ))?);
    }
    std::fs::write(&path, &bytes)?;
    let pin = se_proc::NativeSourcePin::open(&path)?.ok_or("native source absent")?;
    let source = session::record()?;
    let (mut direct, lease) = direct(f)?;
    let mut prepared = session::prepared(f, s, &f.a);
    if let EventBody::SessionPrepared { native_ref, .. } = &mut prepared {
        *native_ref = CONVERSATION.into();
    }
    direct.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request(&format!(
                "fixture-claude_compaction_independent-110-{}",
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
                prepared,
                session::activated(s)?,
                session::source(source, s, &pin.identity(), Expected::Absent),
            ],
        )?,
        &*lease,
    )?;
    direct.close()?;
    drop(lease);
    Ok((
        CompactionSeed {
            path,
            bytes,
            compact_offset,
            source,
        },
        pin,
    ))
}

fn verify_captured_events(
    items: &[StoredEvent],
    bytes: &[u8],
) -> Result<(Vec<String>, usize), Box<dyn std::error::Error>> {
    let mut chat_text = Vec::new();
    let mut metadata = 0;
    for event in items {
        let EventBody::SessionTurn {
            role,
            text: StoredText::Present(text),
            evidence,
            ..
        } = &event.body
        else {
            return Err("unexpected captured event".into());
        };
        if *role == Role::System {
            let body: Value = serde_json::from_str(text)?;
            require(
                body["schema"] == "se.transcript-event/v1",
                "metadata schema absent",
            )?;
            require(
                !text.contains("PRIVATE_PROVIDER_PAYLOAD")
                    && !text.contains("Conversation compacted")
                    && !text.contains("compactMetadata"),
                "provider content leaked into metadata",
            )?;
            metadata += 1;
        } else {
            require(
                matches!(role, Role::User | Role::Assistant),
                "tool became chat",
            )?;
            chat_text.push(text.clone());
        }
        let start = usize::try_from(evidence.offset)?;
        let end = start + usize::try_from(evidence.length)?;
        let digest: [u8; 32] = Hasher::digest(&bytes[start..end]).into();
        require(
            evidence.sha256 == Some(digest),
            "native evidence digest differs",
        )?;
    }
    Ok((chat_text, metadata))
}

struct CompactionCx<'a> {
    f: &'a Fixture,
    capture: &'a CaptureHandle,
    execution: &'a ExecutionContext,
    scope: &'a ReadScope,
    admitted: &'a Admission,
    conversation: &'a ProviderSessionId,
    native: &'a NativePath,
}

async fn verify_broken_tail(
    cx: &CompactionCx<'_>,
    seeded: &CompactionSeed,
    before: ProjectionRecord,
    invalid: &[u8],
) -> Check {
    let (f, capture, execution, scope, admitted, conversation, native) = (
        cx.f,
        cx.capture,
        cx.execution,
        cx.scope,
        cx.admitted,
        cx.conversation,
        cx.native,
    );
    let (path, source) = (&seeded.path, seeded.source);
    let mut file = OpenOptions::new().append(true).open(path)?;
    file.write_all(invalid)?;
    file.sync_all()?;
    require(
        capture
            .catch_up(
                admitted.clone(),
                conversation.clone(),
                native.clone(),
                &bound()?,
            )
            .await
            .is_err(),
        "broken JSON/framing/known chat was silently accepted",
    )?;
    let mut after = execution.reader.snapshot(scope.clone())?;
    let current = present(after.capture_source(source)?)?;
    require(
        current.revision == before.revision
            && current.current.header.event == before.current.header.event,
        "refused record advanced durable capture progress",
    )?;
    require(
        after
            .turns(f.a.clone(), budget(100, 200_000, None)?)?
            .items()
            .len()
            == 1,
        "refused record fabricated a turn",
    )?;
    after.close()?;
    Ok(())
}

fn verify_clean_compaction(
    f: &Fixture,
    snapshot: &mut impl Snapshot,
    admitted: &Admission,
    mut chat_text: Vec<String>,
    metadata: usize,
    compact_offset: u64,
) -> Check {
    chat_text.sort();
    require(
        chat_text
            == vec![
                "real assistant after compaction",
                "real user before compaction",
            ]
            && metadata == 26,
        "metadata polluted or replaced chat",
    )?;
    let mut cx = Cx {
        read: snapshot,
        admission: admitted,
    };
    let resumed = serde_json::to_value(resume(
        Resume {
            source_failure: None,
            limit: 20,
            since: None,
            byte_budget: 65536,
            preview_agent: None,
        },
        UnixMicros::new(u64::try_from(now()?)?)?,
        &mut cx,
    )?)?;
    summary(&resumed, compact_offset)?;
    require(
        resumed["complete"] == true,
        "exact bounded metadata window became partial",
    )?;
    let recent = resumed["recent_turns"]
        .as_array()
        .ok_or("recent turns absent")?;
    require(
        recent.len() == 2
            && recent
                .iter()
                .all(|v| v["role"] == "user" || v["role"] == "assistant"),
        "resume promoted metadata into recent turns",
    )?;
    let shown = serde_json::to_value(se_core::ops::agent_status::show(
        AgentShow {
            target_agent_id: Some(f.a.clone()),
        },
        &mut cx,
    )?)?;
    summary(&read_value(&shown["agent"])?["session"], compact_offset)
}

async fn run_compaction_checks(
    cx: &CompactionCx<'_>,
    seeded: &CompactionSeed,
    broken: Option<Vec<u8>>,
) -> Check {
    let first = cx
        .capture
        .catch_up(
            cx.admitted.clone(),
            cx.conversation.clone(),
            cx.native.clone(),
            &bound()?,
        )
        .await?;
    require(
        first.capture_commits.len() == if broken.is_some() { 1 } else { 28 },
        "capture lost records or promoted tool data",
    )?;
    let mut before_replay = cx.execution.reader.snapshot(cx.scope.clone())?;
    let committed = present(before_replay.capture_source(seeded.source)?)?;
    before_replay.close()?;
    cx.capture
        .catch_up(
            cx.admitted.clone(),
            cx.conversation.clone(),
            cx.native.clone(),
            &bound()?,
        )
        .await?;
    let mut snapshot = cx.execution.reader.snapshot(cx.scope.clone())?;
    let repeated = present(snapshot.capture_source(seeded.source)?)?;
    require(
        repeated.revision == committed.revision
            && repeated.current.header.event == committed.current.header.event,
        "capture replay advanced durable progress",
    )?;
    let page = snapshot.turns(cx.f.a.clone(), budget(100, 200_000, None)?)?;
    require(
        page.items().len() == if broken.is_some() { 1 } else { 28 },
        "capture replay duplicated durable events",
    )?;
    let (chat_text, metadata) = verify_captured_events(page.items(), &seeded.bytes)?;
    if let Some(invalid) = broken {
        let before = present(snapshot.capture_source(seeded.source)?)?;
        snapshot.close()?;
        verify_broken_tail(cx, seeded, before, &invalid).await?;
    } else {
        verify_clean_compaction(
            cx.f,
            &mut snapshot,
            cx.admitted,
            chat_text,
            metadata,
            seeded.compact_offset,
        )?;
        snapshot.close()?;
    }
    Ok(())
}

fn exercise(broken: Option<Vec<u8>>) -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let s = session::session()?;
    let conversation = ProviderSessionId::new(CONVERSATION)?;
    let (seeded, pin) = seed_compaction_session(&f, &s, broken.is_some())?;
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
        scope.admission.session = Some(s.clone());
        let admitted = scope.admission.clone();
        let stop = host.local_stop();
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let consumer = async {
            let cx = CompactionCx {
                f: &f,
                capture: &capture,
                execution: &execution,
                scope: &scope,
                admitted: &admitted,
                conversation: &conversation,
                native: &native,
            };
            let result = run_compaction_checks(&cx, &seeded, broken).await;
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), consumer).await;
        drop(capture);
        drop(execution);
        let report = exit.finish(&bound()?).await;
        require(
            report.transport_closed && report.endpoint_retired,
            "capture host cleanup incomplete",
        )?;
        result
    })
}

/// Bug: compact_boundary with native content used to refuse and strand later chat.
#[test]
fn stock_compaction_future_metadata_and_bounded_public_continuity() -> Check {
    exercise(None)
}

/// Protects: tolerating unknown records never tolerates broken framing or malformed known chat.
#[test]
fn malformed_json_framing_and_known_messages_keep_the_committed_cursor() -> Check {
    for bytes in [
        b"{broken JSON}\n".to_vec(),
        b"{}{}\n".to_vec(),
        line(
            json!({"type":"user","sessionId":CONVERSATION,"uuid":"bad-user","message":{"role":"user"}}),
        )?,
        line(
            json!({"type":"assistant","sessionId":CONVERSATION,"uuid":"bad-assistant","message":{"role":"assistant"}}),
        )?,
    ] {
        exercise(Some(bytes))?;
    }
    for record in [
        json!({"sessionId":CONVERSATION}),
        json!({"type":42,"sessionId":CONVERSATION}),
        json!({"type":"User","sessionId":CONVERSATION,"message":{"role":"user","content":"MUST_NOT_DISAPPEAR"}}),
        json!({"type":"future-chat","sessionId":CONVERSATION,"message":{"role":"assistant","content":"MUST_NOT_DISAPPEAR"}}),
    ] {
        exercise(Some(line(record)?))?;
    }
    Ok(())
}
