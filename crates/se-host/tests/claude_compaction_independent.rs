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
const CONVERSATION: &str = "01a1a4cd-d140-70df-bd3c-f3f879fce410";

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

fn exercise(broken: Option<Vec<u8>>) -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let s = session::session()?;
    let conversation = ProviderSessionId::new(CONVERSATION)?;
    let path = f.home.join("transcript.jsonl");
    let native = NativePath::from_local(path.clone())?;
    let mut bytes = line(chat(
        "user",
        "before-compact",
        "real user before compaction",
    ))?;
    let compact_offset = bytes.len() as u64;
    if broken.is_none() {
        require(
            format!("{:x}", Hasher::digest(COMPACT))
                == "1f210dced6165d8a991e315ee12fc2d155ce787b190eec6686e3a017390ba191",
            "retained stock compaction record changed",
        )?;
        bytes.extend_from_slice(COMPACT);
        for n in 0..25 {
            bytes.extend(line(json!({"type":"future-provider-record","sessionId":CONVERSATION,"uuid":format!("future-{n}"),"message":{"role":"assistant","content":"PRIVATE_PROVIDER_PAYLOAD"},"opaque":"PRIVATE_PROVIDER_PAYLOAD"}))?);
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
    let (mut direct, lease) = direct(&f)?;
    let mut prepared = session::prepared(&f, &s, &f.a);
    if let EventBody::SessionPrepared { native_ref, .. } = &mut prepared {
        *native_ref = CONVERSATION.into();
    }
    direct.append(
        f.batch(
            f.owner_project(),
            None,
            vec![
                prepared,
                session::activated(&s)?,
                session::source(source, &s, &pin.identity(), Expected::Absent),
            ],
        )?,
        &*lease,
    )?;
    direct.close()?;
    drop(lease);
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
                source,
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
            let result: Check = async {
                let first = capture
                    .catch_up(
                        admitted.clone(),
                        conversation.clone(),
                        native.clone(),
                        &bound()?,
                    )
                    .await?;
                require(
                    first.capture_commits.len() == if broken.is_some() { 1 } else { 28 },
                    "capture lost records or promoted tool data",
                )?;
                let mut before_replay = execution.reader.snapshot(scope.clone())?;
                let committed = present(before_replay.capture_source(source)?)?;
                before_replay.close()?;
                capture
                    .catch_up(
                        admitted.clone(),
                        conversation.clone(),
                        native.clone(),
                        &bound()?,
                    )
                    .await?;
                let mut snapshot = execution.reader.snapshot(scope.clone())?;
                let repeated = present(snapshot.capture_source(source)?)?;
                require(
                    repeated.revision == committed.revision
                        && repeated.current.header.event == committed.current.header.event,
                    "capture replay advanced durable progress",
                )?;
                let page = snapshot.turns(f.a.clone(), budget(100, 200_000, None)?)?;
                require(
                    page.items().len() == if broken.is_some() { 1 } else { 28 },
                    "capture replay duplicated durable events",
                )?;
                let mut chat_text = Vec::new();
                let mut metadata = 0;
                for event in page.items() {
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
                        chat_text.push(text.as_str());
                    }
                    let start = usize::try_from(evidence.offset)?;
                    let end = start + usize::try_from(evidence.length)?;
                    let digest: [u8; 32] = Hasher::digest(&bytes[start..end]).into();
                    require(
                        evidence.sha256 == Some(digest),
                        "native evidence digest differs",
                    )?;
                }
                if let Some(invalid) = broken {
                    let before = present(snapshot.capture_source(source)?)?;
                    snapshot.close()?;
                    let mut file = OpenOptions::new().append(true).open(&path)?;
                    file.write_all(&invalid)?;
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
                } else {
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
                        read: &mut snapshot,
                        admission: &admitted,
                    };
                    let resumed = serde_json::to_value(resume(
                        Resume {
                            limit: 20,
                            governing_cursor: None,
                            since: None,
                            byte_budget: 65536,
                            preview_agent: None,
                        },
                        UnixMicros::new(u64::try_from(now()?)?)?,
                        &mut cx,
                    )?)?;
                    summary(&resumed, compact_offset)?;
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
                    summary(&read_value(&shown["agent"])?["session"], compact_offset)?;
                    snapshot.close()?;
                }
                Ok(())
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
    Ok(())
}
