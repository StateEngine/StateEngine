//! Committed native metadata -> retained root -> index -> authoritative activity.
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[allow(
    dead_code,
    reason = "Shared capture fixture supports more consumers than this focused native activity test."
)]
#[path = "../../se-store/tests/support/capture_fixture.rs"]
mod capture;
use se_atlas::{
    cache::{connection::*, *},
    model::*,
    query::RecordReader,
};
use se_core::ops::transcript::{Position, tool::*};
use se_host::{
    atlas_cache::NativeAtlasCache,
    atlas_records::{AtlasRecordReader, next_feed},
    atlas_source::NativeAtlasSource,
};
use se_store::*;
use se_types::{Read, code::*};
use std::{
    fs,
    time::{Duration, Instant},
};
fn end() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn fail(e: impl std::fmt::Display) -> se_types::SeError {
    se_types::SeError::invalid("captured activity fixture", &e.to_string())
}
#[test]
fn both_providers_feed_only_bound_successful_root_paths_without_authorship() -> Check {
    for provider in [Provider::Claude, Provider::Codex] {
        check(provider)?;
    }
    Ok(())
}
fn check(provider: Provider) -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let root_dir = f.home.join("source");
    fs::create_dir(&root_dir)?;
    fs::write(root_dir.join("file.rs"), "fn edited() {}\n")?;
    fs::write(root_dir.join(".env"), "PRIVATE=fixture\n")?;
    let session = capture::session()?;
    let source_id = capture::record()?;
    let mut prepared = capture::prepared(&f, &session, &f.a);
    if let EventBody::SessionPrepared {
        provider: actual, ..
    } = &mut prepared
    {
        *actual = provider;
    }
    direct.append(
        f.batch(
            f.owner_project(),
            Some(request("atlas-captured-setup")?),
            vec![
                prepared,
                capture::activated(&session)?,
                capture::source(source_id, &session, b"native", Expected::Absent),
            ],
        )?,
        &*lease,
    )?;
    let transcript = f.home.join("native.jsonl");
    fs::write(&transcript, b"0123456789".repeat(8))?;
    let mut facts = Vec::new();
    let mut successful_event = None;
    for index in 0..8 {
        let position = Position {
            offset: index * 10,
            length: 10,
        };
        let mut tool = Observation {
            schema: SCHEMA.into(),
            session: session.clone(),
            agent: f.a.clone(),
            provider,
            source: source_id,
            position: position.clone(),
            native: if provider == Provider::Claude {
                NativeIdentity::ClaudeCall {
                    tool_use_id: format!("call-{index}"),
                }
            } else {
                NativeIdentity::CodexItem {
                    turn_id: Some("turn".into()),
                    item_id: Some(format!("item-{index}")),
                    call_id: None,
                }
            },
            phase: Phase::Completed,
            tool: ToolName::Known(
                if provider == Provider::Claude {
                    "Edit"
                } else {
                    "FileChange"
                }
                .into(),
            ),
            target: Target::Paths(vec![ObservedPath {
                spelling: "file.rs".into(),
                cwd: Some(root_dir.to_string_lossy().into_owned()),
                content_revision: Some(ContentRevision::Opaque {
                    scheme: "native".into(),
                    value: "not-a-digest".into(),
                }),
            }]),
            outcome: Outcome::Succeeded,
        };
        match index {
            1 => tool.outcome = Outcome::Failed,
            2 => {
                tool.phase = Phase::Called;
                tool.outcome = Outcome::Unknown(UnknownReason::Pending);
                if let Target::Paths(paths) = &mut tool.target {
                    paths[0].content_revision = None;
                }
            }
            3 => tool.tool = ToolName::Known("Read".into()),
            4 => {
                if let Target::Paths(paths) = &mut tool.target {
                    paths[0].cwd = None;
                }
            }
            5 => {
                if let Target::Paths(paths) = &mut tool.target {
                    paths[0].spelling = ".env".into();
                }
            }
            6 => {
                if let Target::Paths(paths) = &mut tool.target {
                    paths[0].spelling = f.home.join("outside.rs").to_string_lossy().into_owned();
                }
            }
            7 => tool.native = NativeIdentity::Unknown(UnknownReason::NoNativeIdentity),
            _ => (),
        }
        let evidence = SourceEvidence {
            path: Some(se_types::NativePath::from_local(transcript.clone())?),
            incarnation: b"native".to_vec(),
            offset: position.offset,
            length: position.length,
            sha256: Some({
                use sha2::Digest;
                sha2::Sha256::digest(b"0123456789").into()
            }),
        };
        tool.validate_binding(&session, &f.a, provider, source_id, &evidence)?;
        let text = serde_json::json!({"schema":"se.transcript-event/v1","kind":"captured-tool","kind_truncated":false,"subtype_truncated":false,"position":position,"captured_tool":tool});
        let turn = capture::record()?;
        let mut admitted = f.owner_project();
        admitted.session = Some(session.clone());
        let mut batch = f.batch(
            admitted,
            None,
            vec![
                EventBody::SessionTurn {
                    turn,
                    agent: f.a.clone(),
                    session: session.clone(),
                    provider,
                    vendor_ref: format!("{}tool-{index}", TRANSCRIPT_EVENT_PREFIX),
                    role: Role::System,
                    text: InputText::Inline(text.to_string()),
                    evidence,
                },
                EventBody::CaptureProgress {
                    source: source_id,
                    expected: revision(index + 1)?,
                    incarnation: b"native".to_vec(),
                    old_offset: index * 10,
                    new_offset: (index + 1) * 10,
                    last_turn: turn,
                    replay_evidence: None,
                },
            ],
        )?;
        for event in &mut batch.events {
            event.header.session = Some(session.clone());
        }
        let committed = direct.append(batch, &*lease)?;
        if index == 0 {
            successful_event = Some(committed.primary_event);
        }
    }
    let atlas_home = f.home.join("atlas");
    let root = RootId::from_parts(1, [2; 10])?;
    let source = NativeAtlasSource::open(
        RootRegistration {
            project: f.project.clone(),
            root: root.clone(),
            canonical_source_root: root_dir,
            cache: CacheLocation {
                directory: atlas_home.join(f.project.as_str()).join(root.as_str()),
            },
            git_metadata: None,
        },
        se_atlas::lifecycle::CaseMode::Sensitive,
    )?;
    let files = NativeAtlasCache::create(&atlas_home, source.scope.clone())?;
    let seed = CacheSeed {
        identity: CacheIdentity {
            scope: source.scope.clone(),
            epoch: CacheEpoch::from_parts(1, [3; 10])?,
        },
        extractor_version: "tool-consumer".into(),
        ignore_digest: ContentHash([0; 32]),
        coverage: serde_json::from_value(
            serde_json::json!({"discovered_files":1,"indexed_files":1,"partial_files":0,"deferred_files":0,"failed_files":0,"discovery_complete":true,"stale_files":0,"resolved_references":0,"name_only_references":0,"watched_directories":0,"unwatched_directories":0,"watch_discovery_complete":true,"watch_stats_started":null,"watch_activation_attempts":0,"watch_limited_activations":0,"reasons":[]}),
        )?,
        state: IndexState::Current,
    };
    let cache = CacheConnection::create(
        &files,
        &seed,
        ConnectionRole::HostWriter,
        &SqlProfile::from_qualified_overhead(1)?,
        end(),
    )?;
    cache.write(131072,end(),|sql|{
        sql.prepare("INSERT INTO files(id,key,path,path_key,bytes,identity,coverage_json,last_code_generation,last_author_generation,baseline_reset) VALUES(1,?1,'file.rs','file.rs',15,x'01','\"Indexed\"',0,0,0)")?.execute([[1u8;16].as_slice()]).map_err(fail)?;Ok(())
    })?;
    let store = present(SqliteFactory::open_reader(&f.options)?)?;
    let scope = f.scoped(Visibility::Owner);
    let mut snapshot = store.snapshot(scope.clone())?;
    let mut after = None;
    while let Some(feed) = next_feed(&mut snapshot, &scope.admission, after.clone(), &source)? {
        for change in &feed.changes {
            if let RecordFeedChange::Upsert(record) = change {
                facts.push(record.pointer.clone());
                assert_eq!(
                    record.mentions,
                    vec![MentionTarget::File(RelativePath::new("file.rs")?)]
                );
            }
        }
        se_atlas::records::apply(&cache, &feed, end())?;
        after = Some(feed.through);
        if feed.complete {
            break;
        }
    }
    assert_eq!(
        facts.len(),
        1,
        "intent, failure, read, unknown or unbound/private path became activity"
    );
    let pointer = facts.remove(0);
    assert_eq!(Some(pointer.source_event.clone()), successful_event);
    snapshot.close()?;
    for (agent, visible) in [(&f.a, true), (&f.b, false)] {
        let scope = f.self_scope(agent);
        let mut snapshot = store.snapshot(scope.clone())?;
        let records = AtlasRecordReader::new(&mut snapshot, &scope.admission);
        let viewer = AtlasPrincipal::Agent(agent.clone());
        let hit = records.read(&f.project, &viewer, &pointer, None)?;
        assert_eq!(matches!(hit, Read::Present { .. }), visible);
        if let Read::Present { value } = hit {
            assert!(value.line.contains("author unknown"));
            assert_eq!(value.actor.map(|a| a.principal), Some(viewer.clone()));
        }
        let activity = cache.read(end(), |sql| {
            se_atlas::rank::activity(
                sql,
                "file",
                &[1; 16],
                se_atlas::rank::ActivityQuery {
                    project: &f.project,
                    viewer: &viewer,
                    records: &records,
                    now: Some(i64::MAX),
                },
            )
        })?;
        assert_eq!(activity.last.is_some(), visible);
        assert_eq!(
            activity.edited_by, None,
            "tool intent/revision fabricated current-content authorship"
        );
        snapshot.close()?;
    }
    Ok(())
}
