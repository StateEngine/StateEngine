//! Native continuity assembly and sole-writer cursor checks, not latency qualification.
#![cfg(any(target_os = "linux", windows))]
use se_core::{atlas_resume::*, commit::Cx, ops::continuity::*};
use se_store::{atlas_resume::*, *};
use se_types::{UnixMicros, code::*};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[expect(
    dead_code,
    reason = "The native fixture also supports captured turns; this consumer uses only its session setup."
)]
#[path = "../../se-store/tests/support/capture_fixture.rs"]
mod capture;
#[path = "../../se-store/tests/support/host_fixture.rs"]
mod native_host;
use native_host::*;
use sha2::{Digest, Sha256};
use std::{io::Write, time::Duration};
fn index(f: &Fixture) -> Result<IndexSummary, Box<dyn std::error::Error>> {
    Ok(IndexSummary {
        memory: None,
        project: f.project.clone(),
        root: RootId::from_parts(1, [2; 10])?,
        epoch: Some(CacheEpoch::from_parts(1, [3; 10])?),
        generation: Some(Generation(8)),
        state: IndexState::Current,
        coverage: serde_json::from_value(
            serde_json::json!({"discovered_files":0,"indexed_files":0,"partial_files":0,"deferred_files":0,"failed_files":0,"discovery_complete":true,"stale_files":0,"resolved_references":0,"name_only_references":0,"watched_directories":0,"unwatched_directories":0,"watch_discovery_complete":true,"watch_stats_started":null,"watch_activation_attempts":0,"watch_limited_activations":0,"reasons":[]}),
        )?,
    })
}
fn cursor(
    index: &IndexSummary,
    viewer: &se_types::AgentId,
    lower: u64,
    upper: Option<Generation>,
) -> se_types::Result<AtlasCursor> {
    CodeCursorPosition::new(
        index,
        "changes-range",
        cursor_digest(&("changes-range", AtlasPrincipal::Agent(viewer.clone())))?,
        CursorKey {
            integers: vec![lower, u64::from(u32::MAX)],
            bytes: vec![],
        },
        upper,
    )?
    .encode()
}
fn source(
    f: &Fixture,
    baseline: Option<AtlasCursor>,
    revision: u64,
    items: usize,
) -> Result<ResumeCode, Box<dyn std::error::Error>> {
    let index = index(f)?;
    let mut output = ResumeCode {
        advance: Some(ResumeAdvance {
            offer: ResumeOfferId([revision as u8; 16]),
            expected_cursor: baseline.clone(),
            expected_revision: revision,
            next_cursor: cursor(&index, &f.a, 8, None)?,
            fence: Generation(8),
        }),
        omitted_since: if baseline.is_none() {
            Some(cursor(&index, &f.a, 0, Some(Generation(8)))?)
        } else {
            None
        },
        state: if baseline.is_none() {
            ResumeCodeState::BaselineGap
        } else if items == 0 {
            ResumeCodeState::Zero
        } else {
            ResumeCodeState::Available
        },
        complete: baseline.is_some(),
        omitted: Some(0),
        unattributed_omitted: Some(0),
        items: vec![],
        diagnostic: None,
        index,
    };
    for n in 0..items {
        output.items.push(ResumeChange::Bulk(BulkChange {
            id: ChangeId {
                generation: Generation(8),
                ordinal: n as u32,
            },
            reason: BulkReason::WatchReconcile,
            files: 2,
            semantic_changes: None,
            sample_paths: vec![RelativePath::new("changed.rs")?],
            complete: true,
        }));
    }
    Ok(output)
}
fn resume_packet(
    f: &Fixture,
    read: &mut impl Snapshot,
    admission: &Admission,
) -> Result<ResumeOutput, Box<dyn std::error::Error>> {
    let result = resume(
        Resume {
            source_failure: None,
            limit: 20,
            since: None,
            byte_budget: 32768,
            preview_agent: None,
        },
        UnixMicros::new(1_800_000_000_000_000)?,
        &mut Cx { read, admission },
    )?;
    assert_eq!(result.principal.project.id, f.project);
    Ok(result)
}
fn encoded<T: serde::Serialize>(
    family: &str,
    value: &T,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut value = serde_json::to_value(value)?;
    value["schema"] = family.into();
    Ok(serde_json::to_vec(&value)?.len())
}
#[test]
fn typed_code_context_uses_only_available_space_on_both_consumers() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let sid = capture::session()?;
    capture::active(&f, &mut direct, &lease, &sid, capture::record()?)?;
    let mut scope = f.self_scope(&f.a);
    scope.admission.session = Some(sid);
    let admission = scope.admission.clone();
    let mut read = direct.snapshot(scope)?;
    let mut packet = resume_packet(&f, &mut read, &admission)?;
    let saved = cursor(&index(&f)?, &f.a, 0, None)?;
    let private = serde_json::to_value(&packet.working_state)?;
    let token = attach_resume(&mut packet, source(&f, Some(saved.clone()), 1, 5)?, 600)?;
    assert!(token.is_some());
    assert!(packet.code_changes.as_ref().is_some_and(|v| v.len() < 5));
    let status = packet.code_status.as_ref().ok_or("code status absent")?;
    assert!(!status.complete);
    let range =
        CodeCursorPosition::decode(status.omitted_since.as_ref().ok_or("retrieval absent")?)?;
    assert_eq!(range.change_fence, Some(Generation(8)));
    assert_eq!(range.last_key.integers[0], 0);
    let section =
        serde_json::json!({"code_changes":packet.code_changes,"code_status":packet.code_status});
    assert!(serde_json::to_vec(&section)?.len() <= 600);
    assert_eq!(
        packet.budget.used_bytes,
        encoded("se.resume/v1", &packet)? as u64
    );
    assert_eq!(serde_json::to_value(&packet.working_state)?, private);
    let mut small = resume_packet(&f, &mut read, &admission)?;
    assert!(attach_resume(&mut small, source(&f, None, 0, 0)?, 200)?.is_none());
    assert_eq!(
        small.code_status.as_ref().map(|s| &s.state),
        Some(&ResumeCodeState::BudgetExceeded)
    );
    let mut full = resume_packet(&f, &mut read, &admission)?;
    full.budget.limit_bytes = full.budget.used_bytes as u32;
    assert!(attach_resume(&mut full, source(&f, None, 0, 0)?, 600)?.is_none());
    assert!(full.code_changes.is_none());
    let mut linked = context(
        SessionContextRequest {
            source_failure: None,
            limit: 20,
            since: None,
            byte_budget: 32768,
        },
        UnixMicros::new(1_800_000_000_000_000)?,
        &mut Cx {
            read: &mut read,
            admission: &admission,
        },
    )?;
    assert!(attach_context(&mut linked, source(&f, Some(saved), 1, 1)?, 32768, 600)?.is_some());
    let model: serde_json::Value = serde_json::from_str(&linked.assembled_model_input)?;
    assert!(model["code_changes"].is_array());
    assert_eq!(model["code_changes"].as_array().map(Vec::len), Some(1));
    assert!(model.get("advance").is_none());
    assert_eq!(linked.byte_size, linked.assembled_model_input.len() as u64);
    assert_eq!(
        linked.packet_id,
        format!(
            "{:x}",
            Sha256::digest(linked.assembled_model_input.as_bytes())
        )
    );
    assert!(encoded("secode.session-context-v1", &linked)? <= 32768);
    drop(read);
    direct.close()?;
    drop(lease);
    Ok(())
}
#[test]
fn successful_delivery_cas_is_replayable_and_stale_or_retired_offers_do_not_consume() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let owner = host.start_writer(options(256)?, lease)?;
    let client = owner.client();
    let sid = capture::session()?;
    wait(client.submit(f.batch(
        f.owner_project(),
        Some(request("atlas-resume-session")?),
        vec![capture::prepared(&f, &sid, &f.a), capture::activated(&sid)?],
    )?)?)??;
    let index = index(&f)?;
    let epoch = index.epoch.clone().ok_or("epoch")?;
    wait(client.atlas_resume(AtlasResumeMutation::Epoch {
        project: f.project.clone(),
        root: index.root.clone(),
        expected: None,
        next: Some(epoch.clone()),
    })?)??;
    let mut scope = f.self_scope(&f.a);
    scope.admission.session = Some(sid);
    let admission = scope.admission.clone();
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut read = reader.snapshot(scope.clone())?;
    let mut packet = resume_packet(&f, &mut read, &admission)?;
    let token =
        attach_resume(&mut packet, source(&f, None, 0, 0)?, 600)?.ok_or("delivery token absent")?;
    assert_eq!(
        present(read.atlas_resume_cursor(&f.a, &index.root, &epoch)?)?.revision,
        0,
        "packet construction consumed cursor"
    );
    let dropped = attach_resume(
        &mut resume_packet(&f, &mut read, &admission)?,
        source(&f, None, 0, 0)?,
        600,
    )?;
    drop(dropped);
    drop(read);
    // A successful consumer write is the boundary, before the private writer CAS.
    let mut consumer = Vec::new();
    consumer.write_all(&serde_json::to_vec(&packet)?)?;
    let mutation = token.delivered(admission.clone(), event()?)?;
    let replay = mutation.clone();
    assert!(matches!(
        wait(client.atlas_resume(mutation)?)??,
        AtlasResumeWrite::Cursor(ResumeCursorCommit::Applied { revision: 1 })
    ));
    assert!(matches!(
        wait(client.atlas_resume(replay)?)??,
        AtlasResumeWrite::Cursor(ResumeCursorCommit::AlreadyApplied { revision: 1 })
    ));
    let mut stale = source(&f, None, 0, 0)?;
    stale.advance.as_mut().ok_or("advance")?.offer = ResumeOfferId([99; 16]);
    let mut read = reader.snapshot(scope.clone())?;
    let stale = attach_resume(&mut resume_packet(&f, &mut read, &admission)?, stale, 600)?
        .ok_or("stale token")?
        .delivered(admission.clone(), event()?)?;
    drop(read);
    assert!(matches!(
        wait(client.atlas_resume(stale)?)??,
        AtlasResumeWrite::Cursor(ResumeCursorCommit::Stale { actual_revision: 1 })
    ));
    let mut read = reader.snapshot(scope.clone())?;
    let head = present(read.atlas_resume_cursor(&f.a, &index.root, &epoch)?)?;
    assert_eq!(head.revision, 1);
    assert_eq!(head.fence, 8);
    assert!(read.atlas_resume_cursor(&f.b, &index.root, &epoch).is_err());
    let old = attach_resume(
        &mut resume_packet(&f, &mut read, &admission)?,
        source(&f, head.cursor, 1, 0)?,
        600,
    )?
    .ok_or("old epoch token")?
    .delivered(admission, event()?)?;
    drop(read);
    wait(client.atlas_resume(AtlasResumeMutation::Epoch {
        project: f.project.clone(),
        root: index.root.clone(),
        expected: Some(epoch.clone()),
        next: None,
    })?)??;
    assert!(wait(client.atlas_resume(old)?)?.is_err());
    assert!(matches!(
        reader
            .snapshot(scope)?
            .atlas_resume_cursor(&f.a, &index.root, &epoch)?,
        se_types::Read::Unknown { .. }
    ));
    drop(wait(owner.drain(Duration::from_secs(2)))??);
    Ok(())
}

#[test]
fn native_model_status_fits_the_remaining_budget_without_an_offer() -> Check {
    let f = Fixture::new()?;
    let original = serde_json::json!({"private_context":"retained","agent":f.a}).to_string();
    let mut text = original.clone();
    let offer = attach_model_input(
        &mut text,
        Err(ResumeCodeState::BudgetExceeded),
        &f.project,
        &f.a,
        4096,
        600,
    )?;
    assert!(offer.is_none());
    let model: serde_json::Value = serde_json::from_str(&text)?;
    assert_eq!(model["private_context"], "retained");
    assert_eq!(model["code_status"]["state"], "BudgetExceeded");
    let mut too_small = original.clone();
    assert!(
        attach_model_input(
            &mut too_small,
            Err(ResumeCodeState::Unreadable),
            &f.project,
            &f.a,
            original.len() as u32,
            600
        )?
        .is_none()
    );
    assert_eq!(too_small, original);
    Ok(())
}
