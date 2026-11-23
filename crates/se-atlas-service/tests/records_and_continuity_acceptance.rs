//! End-to-end acceptance tests for record ACL authorization, DM/linked oracles,
//! tight byte-budget paging, and canonical continuity / `ChangeBaseline::Cursor` ranges.

mod support;

use rusqlite::Connection;
use se_atlas_service::{RecordCheck, Root};
use se_types::{
    Detail, SeError,
    code::{
        AtlasCursor, AtlasPrincipal, AtlasText as _, ChangeBaseline, CodeCursorPosition,
        CoverageReason, MentionTarget, RecordVisibility, RelativePath, ResumeCodeState,
        ResumeRequest, SearchKind,
    },
};
use std::collections::BTreeSet;
use support::*;

fn seed_acl_records(
    live: &LiveRoot,
) -> Result<(MapRecordCheck, MapRecordCheck), Box<dyn std::error::Error>> {
    let project = live.spec.project.clone();
    let mut audience = vec![
        AtlasPrincipal::Agent(agent_id(1)?),
        AtlasPrincipal::Agent(agent_id(2)?),
    ];
    audience.sort();
    let service_mention = vec![MentionTarget::File(RelativePath::new("src/service.rs")?)];

    let mut feed_records = Vec::new();
    let mut unauth = MapRecordCheck::new();
    let mut auth = MapRecordCheck::new();

    for idx in 1..=12u64 {
        let (rec, hit) = build_record_pair(
            &project,
            SeedSpec {
                key: &format!("dm-{idx:02}"),
                event_seq: idx,
                occurred_unix_ms: 10_000 + (idx as i64) * 1_000,
                title: &format!("Private thread {idx}"),
                body: "dm_only_secret shared_beacon discussing src/service.rs",
                visibility: RecordVisibility::Restricted {
                    audience: Some(audience.clone()),
                },
                mentions: service_mention.clone(),
            },
        )?;
        feed_records.push(rec);
        auth.allow(hit);
    }

    for (key, seq, ts, mentions) in [
        ("pub-1", 20u64, 25_000i64, Vec::new()),
        ("pub-2", 21u64, 15_500i64, Vec::new()),
        ("pub-3", 22u64, 500i64, service_mention),
    ] {
        let (rec, hit) = build_record_pair(
            &project,
            SeedSpec {
                key,
                event_seq: seq,
                occurred_unix_ms: ts,
                title: &format!("Public note {key}"),
                body: "shared_beacon public update",
                visibility: RecordVisibility::Project,
                mentions,
            },
        )?;
        feed_records.push(rec);
        unauth.allow(hit.clone());
        auth.allow(hit);
    }
    let receipt = feed_batch(live.root()?, &project, None, event_id(22)?, feed_records)?;
    assert_eq!(receipt.changed, 15);
    Ok((unauth, auth))
}

fn page_find_tight(
    root: &Root,
    kind: SearchKind,
    term: &str,
    max_bytes: u32,
    checker: &dyn RecordCheck,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut collected = Vec::new();
    let mut cursor: Option<AtlasCursor> = None;
    loop {
        let q = find_query(kind, term, budget(20, max_bytes)?, cursor.clone())?;
        let ans = root.find(&q, checker)?;
        assert!(
            serde_json::to_vec(&ans)?.len() <= max_bytes as usize,
            "serialized answer exceeded max_bytes {max_bytes}"
        );
        let res = present(ans.data)?;
        assert!(!res.page.items().is_empty(), "tight page must progress");
        if kind == SearchKind::Message {
            collected.extend(record_hit_keys(&res));
        } else {
            collected.extend(code_hit_paths(&res));
        }
        let next = res
            .page
            .next()
            .map(|c| AtlasCursor::new(c.as_str()))
            .transpose()?;
        assert_ne!(next, cursor, "continuation cursor must progress");
        cursor = next;
        if cursor.is_none() {
            break;
        }
    }
    Ok(collected)
}

fn assert_all_record_pages(
    root: &Root,
    term: &str,
    page_size: u16,
    checker: &dyn RecordCheck,
    expected_count: usize,
) -> TestResult {
    let mut keys = Vec::new();
    let mut cursor = None;
    loop {
        let q = find_query(
            SearchKind::Message,
            term,
            budget(page_size, 65_536)?,
            cursor,
        )?;
        let res = present(root.find(&q, checker)?.data)?;
        keys.extend(record_hit_keys(&res));
        cursor = res
            .page
            .next()
            .map(|c| AtlasCursor::new(c.as_str()))
            .transpose()?;
        if cursor.is_none() {
            break;
        }
    }
    let unique: BTreeSet<&str> = keys.iter().map(String::as_str).collect();
    assert_eq!(keys.len(), expected_count);
    assert_eq!(unique.len(), expected_count);
    Ok(())
}

fn assert_tight_and_sub_single_budget(
    root: &Root,
    kind: SearchKind,
    term: &str,
    checker: &dyn RecordCheck,
    expected_items: usize,
) -> TestResult {
    let one = root.find(&find_query(kind, term, budget(1, 65_536)?, None)?, checker)?;
    let two = root.find(&find_query(kind, term, budget(2, 65_536)?, None)?, checker)?;
    let one_len = serde_json::to_vec(&one)?.len() as u32;
    let two_len = serde_json::to_vec(&two)?.len() as u32;
    let tight = (one_len + two_len) / 2;
    let found = page_find_tight(root, kind, term, tight, checker)?;
    assert_eq!(found.len(), expected_items);

    // Sweep across the exact 1-hit boundary: every budget either returns >=1 hit with
    // serialized size <= max_bytes or refuses cleanly with AtlasResourceBudget.
    for cap in (one_len.saturating_sub(40)..=one_len + 80).step_by(8) {
        let q = find_query(kind, term, budget(20, cap.max(1))?, None)?;
        match root.find(&q, checker) {
            Ok(ans) => {
                assert!(serde_json::to_vec(&ans)?.len() <= cap as usize);
                let res = present(ans.data)?;
                assert!(
                    !res.page.items().is_empty(),
                    "cap {cap} must not emit an empty progressing page"
                );
            }
            Err(SeError { body, .. })
                if matches!(body.detail(), Detail::AtlasResourceBudget(_)) => {}
            Err(other) => return Err(format!("unexpected error at cap {cap}: {other}").into()),
        }
    }

    let too_small = root.find(&find_query(kind, term, budget(20, 512)?, None)?, checker);
    assert!(matches!(
        too_small,
        Err(SeError { body, .. }) if matches!(body.detail(), Detail::AtlasResourceBudget(_))
    ));
    Ok(())
}

#[test]
fn record_acl_eliminates_dm_and_linked_oracles_and_propagates_unreadable() -> TestResult {
    let mut live = LiveRoot::start(
        "record-acl",
        &[
            ("src/service.rs", "pub fn handle_order() -> u32 { 1 }\n"),
            (
                "src/caller.rs",
                "mod service;\npub fn invoke() -> u32 { service::handle_order() }\n",
            ),
        ],
    )?;
    let _ = wait_current(live.root()?, SETTLE_TIMEOUT)?;
    let (unauth, auth) = seed_acl_records(&live)?;

    // 1) Unauthorized viewer searching a DM-only keyword sees 0 hits, next: None, complete: true.
    let dm_q = find_query(
        SearchKind::Message,
        "dm_only_secret",
        budget(1, 65_536)?,
        None,
    )?;
    let dm_res = present(live.root()?.find(&dm_q, &unauth)?.data)?;
    assert!(dm_res.page.items().is_empty());
    assert!(dm_res.page.next().is_none());
    assert!(dm_res.page.window().complete());

    // 2) Interleaved visible + restricted messages page by keyset without leaking hidden count.
    let p1_q = find_query(
        SearchKind::Message,
        "shared_beacon",
        budget(2, 65_536)?,
        None,
    )?;
    let p1 = present(live.root()?.find(&p1_q, &unauth)?.data)?;
    assert_eq!(record_hit_keys(&p1), vec!["pub-1", "pub-2"]);
    let next1 = AtlasCursor::new(p1.page.next().ok_or("expected page 2 cursor")?.as_str())?;
    assert!(
        next1.as_str().contains("15500"),
        "keyset cursor should name the last visible hit timestamp, got {}",
        next1.as_str()
    );
    let p2_q = find_query(
        SearchKind::Message,
        "shared_beacon",
        budget(2, 65_536)?,
        Some(next1),
    )?;
    let p2 = present(live.root()?.find(&p2_q, &unauth)?.data)?;
    assert_eq!(record_hit_keys(&p2), vec!["pub-3"]);
    assert!(p2.page.next().is_none());
    assert!(p2.page.window().complete());

    assert_all_record_pages(live.root()?, "shared_beacon", 3, &auth, 15)?;

    // 3) linked() authorizes before setting limited: 12 restricted DMs + 1 visible keeps limited=false.
    let unauth_impact = present(
        live.root()?
            .impact(&impact_query("src/service.rs")?, &unauth)?
            .data,
    )?;
    assert_eq!(unauth_impact.records.len(), 1);
    assert_eq!(unauth_impact.records[0].pointer.key.as_str(), "pub-3");
    assert!(unauth_impact.frontier_count_complete);
    assert!(unauth_impact.complete);

    let auth_impact = present(
        live.root()?
            .impact(&impact_query("src/service.rs")?, &auth)?
            .data,
    )?;
    assert_eq!(auth_impact.records.len(), 10);
    assert!(!auth_impact.frontier_count_complete);

    let unauth_outline = present(
        live.root()?
            .outline(&outline_query("src/service.rs")?, &unauth)?
            .data,
    )?;
    assert_eq!(unauth_outline.records.len(), 1);

    // 4) Read::Unreadable propagates as an error across find, impact, and outline.
    assert!(live.root()?.find(&p1_q, &UnreadableRecordCheck).is_err());
    assert!(
        live.root()?
            .impact(&impact_query("src/service.rs")?, &UnreadableRecordCheck)
            .is_err()
    );
    assert!(
        live.root()?
            .outline(&outline_query("src/service.rs")?, &UnreadableRecordCheck)
            .is_err()
    );

    live.stop(STOP_TIMEOUT)
}

#[test]
fn tight_max_bytes_preserves_continuation_and_never_emits_non_progressing_cursor() -> TestResult {
    let mut live = LiveRoot::start(
        "tight-bytes",
        &[
            (
                "src/alpha.rs",
                "pub fn budget_target_fn_alpha() -> u32 { 1 }\n",
            ),
            (
                "src/beta.rs",
                "pub fn budget_target_fn_beta() -> u32 { 2 }\n",
            ),
            (
                "src/gamma.rs",
                "pub fn budget_target_fn_gamma() -> u32 { 3 }\n",
            ),
            (
                "src/delta.rs",
                "pub fn budget_target_fn_delta() -> u32 { 4 }\n",
            ),
        ],
    )?;
    let _ = wait_current(live.root()?, SETTLE_TIMEOUT)?;

    let project = live.spec.project.clone();
    let mut records = Vec::new();
    let mut checker = MapRecordCheck::new();
    for idx in 1..=5u64 {
        let (rec, hit) = build_record_pair(
            &project,
            SeedSpec {
                key: &format!("msg-{idx}"),
                event_seq: idx,
                occurred_unix_ms: 1_700_000_000_000 + (idx as i64) * 1_000,
                title: &format!("Budget message {idx}"),
                body: "budget_msg_token payload body text for byte-cap paging",
                visibility: RecordVisibility::Project,
                mentions: Vec::new(),
            },
        )?;
        records.push(rec);
        checker.allow(hit);
    }
    let _ = feed_batch(live.root()?, &project, None, event_id(5)?, records)?;

    assert_tight_and_sub_single_budget(
        live.root()?,
        SearchKind::Message,
        "budget_msg_token",
        &checker,
        5,
    )?;
    assert_tight_and_sub_single_budget(
        live.root()?,
        SearchKind::All,
        "budget_target_fn",
        &DenyAllRecords,
        4,
    )?;

    live.stop(STOP_TIMEOUT)
}

#[test]
fn continuity_resume_and_changes_cursor_paging_and_fence() -> TestResult {
    let mut live = LiveRoot::start("continuity", &[("src/base.rs", "pub fn base() {}\n")])?;
    let mut summary = wait_current(live.root()?, SETTLE_TIMEOUT)?;
    for (file, body) in [
        ("src/e1.rs", "pub fn step_one() {}\n"),
        ("src/e2.rs", "pub fn step_two() {}\n"),
        ("src/e3.rs", "pub fn step_three() {}\n"),
    ] {
        let before = summary.generation.map_or(0, |g| g.0);
        live.repo.write(file, body)?;
        summary = wait_generation_gt(live.root()?, before, SETTLE_TIMEOUT)?;
    }

    let viewer_agent = agent_id(7)?;
    let viewer = AtlasPrincipal::Agent(viewer_agent.clone());
    let resume = live.root()?.resume(&ResumeRequest {
        viewer: viewer_agent,
        saved_cursor: None,
        cursor_revision: 0,
        recently_edited_symbols: Vec::new(),
    })?;
    let advance = resume.advance.as_ref().ok_or("resume advance missing")?;
    let omitted_since = resume
        .omitted_since
        .as_ref()
        .ok_or("resume omitted_since missing")?;
    assert_eq!(resume.index.generation, Some(advance.fence));

    let epoch = resume.index.epoch.as_ref().ok_or("epoch missing")?;
    let decoded_next = CodeCursorPosition::decode(&advance.next_cursor)?;
    assert_eq!(
        decoded_next.resume_fence(&live.spec.project, &live.spec.root, epoch, &viewer)?,
        advance.fence.0
    );
    assert!(matches!(
        ChangeBaseline::from_text(advance.next_cursor.as_str())?,
        ChangeBaseline::Cursor(_)
    ));
    let decoded_omitted = CodeCursorPosition::decode(omitted_since)?;
    assert_eq!(decoded_omitted.change_fence, Some(advance.fence));
    assert!(matches!(
        ChangeBaseline::from_text(omitted_since.as_str())?,
        ChangeBaseline::Cursor(_)
    ));

    // Add newer generations beyond the offer fence before retrieving the fenced range.
    for (file, body) in [
        ("src/post1.rs", "pub fn post_fence_one() {}\n"),
        ("src/post2.rs", "pub fn post_fence_two() {}\n"),
    ] {
        let before = summary.generation.map_or(0, |g| g.0);
        live.repo.write(file, body)?;
        summary = wait_generation_gt(live.root()?, before, SETTLE_TIMEOUT)?;
    }
    assert!(summary.generation.map_or(0, |g| g.0) >= advance.fence.0 + 2);

    // Fenced cursor stops cleanly at fence with zero empty pages and no RetentionGap.
    let fenced = collect_all_changes(
        live.root()?,
        ChangeBaseline::Cursor(omitted_since.clone()),
        &viewer,
        1,
    )?;
    assert!(fenced.pages >= 2);
    assert!(!fenced.items.is_empty());
    assert!(
        fenced
            .items
            .iter()
            .all(|change| change_generation(change) <= advance.fence.0),
        "fenced retrieval must never leak post-fence generations"
    );
    assert!(!fenced.reasons.contains(&CoverageReason::RetentionGap));

    // Unfenced advance cursor returns only post-fence generations with zero empty pages.
    let post = collect_all_changes(
        live.root()?,
        ChangeBaseline::Cursor(advance.next_cursor.clone()),
        &viewer,
        1,
    )?;
    assert!(!post.items.is_empty());
    assert!(
        post.items
            .iter()
            .all(|change| change_generation(change) > advance.fence.0)
    );
    assert!(!post.reasons.contains(&CoverageReason::RetentionGap));

    live.stop(STOP_TIMEOUT)
}

#[test]
fn continuity_retention_gap_triggers_only_below_floor() -> TestResult {
    let mut live = LiveRoot::start("retention-gap", &[("src/base.rs", "pub fn base() {}\n")])?;
    let mut summary = wait_current(live.root()?, SETTLE_TIMEOUT)?;
    for idx in 1..=5u32 {
        let before = summary.generation.map_or(0, |g| g.0);
        live.repo.write(
            &format!("src/g_{idx}.rs"),
            &format!("pub fn gen_step_{idx}() {{}}\n"),
        )?;
        summary = wait_generation_gt(live.root()?, before, SETTLE_TIMEOUT)?;
    }

    // Prune generations < 4 so the retention floor is exactly 4.
    live.stop(STOP_TIMEOUT)?;
    let db = epoch_db_path(live.state.path())?;
    {
        let conn = Connection::open(&db)?;
        conn.execute("DELETE FROM observed_commits WHERE generation < 4", [])?;
        conn.execute("DELETE FROM authors WHERE generation < 4", [])?;
        conn.execute("DELETE FROM changes WHERE generation < 4", [])?;
        conn.execute("DELETE FROM generations WHERE generation < 4", [])?;
    }
    live.restart()?;
    let current = wait_current(live.root()?, SETTLE_TIMEOUT)?;

    let viewer_agent = agent_id(8)?;
    let viewer = AtlasPrincipal::Agent(viewer_agent.clone());

    let at_floor = range_cursor_for(&current, &viewer, 3, None)?;
    let exact = collect_all_changes(
        live.root()?,
        ChangeBaseline::Cursor(at_floor.clone()),
        &viewer,
        10,
    )?;
    assert!(!exact.items.is_empty());
    assert!(
        !exact.reasons.contains(&CoverageReason::RetentionGap),
        "delivered + 1 == floor must not report RetentionGap"
    );
    let resume_exact = live.root()?.resume(&ResumeRequest {
        viewer: viewer_agent.clone(),
        saved_cursor: Some(at_floor),
        cursor_revision: 1,
        recently_edited_symbols: Vec::new(),
    })?;
    assert_ne!(resume_exact.state, ResumeCodeState::BaselineGap);

    let before_floor = range_cursor_for(&current, &viewer, 2, None)?;
    let gap = collect_all_changes(
        live.root()?,
        ChangeBaseline::Cursor(before_floor.clone()),
        &viewer,
        10,
    )?;
    assert!(
        gap.reasons.contains(&CoverageReason::RetentionGap),
        "delivered + 1 < floor must report RetentionGap"
    );
    let resume_gap = live.root()?.resume(&ResumeRequest {
        viewer: viewer_agent,
        saved_cursor: Some(before_floor),
        cursor_revision: 2,
        recently_edited_symbols: Vec::new(),
    })?;
    assert_eq!(resume_gap.state, ResumeCodeState::BaselineGap);

    live.stop(STOP_TIMEOUT)
}
