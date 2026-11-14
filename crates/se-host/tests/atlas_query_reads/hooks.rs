//! Both provider hint targets use the real retained root and scoped index.
//! Every reader owns the connection exclusively, so each phase below rebuilds
//! its reader after the previous one drops.
use super::*;
pub(super) fn check(
    cache: &mut CacheConnection<'_>,
    source: &se_atlas::source::RegisteredSource<NativeAtlasSource>,
    records: &dyn se_atlas::query::RecordReader,
    viewer: &AtlasPrincipal,
    other: &se_types::AgentId,
    feed_current: bool,
) -> Check {
    let mut hook = se_core::ops::AtlasAugment {
        target: se_core::ops::AtlasHookTarget::Symbol(QueryText::new("alpha")?),
        root: None,
        deadline: Some(se_atlas::clock::now() + Duration::from_millis(500)),
    };
    let augmentation = {
        let mut reader = super::outer_reader(cache, viewer, records, source, 1, feed_current);
        se_host::atlas_hooks::augment(&mut reader, source, &hook)?
    };
    let native: serde_json::Value = serde_json::from_str(&augmentation.stdout)?;
    let context = native["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .ok_or("hook context absent")?;
    assert!(context.contains("definition alpha alpha.rs:1"));
    assert!(context.contains("caller alpha.rs:"));
    assert!(context.contains("linked (sample): 1 messages"));
    for (viewer, current, expected) in [
        (AtlasPrincipal::Agent(other.clone()), true, Some(0)),
        (viewer.clone(), false, None),
    ] {
        let mut hint_reader = super::outer_reader(cache, &viewer, records, source, 1, current);
        let hints =
            hint_reader.hook_context(se_atlas::query::hooks::HookTarget::Symbol("alpha"), end())?;
        assert_eq!(
            hints.map(|h| h.linked.messages),
            expected,
            "hook exposed another agent's private record or an uncertified feed"
        );
    }
    history_is_optional(cache, source, records, viewer, feed_current)?;
    assert!(augmentation.stdout.len() <= 600);
    let mut reader = super::outer_reader(cache, viewer, records, source, 1, feed_current);
    hook.deadline = Some(se_atlas::clock::now() - Duration::from_millis(1));
    assert!(
        se_host::atlas_hooks::augment(&mut reader, source, &hook)?
            .stdout
            .is_empty()
    );
    hook.target = se_core::ops::AtlasHookTarget::File(se_types::NativePath::from_local(
        source
            .scope
            .registration
            .canonical_source_root
            .join("hook_large.rs"),
    )?);
    hook.deadline = Some(se_atlas::clock::now() + Duration::from_millis(500));
    let large_hint = se_host::atlas_hooks::augment(&mut reader, source, &hook)?;
    let large_json: serde_json::Value = serde_json::from_str(&large_hint.stdout)?;
    let large_context = large_json["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .ok_or("large outline hint absent")?;
    assert!(large_context.contains("Atlas outline (sample): hook_large.rs"));
    assert!(large_context.contains("linked (sample): 1 messages"));
    assert!(large_hint.stdout.len() <= 600);
    hook.target = se_core::ops::AtlasHookTarget::File(se_types::NativePath::from_local(
        source
            .scope
            .registration
            .canonical_source_root
            .join("alpha.rs"),
    )?);
    hook.deadline = Some(se_atlas::clock::now() + Duration::from_millis(5));
    assert!(
        se_host::atlas_hooks::augment(&mut reader, source, &hook)?
            .stdout
            .is_empty(),
        "small reads must not receive outline augmentation"
    );
    Ok(())
}

fn history_is_optional(
    cache: &mut CacheConnection<'_>,
    source: &se_atlas::source::RegisteredSource<NativeAtlasSource>,
    records: &dyn se_atlas::query::RecordReader,
    viewer: &AtlasPrincipal,
    feed_current: bool,
) -> Check {
    let original: (String, String, Option<String>) = cache.read(end(), |sql| {
        sql.prepare("SELECT coverage_json,state_json,history_bound FROM meta,record_feed WHERE meta.singleton=1 AND record_feed.singleton=1")?
            .query_row([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).map_err(fail)
    })?;
    for reason in [
        CoverageReason::HistoryUnavailable,
        CoverageReason::ResultLimit,
    ] {
        let mut coverage: Coverage = serde_json::from_str(&original.0)?;
        coverage.reasons.push(reason);
        let bound = if reason == CoverageReason::HistoryUnavailable {
            coverage.history_unavailable = Some(fail("native history unavailable fixture").body);
            None
        } else {
            Some(serde_json::to_string(&se_atlas::history::HistoryBound {
                head: "1".repeat(40),
                oldest: Some("2".repeat(40)),
                next: Some("3".repeat(40)),
                limit: se_atlas::history::HistoryLimit::CommitCount,
            })?)
        };
        cache.write(65536, end(), |sql| {
            sql.prepare("UPDATE meta SET coverage_json=?1,state_json=?2 WHERE singleton=1")?
                .execute((
                    serde_json::to_string(&coverage).map_err(fail)?,
                    serde_json::to_string(&IndexState::VerificationNeeded { reason })
                        .map_err(fail)?,
                ))
                .map_err(fail)?;
            sql.prepare("UPDATE record_feed SET history_bound=?1 WHERE singleton=1")?
                .execute([bound.as_deref()])
                .map_err(fail)?;
            Ok(())
        })?;
        let hint = super::outer_reader(cache, viewer, records, source, 1, feed_current)
            .hook_context(se_atlas::query::hooks::HookTarget::Symbol("alpha"), end())?
            .ok_or("optional Git limitation suppressed a fresh source hint")?;
        assert_eq!(hint.linked.messages, 1);
        let mut behind = super::outer_reader(cache, viewer, records, source, 1, false);
        assert!(
            behind
                .hook_context(se_atlas::query::hooks::HookTarget::Symbol("alpha"), end())?
                .is_none(),
            "Git limitation bypassed the authoritative-record fence"
        );
        assert!(
            behind
                .summary()?
                .coverage
                .reasons
                .contains(&CoverageReason::RecordFeedLag)
        );
        coverage.watch_discovery_complete = false;
        cache.write(65536, end(), |sql| {
            sql.prepare("UPDATE meta SET coverage_json=?1 WHERE singleton=1")?
                .execute([serde_json::to_string(&coverage).map_err(fail)?])
                .map_err(fail)?;
            Ok(())
        })?;
        assert!(
            super::outer_reader(cache, viewer, records, source, 1, feed_current)
                .hook_context(se_atlas::query::hooks::HookTarget::Symbol("alpha"), end())?
                .is_none(),
            "Git limitation bypassed incomplete source watches"
        );
    }
    cache.write(65536, end(), |sql| {
        sql.prepare("UPDATE meta SET coverage_json=?1,state_json=?2 WHERE singleton=1")?
            .execute((&original.0, &original.1))
            .map_err(fail)?;
        sql.prepare("UPDATE record_feed SET history_bound=?1 WHERE singleton=1")?
            .execute([original.2.as_deref()])
            .map_err(fail)?;
        Ok(())
    })?;
    Ok(())
}
