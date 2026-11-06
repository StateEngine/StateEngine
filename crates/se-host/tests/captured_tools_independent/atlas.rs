//! Real provider capture feeds the retained-root Atlas activity adapter.
use super::*;
use se_types::code::*;
pub(super) fn check(execution: &ExecutionContext, f: &Fixture) -> Check {
    let source = se_host::atlas_source::NativeAtlasSource::open(
        se_atlas::model::RootRegistration {
            project: f.project.clone(),
            root: RootId::from_parts(1, [2; 10])?,
            canonical_source_root: f.home.clone(),
            cache: se_atlas::model::CacheLocation {
                directory: f.home.join("atlas"),
            },
            git_metadata: None,
        },
        se_atlas::lifecycle::CaseMode::Sensitive,
    )?;
    let scope = f.scoped(Visibility::Owner);
    let mut snapshot = execution.reader.snapshot(scope.clone())?;
    let mut after = None;
    let mut edits = 0;
    let mut complete = false;
    for _ in 0..16 {
        let Some(feed) =
            se_host::atlas_records::next_feed(&mut snapshot, &scope.admission, after, &source)?
        else {
            complete = true;
            break;
        };
        for change in &feed.changes {
            let RecordFeedChange::Upsert(record) = change else {
                continue;
            };
            if record.pointer.kind != RecordKind::Edit {
                continue;
            }
            edits += 1;
            assert!(record.mentions.iter().any(|target| matches!(target,
                MentionTarget::File(path) if path.as_str() == "a.rs")));
            assert!(matches!(&record.actor, Some(actor)
                if actor.principal == AtlasPrincipal::Agent(f.a.clone())));
            assert!(record.body.contains("current-content author unknown"));
        }
        after = Some(feed.through);
        if feed.complete {
            complete = true;
            break;
        }
    }
    assert!(
        complete,
        "native capture feed did not finish its bounded fixture"
    );
    assert_eq!(
        edits, 1,
        "intent, failed read or duplicate capture became edit activity"
    );
    snapshot.close()?;
    Ok(())
}
