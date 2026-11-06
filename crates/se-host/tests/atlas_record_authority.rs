//! Author checks use the real native store and production record adapter.
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
use se_atlas::query::RecordReader;
use se_host::atlas_records::AtlasRecordReader;
use se_store::*;
use se_types::{Read, code::*};

#[test]
fn record_hits_recheck_visibility_and_read_the_matching_authoritative_line() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let private = message()?;
    let private_receipt = direct.append(
        f.send(
            Actor::Agent(f.a.clone()),
            Actor::Agent(f.a.clone()),
            private.clone(),
            "private packet budget",
            "atlas-private",
        )?,
        &*lease,
    )?;
    let shared = message()?;
    let shared_receipt = direct.append(
        f.send(
            Actor::Agent(f.a.clone()),
            Actor::Agent(f.b.clone()),
            shared.clone(),
            "Generic introduction\nThe packet budget is 600 bytes\nMore detail",
            "atlas-visible",
        )?,
        &*lease,
    )?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let b_scope = f.self_scope(&f.b);
    let mut snapshot = reader.snapshot(b_scope.clone())?;
    let access = AtlasRecordReader::new(&mut snapshot, &b_scope.admission);
    let viewer = AtlasPrincipal::Agent(f.b.clone());
    let query = QueryText::new("packet budget")?;
    let private = RecordPointer {
        key: RecordKey::new(private.as_str())?,
        kind: RecordKind::Message,
        source_event: private_receipt.primary_event,
    };
    assert!(matches!(
        access.read(&f.project, &viewer, &private, Some(&query))?,
        Read::Absent { .. }
    ));
    let pointer = RecordPointer {
        key: RecordKey::new(shared.as_str())?,
        kind: RecordKind::Message,
        source_event: shared_receipt.primary_event,
    };
    let hit = present(access.read(&f.project, &viewer, &pointer, Some(&query))?)?;
    assert_eq!(hit.line, "The packet budget is 600 bytes");
    assert_eq!(hit.pointer, pointer);
    let body = present(access.body(&f.project, &viewer, &pointer, Some(&query))?)?;
    assert_eq!(body.origin, BodyOrigin::AuthoritativeRecord(pointer));
    assert!(body.text.contains("packet budget"));
    assert!(
        access
            .read(
                &f.project,
                &AtlasPrincipal::Agent(f.a.clone()),
                &private,
                None
            )
            .is_err()
    );
    snapshot.close()?;
    Ok(())
}
#[test]
fn overwritten_working_state_cannot_render_from_a_stale_cached_pointer() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let old = direct.append(
        f.working("old private note", Expected::Absent, "atlas-old-working")?,
        &*lease,
    )?;
    let new = direct.append(
        f.working("current packet budget", revision(1)?, "atlas-new-working")?,
        &*lease,
    )?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let scope = f.self_scope(&f.a);
    let mut snapshot = reader.snapshot(scope.clone())?;
    let access = AtlasRecordReader::new(&mut snapshot, &scope.admission);
    let viewer = AtlasPrincipal::Agent(f.a.clone());
    let mut pointer = RecordPointer {
        key: RecordKey::new(f.a.as_str())?,
        kind: RecordKind::Working,
        source_event: old.primary_event,
    };
    assert!(matches!(
        access.read(&f.project, &viewer, &pointer, None)?,
        Read::Absent { .. }
    ));
    pointer.source_event = new.primary_event;
    let hit = present(access.read(&f.project, &viewer, &pointer, None)?)?;
    assert_eq!(hit.line, "current packet budget");
    snapshot.close()?;
    Ok(())
}

#[test]
fn committed_feed_preserves_source_order_and_does_not_replay_old_working_text() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let old = direct.append(
        f.working("replaced note", Expected::Absent, "atlas-feed-old")?,
        &*lease,
    )?;
    let new = direct.append(
        f.working("current note with alpha.rs", revision(1)?, "atlas-feed-new")?,
        &*lease,
    )?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let scope = f.scoped(Visibility::Owner);
    let mut snapshot = reader.snapshot(scope.clone())?;
    let first = se_core::atlas_records::feed::next(&mut snapshot, &scope.admission, None)?
        .ok_or("missing first committed feed")?;
    assert_eq!(first.through, old.primary_event);
    assert!(first.changes.is_empty());
    assert!(!first.complete);
    let second = se_core::atlas_records::feed::next(
        &mut snapshot,
        &scope.admission,
        Some(first.through.clone()),
    )?
    .ok_or("missing current feed")?;
    assert_eq!(second.after, Some(first.through));
    assert_eq!(second.through, new.primary_event);
    assert!(second.complete);
    let RecordFeedChange::Upsert(record) =
        second.changes.first().ok_or("current record omitted")?
    else {
        return Err("unexpected change kind".into());
    };
    assert_eq!(record.body, "current note with alpha.rs");
    assert_eq!(
        record.visibility,
        RecordVisibility::Restricted {
            audience: Some(vec![AtlasPrincipal::Agent(f.a.clone())]),
        }
    );
    assert!(
        se_core::atlas_records::feed::next(&mut snapshot, &scope.admission, Some(second.through))?
            .is_none()
    );
    snapshot.close()?;
    Ok(())
}

#[test]
fn committed_ratification_carries_a_separate_mention_weight_fact() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let id = se_types::DecisionId::from_parts(1, [8; 10])?;
    let proposal = direct.append(
        f.batch(
            f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.a.clone())),
            Some(request("atlas-proposal")?),
            vec![EventBody::DecisionProposed {
                decision: id.clone(),
                key: "atlas-budget".into(),
                statement: InputText::Inline("Use alpha.rs for the packet budget".into()),
                rationale: None,
                prior: None,
                kind: DecisionKind::Decision,
            }],
        )?,
        &*lease,
    )?;
    let ratified = direct.append(
        f.batch(
            f.owner_project(),
            Some(request("atlas-ratification")?),
            vec![EventBody::DecisionRatified {
                decision: id.clone(),
                expected: revision(1)?,
                approval: proposal.primary_event.clone(),
            }],
        )?,
        &*lease,
    )?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let scope = f.scoped(Visibility::Owner);
    let mut snapshot = reader.snapshot(scope.clone())?;
    let feed = se_core::atlas_records::feed::next(
        &mut snapshot,
        &scope.admission,
        Some(proposal.primary_event),
    )?
    .ok_or("ratification omitted")?;
    assert_eq!(feed.through, ratified.primary_event);
    assert_eq!(feed.changes.len(), 2);
    assert!(
        matches!(feed.changes.last(),Some(RecordFeedChange::Ratify{key,source_event,..}) if key.as_str()==id.as_str()&&source_event==&ratified.primary_event)
    );
    snapshot.close()?;
    Ok(())
}

#[test]
fn shared_work_mail_enters_the_feed_without_expanding_its_audience() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let id = message()?;
    let sent = direct.append(
        f.batch(
            f.owner_project(),
            Some(request("atlas-work-feed")?),
            vec![EventBody::WorkMessageSent {
                quiet: false,
                message: id.clone(),
                work: se_types::WorkAddressing {
                    action: se_types::WorkAction::Finding,
                    addressees: vec![f.a.clone()],
                },
                kind: "finding".into(),
                body: InputText::Inline("use alpha.rs for the packet budget".into()),
                refs: vec![],
                reply_to: None,
            }],
        )?,
        &*lease,
    )?;
    let store = present(SqliteFactory::open_reader(&f.options)?)?;
    let owner_scope = f.scoped(Visibility::Owner);
    let mut owner = store.snapshot(owner_scope.clone())?;
    let feed = se_core::atlas_records::feed::next(&mut owner, &owner_scope.admission, None)?
        .ok_or("work mail was omitted from committed record history")?;
    assert_eq!(feed.through, sent.primary_event);
    let RecordFeedChange::Upsert(record) = feed.changes.first().ok_or("work mail omitted")? else {
        return Err("unexpected feed change".into());
    };
    assert_eq!(record.body, "use alpha.rs for the packet budget");
    assert!(matches!(
        record.visibility,
        RecordVisibility::Restricted { .. }
    ));
    for (agent, expected) in [(&f.a, true), (&f.b, false)] {
        let scope = f.self_scope(agent);
        let mut snapshot = store.snapshot(scope.clone())?;
        let access = AtlasRecordReader::new(&mut snapshot, &scope.admission);
        let hit = access.read(
            &f.project,
            &AtlasPrincipal::Agent(agent.clone()),
            &record.pointer,
            None,
        )?;
        assert_eq!(matches!(hit, Read::Present { .. }), expected);
        snapshot.close()?;
    }
    owner.close()?;
    Ok(())
}
