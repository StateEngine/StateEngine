use se_store::*;
use se_types::{EventId, ProjectId, Read};
#[path = "support/store_fixture.rs"]
mod fixture;
#[allow(
    dead_code,
    reason = "Shared native host fixture also serves writer-queue consumers."
)]
#[path = "support/host_fixture.rs"]
mod host_fixture;
use fixture::*;
fn legacy(n: u64) -> Result<EventId, Box<dyn std::error::Error>> {
    Ok(EventId::from_legacy(format!("evt-{n:064x}"))?)
}
// Retained alias dictionary fixtures exercise public reads of historical names;
// they claim no import execution or native authority.
fn alias(
    f: &Fixture,
    id: &EventId,
    project: &ProjectId,
) -> Result<EventId, Box<dyn std::error::Error>> {
    let old = legacy(serial())?;
    let key = id
        .canonical_bytes()?
        .ok_or("canonical retained fixture event")?;
    let mut scope = vec![1];
    scope.extend_from_slice(
        &project
            .canonical_bytes()?
            .ok_or("canonical fixture project")?,
    );
    let db = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    db.execute("INSERT INTO identities(storage_key,kind,wire_id,scope_key,encoding) VALUES(?,'event',?,?,'legacy-shape')",rusqlite::params![key.as_slice(),old.as_str(),scope])?;
    Ok(old)
}
fn project(
    f: &Fixture,
    store: &mut SqliteDirect,
    lease: &Lease,
) -> Result<ProjectId, Box<dyn std::error::Error>> {
    let p = ProjectId::from_parts(1_700_000_000_000 + serial(), [76; 10])?;
    store.append(
        f.batch(
            f.admission(Scope::Project(p.clone()), Actor::Human(f.owner.clone())),
            Some(request(&format!("fixture-event_scope-43-{}", serial()))?),
            vec![EventBody::ProjectRegistered {
                project: p.clone(),
                name: "Foreign".into(),
                roots: vec![],
                owner: f.owner.clone(),
                history_from: None,
                expected: Expected::Absent,
            }],
        )?,
        lease,
    )?;
    Ok(p)
}
fn history(snapshot: &mut impl Snapshot) -> Result<Vec<EventId>, Box<dyn std::error::Error>> {
    Ok(snapshot
        .history(
            HistoryQuery {
                agent: None,
                session: None,
                kinds: vec![],
                families: vec![],
                transcript: se_store::TranscriptFilter::All,
                since: None,
            },
            budget(100, 1_048_576, None)?,
        )?
        .items()
        .iter()
        .map(|event| event.header.event.clone())
        .collect())
}

/// Protects: exact canonical IDs and retained legacy aliases return their original visible event; genuinely unknown IDs remain measured absence and do not mutate the store.
#[test]
fn visible_and_unknown_ids_remain_distinct() -> Check {
    for old in [false, true] {
        let f = Fixture::new()?;
        let (mut store, lease) = f.direct()?;
        let id = event()?;
        let mut batch = f.working("exact immutable body", Expected::Absent, "visible")?;
        batch.events[0].header.event = id.clone();
        let receipt = store.append(batch, &*lease)?;
        let head = store.info()?.head;
        let lookup = if old {
            alias(&f, &id, &f.project)?
        } else {
            id.clone()
        };
        let mut snapshot = store.snapshot(f.self_scope(&f.a))?;
        let value = present(snapshot.event(lookup)?)?;
        assert_eq!(value.header.event, id);
        assert_eq!(value.position, receipt.first);
        assert!(
            matches!(value.body,EventBody::WorkingStateSet{text:StoredText::Present(ref text),..} if text=="exact immutable body")
        );
        assert!(matches!(
            snapshot.event(if old { legacy(serial())? } else { event()? })?,
            Read::Absent { .. }
        ));
        snapshot.close()?;
        assert_eq!(store.info()?.head, head);
        store.close()?;
    }
    Ok(())
}

/// Protects: a retained foreign event is a scope refusal for canonical and scoped legacy IDs, before its damaged body is loaded; exact lookups never widen history.
#[test]
fn foreign_ids_refuse_before_payload_and_preserve_history_scope() -> Check {
    for old in [false, true] {
        let f = Fixture::new()?;
        let (mut store, lease) = f.direct()?;
        let foreign = project(&f, &mut store, &lease)?;
        let id = event()?;
        let mut batch = f.batch(
            f.admission(
                Scope::Project(foreign.clone()),
                Actor::Human(f.owner.clone()),
            ),
            Some(request(&format!("fixture-event_scope-120-{}", serial()))?),
            vec![EventBody::PrincipalRegistered {
                principal: Actor::Human(f.owner.clone()),
                kind: PrincipalKind::Human,
                owner: f.owner.clone(),
                created_by: None,
                name: "Foreign private metadata".into(),
                role: "owner".into(),
                expected: Expected::Absent,
            }],
        )?;
        batch.events[0].header.event = id.clone();
        store.append(batch, &*lease)?;
        let lookup = if old {
            alias(&f, &id, &foreign)?
        } else {
            id.clone()
        };
        let mut snapshot = store.snapshot(f.scoped(Visibility::Owner))?;
        let before = history(&mut snapshot)?;
        let error = snapshot
            .event(lookup.clone())
            .err()
            .ok_or("known foreign event became absence")?;
        assert_eq!(error.code, StoreErrorCode::ScopeMismatch);
        assert_eq!(history(&mut snapshot)?, before);
        assert!(!before.contains(&id));
        snapshot.close()?;
        store.close()?;
        drop(lease);
        // Foreign payload damage must not replace the earlier scope refusal.
        let db = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
        db.execute_batch("DROP TABLE aux_data")?;
        drop(db);
        let reader = present(SqliteFactory::open_reader(&f.options)?)?;
        let mut snapshot = reader.snapshot(f.scoped(Visibility::Owner))?;
        assert_eq!(
            snapshot
                .event(lookup)
                .err()
                .ok_or("foreign damaged event became absence")?
                .code,
            StoreErrorCode::ScopeMismatch
        );
        snapshot.close()?;
    }
    Ok(())
}

/// Protects: a known same-project event outside SelfOnly visibility refuses, while the owner's exact lookup and lists retain their original scope.
#[test]
fn same_project_private_event_refuses_self_visibility() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let receipt = store.append(
        f.working("another agent private body", Expected::Absent, "private")?,
        &*lease,
    )?;
    let mut own = store.snapshot(f.self_scope(&f.b))?;
    let before = history(&mut own)?;
    assert_eq!(
        own.event(receipt.primary_event.clone())
            .err()
            .ok_or("private event became absent or visible")?
            .code,
        StoreErrorCode::ScopeMismatch
    );
    assert_eq!(history(&mut own)?, before);
    assert!(!before.contains(&receipt.primary_event));
    own.close()?;
    let mut owner = store.snapshot(f.scoped(Visibility::Owner))?;
    assert_eq!(
        present(owner.event(receipt.primary_event.clone())?)?
            .header
            .event,
        receipt.primary_event
    );
    owner.close()?;
    store.close()?;
    Ok(())
}

/// Protects: actual retained runtime-owner facts refuse exact public event access from both project and registry snapshots; their existence is never reported as not-found.
#[test]
fn runtime_private_ids_refuse_project_and_registry_readers() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host_fixture::host(&f)?;
    let runtime = present(host.runtime_owner()?)?;
    for scope in [
        f.scoped(Visibility::Owner),
        ReadScope {
            admission: f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
            visibility: Visibility::Owner,
        },
    ] {
        let mut snapshot = host.snapshot(scope)?;
        assert_eq!(
            snapshot
                .event(runtime.event.clone())
                .err()
                .ok_or("runtime-private event became absence or public data")?
                .code,
            StoreErrorCode::ScopeMismatch
        );
        snapshot.close()?;
    }
    drop(host);
    drop(lease);
    Ok(())
}
