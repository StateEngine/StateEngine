//! Real direct-writer/readback judges for projects which never launched a session.
#![cfg(any(target_os = "linux", windows))]
use se_store::*;
use se_types::{IdempotencyKey, ProjectId};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
fn project() -> Result<ProjectId, Box<dyn std::error::Error>> {
    Ok(ProjectId::from_parts(
        1_700_000_000_000 + serial(),
        [77; 10],
    )?)
}
fn commit(
    f: &Fixture,
    writer: &mut SqliteDirect,
    lease: &Lease,
    scope: Scope,
    body: EventBody<InputText>,
) -> Result<CommitReceipt, Box<dyn std::error::Error>> {
    Ok(writer.append(
        f.batch(
            f.admission(scope, Actor::Human(f.owner.clone())),
            Some(request(&format!(
                "fixture-wave2_empty_project_removal_independent-22-{}",
                serial()
            ))?),
            vec![body],
        )?,
        lease,
    )?)
}
fn registration(f: &Fixture, id: &ProjectId) -> EventBody<InputText> {
    EventBody::ProjectRegistered {
        project: id.clone(),
        name: "Never launched".into(),
        roots: vec![],
        owner: f.owner.clone(),
        history_from: None,
        expected: Expected::Absent,
    }
}
fn removal(
    id: &ProjectId,
    rev: u64,
    witness: se_types::EventId,
) -> Result<EventBody<InputText>, Box<dyn std::error::Error>> {
    Ok(EventBody::ProjectRemoved {
        project: id.clone(),
        expected: revision(rev)?,
        witnesses: vec![witness],
        preserved: vec!["retain project history".into()],
    })
}
fn snapshot(f: &Fixture, id: &ProjectId) -> Result<SqliteSnapshot, Box<dyn std::error::Error>> {
    Ok(
        present(SqliteFactory::open_reader(&f.options)?)?.snapshot(ReadScope {
            admission: f.admission(Scope::Project(id.clone()), Actor::Human(f.owner.clone())),
            visibility: Visibility::Owner,
        })?,
    )
}

/// Protects: a fresh init can be removed without inventing a session or effect.
#[test]
fn never_launched_project_removes_with_its_current_registry_registration() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let id = project()?;
    let registered = commit(
        &f,
        &mut writer,
        &lease,
        Scope::Registry,
        registration(&f, &id),
    )?;
    let head = present(snapshot(&f, &id)?.project(id.clone())?)?;
    assert!(matches!(head.current.header.scope, Scope::Registry));
    assert_eq!(head.current.header.event, registered.primary_event);
    let result = commit(
        &f,
        &mut writer,
        &lease,
        Scope::Project(id.clone()),
        removal(&id, 1, registered.primary_event.clone())?,
    );
    assert!(
        result.is_ok(),
        "fresh never-launched project refused its current registry witness: {}",
        result.err().map(|e| e.to_string()).unwrap_or_default()
    );
    let mut outside = snapshot(&f, &id)?;
    assert!(matches!(
        present(outside.project(id)?)?.current.body,
        EventBody::ProjectRemoved { .. }
    ));
    let scoped = outside.event(registered.primary_event.clone());
    let scoped = scoped
        .err()
        .ok_or("project event reader gained Registry scope")?;
    assert_eq!(scoped.code, StoreErrorCode::ScopeMismatch);
    let mut registry = present(SqliteFactory::open_reader(&f.options)?)?.snapshot(ReadScope {
        admission: f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
        visibility: Visibility::Owner,
    })?;
    assert!(matches!(
        registry.event(registered.primary_event)?,
        se_types::Read::Present { .. }
    ));
    Ok(())
}

/// Protects: the registry witness exception cannot relax owner or project CAS checks.
#[test]
fn empty_registry_witness_preserves_owner_and_expected_revision() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let id = project()?;
    let registered = commit(
        &f,
        &mut writer,
        &lease,
        Scope::Registry,
        registration(&f, &id),
    )?;
    let other = se_types::HumanId::from_parts(1_700_000_000_000 + serial(), [94; 10])?;
    let actor = Actor::Human(other.clone());
    writer.append(
        f.batch(
            f.admission(Scope::Registry, actor.clone()),
            Some(request(&format!(
                "fixture-wave2_empty_project_removal_independent-126-{}",
                serial()
            ))?),
            vec![EventBody::PrincipalRegistered {
                principal: actor.clone(),
                kind: PrincipalKind::Human,
                owner: other,
                created_by: None,
                name: "Other owner".into(),
                role: "owner".into(),
                expected: Expected::Absent,
            }],
        )?,
        &*lease,
    )?;
    let before = snapshot(&f, &id)?.info().head;
    let nonowner = writer.append(
        f.batch(
            f.admission(Scope::Project(id.clone()), actor),
            Some(request(&format!(
                "fixture-wave2_empty_project_removal_independent-143-{}",
                serial()
            ))?),
            vec![removal(&id, 1, registered.primary_event.clone())?],
        )?,
        &*lease,
    );
    let nonowner = nonowner
        .err()
        .ok_or("foreign human removed a project with its registry witness")?;
    assert_eq!(nonowner.code, StoreErrorCode::ScopeMismatch);
    assert!(
        nonowner.cause.contains("owner"),
        "non-owner refusal lost its reason: {nonowner}"
    );
    let stale = commit(
        &f,
        &mut writer,
        &lease,
        Scope::Project(id.clone()),
        removal(&id, 2, registered.primary_event)?,
    );
    let stale = stale
        .err()
        .ok_or("stale project revision was removed with its registry witness")?;
    assert!(
        stale.to_string().contains("RevisionConflict"),
        "wrong stale revision refusal: {stale}"
    );
    assert_eq!(
        snapshot(&f, &id)?.info().head,
        before,
        "refused removal changed the store"
    );
    Ok(())
}

/// Protects: the narrow exception cannot launder other registry facts into this project.
#[test]
fn empty_project_refuses_foreign_or_unrelated_registry_witnesses() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let id = project()?;
    commit(
        &f,
        &mut writer,
        &lease,
        Scope::Registry,
        registration(&f, &id),
    )?;
    let foreign = project()?;
    let foreign = commit(
        &f,
        &mut writer,
        &lease,
        Scope::Registry,
        registration(&f, &foreign),
    )?;
    let other = se_types::HumanId::from_parts(1_700_000_000_000 + serial(), [93; 10])?;
    let actor = Actor::Human(other.clone());
    let unrelated = writer.append(
        f.batch(
            f.admission(Scope::Registry, actor.clone()),
            Some(request(&format!(
                "fixture-wave2_empty_project_removal_independent-204-{}",
                serial()
            ))?),
            vec![EventBody::PrincipalRegistered {
                principal: actor,
                kind: PrincipalKind::Human,
                owner: other,
                created_by: None,
                name: "Unrelated registry owner".into(),
                role: "owner".into(),
                expected: Expected::Absent,
            }],
        )?,
        &*lease,
    )?;
    let before = snapshot(&f, &id)?.info().head;
    for (label, witness) in [
        ("another project", foreign.primary_event),
        ("unrelated principal", unrelated.primary_event.clone()),
    ] {
        assert!(
            commit(
                &f,
                &mut writer,
                &lease,
                Scope::Project(id.clone()),
                removal(&id, 1, witness)?
            )
            .is_err(),
            "{label} registry event removed this project"
        );
        assert_eq!(
            snapshot(&f, &id)?.info().head,
            before,
            "{label} refusal changed the store"
        );
    }
    let foreign_cause = unrelated.primary_event;
    let ordinary = EventBody::EffectRequested {
        principal: None,
        effect: RecordId::from_parts(1_700_000_000_000 + serial(), [88; 10])?,
        kind: EffectKind::RuntimeStart,
        intent: EffectIntent::Runtime { generation: 1 },
        cause: foreign_cause,
        request_key: IdempotencyKey::new("ordinary-reference-stays-scoped")?,
    };
    assert!(
        commit(
            &f,
            &mut writer,
            &lease,
            Scope::Project(id.clone()),
            ordinary
        )
        .is_err(),
        "ordinary project reference acquired registry authority"
    );
    assert_eq!(snapshot(&f, &id)?.info().head, before);
    Ok(())
}
