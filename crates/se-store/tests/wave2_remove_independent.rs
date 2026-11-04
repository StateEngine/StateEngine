//! Empty-project removal uses the same registry witness as the public host.
#![cfg(any(target_os = "linux", windows))]
use se_store::*;
use se_types::{ProjectId, Read};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;

fn register(
    f: &Fixture,
    d: &mut SqliteDirect,
    lease: &Lease,
) -> Result<(ProjectId, se_types::EventId), Box<dyn std::error::Error>> {
    let project = ProjectId::from_parts(1_700_000_000_000 + serial(), [71; 10])?;
    let batch = f.batch(
        f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
        Some(request(&format!(
            "fixture-wave2_remove_independent-15-{}",
            serial()
        ))?),
        vec![EventBody::ProjectRegistered {
            project: project.clone(),
            name: "Never launched".into(),
            roots: vec![],
            owner: f.owner.clone(),
            history_from: None,
            expected: Expected::Absent,
        }],
    )?;
    let witness = batch.events[0].header.event.clone();
    d.append(batch, lease)?;
    Ok((project, witness))
}
fn remove(
    f: &Fixture,
    project: &ProjectId,
    witness: se_types::EventId,
) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    f.batch(
        f.admission(
            Scope::Project(project.clone()),
            Actor::Human(f.owner.clone()),
        ),
        Some(request(&format!(
            "fixture-wave2_remove_independent-36-{}",
            serial()
        ))?),
        vec![EventBody::ProjectRemoved {
            project: project.clone(),
            expected: revision(1)?,
            witnesses: vec![witness],
            preserved: vec!["User files and immutable history retained".into()],
        }],
    )
}

/// Protects: remove of a project with no sessions or processes may cite its
/// own registry-scoped registration, as the public no-effect fallback does.
#[test]
fn never_launched_project_removes_using_its_registry_registration() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let (project, witness) = register(&f, &mut d, &lease)?;
    d.append(remove(&f, &project, witness.clone())?, &*lease)?;
    let mut read = d.snapshot(ReadScope {
        admission: f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
        visibility: Visibility::Owner,
    })?;
    let head = present(read.project(project.clone())?)?;
    assert!(
        matches!(head.current.body, EventBody::ProjectRemoved { project: ref id, .. } if id == &project)
    );
    assert!(
        matches!(
            read.event(witness)?,
            Read::Present {
                value: StoredEvent {
                    body: EventBody::ProjectRegistered { .. },
                    ..
                }
            }
        ),
        "removal erased registration evidence"
    );
    read.close()?;
    d.close()?;
    drop(lease);
    Ok(())
}

/// Protects: admitting the target registration never admits another project's
/// registration or an unrelated registry event as evidence for removal.
#[test]
fn foreign_and_unrelated_registry_witnesses_do_not_remove_a_project() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let (project, _) = register(&f, &mut d, &lease)?;
    let (_, foreign) = register(&f, &mut d, &lease)?;
    let mut read = d.snapshot(ReadScope {
        admission: f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
        visibility: Visibility::Owner,
    })?;
    let unrelated = present(read.principal(Actor::Human(f.owner.clone()))?)?
        .current
        .header
        .event;
    read.close()?;
    for witness in [foreign, unrelated] {
        assert!(
            d.append(remove(&f, &project, witness)?, &*lease).is_err(),
            "invalid registry evidence removed target"
        );
    }
    let mut read = d.snapshot(ReadScope {
        admission: f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
        visibility: Visibility::Owner,
    })?;
    assert!(matches!(
        present(read.project(project)?)?.current.body,
        EventBody::ProjectRegistered { .. }
    ));
    read.close()?;
    d.close()?;
    drop(lease);
    Ok(())
}
