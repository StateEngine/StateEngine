#![allow(
    dead_code,
    reason = "The shared fixture supports other store consumers."
)]
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
use se_store::*;

#[test]
fn designation_is_project_scoped_revisable_and_owner_controlled() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let project = f.project.clone();
    let select = EventBody::ProjectCaptainChanged {
        project: project.clone(),
        captain: Some(Actor::Agent(f.a.clone())),
        expected: Expected::Absent,
    };
    writer.append(
        f.batch(
            f.owner_project(),
            Some(request("captain-set")?),
            vec![select],
        )?,
        &*lease,
    )?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut snapshot = reader.snapshot(f.self_scope(&f.b))?;
    let saved = present(snapshot.project_captain()?)?;
    assert!(
        matches!(saved.current.body, EventBody::ProjectCaptainChanged { captain: Some(Actor::Agent(ref agent)), .. } if agent == &f.a)
    );
    snapshot.close()?;
    let unauthorized = EventBody::ProjectCaptainChanged {
        project: project.clone(),
        captain: None,
        expected: revision(1)?,
    };
    let error = writer
        .append(
            f.batch(
                f.admission(Scope::Project(project.clone()), Actor::Agent(f.b.clone())),
                Some(request("unauthorized")?),
                vec![unauthorized],
            )?,
            &*lease,
        )
        .err()
        .ok_or("agent changed captain")?;
    assert_eq!(error.code, StoreErrorCode::ScopeMismatch);
    let clear = EventBody::ProjectCaptainChanged {
        project,
        captain: None,
        expected: revision(1)?,
    };
    writer.append(
        f.batch(
            f.owner_project(),
            Some(request("captain-clear")?),
            vec![clear],
        )?,
        &*lease,
    )?;
    let mut snapshot = reader.snapshot(f.scoped(Visibility::Owner))?;
    let saved = present(snapshot.project_captain()?)?;
    assert!(matches!(
        saved.current.body,
        EventBody::ProjectCaptainChanged { captain: None, .. }
    ));
    snapshot.close()?;
    let owner = EventBody::ProjectCaptainChanged {
        project: f.project.clone(),
        captain: Some(Actor::Human(f.owner.clone())),
        expected: revision(2)?,
    };
    writer.append(
        f.batch(
            f.owner_project(),
            Some(request("captain-owner")?),
            vec![owner],
        )?,
        &*lease,
    )?;
    let mut snapshot = reader.snapshot(f.scoped(Visibility::Owner))?;
    let saved = present(snapshot.project_captain()?)?;
    assert!(
        matches!(saved.current.body, EventBody::ProjectCaptainChanged { captain: Some(Actor::Human(ref owner)), .. } if owner == &f.owner)
    );
    snapshot.close()?;
    Ok(())
}
