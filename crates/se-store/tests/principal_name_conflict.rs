//! Public writer checks keep name conflicts atomic and original-key replays intact.
use se_store::*;
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[test]
fn duplicate_registration_and_rename_keep_the_existing_identity_and_head() -> Check {
    let fixture = Fixture::new()?;
    let (mut store, lease) = fixture.direct()?;
    let head = store.info()?.head;
    let new = agent()?;
    for body in [
        EventBody::PrincipalRegistered {
            principal: Actor::Agent(new.clone()),
            kind: PrincipalKind::Agent,
            owner: fixture.owner.clone(),
            created_by: None,
            name: "Alpha".into(),
            role: "".into(),
            expected: Expected::Absent,
        },
        EventBody::PrincipalRenamed {
            principal: Actor::Agent(fixture.b.clone()),
            name: "Alpha".into(),
            expected: revision(1)?,
        },
    ] {
        let error = store
            .append(
                fixture.batch(
                    fixture.owner_project(),
                    Some(request("conflict")?),
                    vec![body],
                )?,
                &*lease,
            )
            .err()
            .ok_or("duplicate name accepted")?;
        assert_eq!(error.code, StoreErrorCode::AlreadyExists);
        assert!(
            matches!(error.detail,StoreDetail::PrincipalNameConflict { project,ref name,existing:Actor::Agent(existing) } if project==fixture.project && name=="Alpha" && existing==fixture.a)
        );
        assert_eq!(store.info()?.head, head);
    }
    // A legal different name still commits, and a lost-reply retry resolves
    // before the duplicate-name guard using the original request identity.
    let make = || {
        fixture.batch(
            fixture.owner_project(),
            Some(request("create-gamma")?),
            vec![EventBody::PrincipalRegistered {
                principal: Actor::Agent(new.clone()),
                kind: PrincipalKind::Agent,
                owner: fixture.owner.clone(),
                created_by: None,
                name: "Gamma".into(),
                role: "".into(),
                expected: Expected::Absent,
            }],
        )
    };
    let created = store.append(make()?, &*lease)?;
    let replay = store.append(make()?, &*lease)?;
    assert_eq!(replay.state, CommitState::Replayed);
    assert_eq!(created.primary_event, replay.primary_event);
    store.close()?;
    Ok(())
}
