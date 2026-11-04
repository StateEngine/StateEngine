use se_store::*;
use se_types::{ProjectId, Read};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;

/// Bug: 4b063489 — a session could commit a message but its receipt continuation refused the same project's public registration metadata at SelfOnly scope.
#[test]
fn self_only_reads_registered_public_project_metadata_after_later_writes() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let mut before = direct.snapshot(f.self_scope(&f.a))?;
    let registered = present(before.project(f.project.clone())?)?;
    assert!(
        matches!(&registered.current.body, EventBody::ProjectRegistered {name,..} if name=="Project")
    );
    direct.append(
        f.working(
            "later unrelated state",
            Expected::Absent,
            "later-metadata-read",
        )?,
        &*lease,
    )?;
    assert_eq!(
        present(before.project(f.project.clone())?)?
            .current
            .header
            .event,
        registered.current.header.event
    );
    before.close()?;
    for scope in [
        f.self_scope(&f.a),
        f.self_scope(&f.b),
        f.scoped(Visibility::Owner),
        f.scoped(Visibility::SharedProject(f.a.clone())),
    ] {
        let mut read = direct.snapshot(scope)?;
        let project = present(read.project(f.project.clone())?)?;
        assert_eq!(project.revision.value.get(), 1);
        assert!(
            matches!(project.current.body, EventBody::ProjectRegistered {ref name,..} if name=="Project")
        );
        assert_eq!(
            project.current.header.event,
            registered.current.header.event
        );
        assert!(project.original.is_none());
        read.close()?;
    }
    Ok(())
}

/// Protects: project metadata scope — knowing another registered project ID cannot expand a SelfOnly snapshot beyond its admitted project.
#[test]
fn public_metadata_cannot_cross_admitted_projects() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let foreign = ProjectId::from_parts(1_700_000_000_000 + serial(), [83; 10])?;
    direct.append(
        f.batch(
            f.admission(
                Scope::Project(foreign.clone()),
                Actor::Human(f.owner.clone()),
            ),
            Some(request(&format!(
                "fixture-project_metadata-62-{}",
                serial()
            ))?),
            vec![EventBody::ProjectRegistered {
                project: foreign.clone(),
                name: "Other project".into(),
                roots: vec![],
                owner: f.owner.clone(),
                history_from: None,
                expected: Expected::Absent,
            }],
        )?,
        &*lease,
    )?;
    let mut read = direct.snapshot(f.self_scope(&f.a))?;
    assert_eq!(
        read.project(foreign)
            .err()
            .ok_or("foreign project metadata leaked")?
            .code,
        StoreErrorCode::ScopeMismatch
    );
    assert!(matches!(
        read.project(f.project.clone())?,
        Read::Present { .. }
    ));
    read.close()?;
    Ok(())
}

/// Protects: metadata is a narrow public view — direct event/history reads and other agents' private message/working-state bodies retain their SelfOnly visibility rules.
#[test]
fn metadata_access_does_not_open_event_or_private_body_visibility() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let mut owner = direct.snapshot(f.scoped(Visibility::Owner))?;
    let registration = present(owner.project(f.project.clone())?)?
        .current
        .header
        .event;
    owner.close()?;
    let mail = message()?;
    let sent = direct.append(
        f.send(
            Actor::Human(f.owner.clone()),
            Actor::Agent(f.b.clone()),
            mail,
            "private beta message",
            "beta-only",
        )?,
        &*lease,
    )?;
    let mut alpha = direct.snapshot(f.self_scope(&f.a))?;
    assert!(matches!(
        alpha.project(f.project.clone())?,
        Read::Present { .. }
    ));
    for id in [registration, sent.primary_event] {
        assert_eq!(
            alpha
                .event(id)
                .err()
                .ok_or("public metadata opened event body visibility")?
                .code,
            StoreErrorCode::ScopeMismatch
        );
    }
    assert_eq!(alpha.message_count(query(None, false))?, 0);
    let history = alpha.history(
        HistoryQuery {
            agent: None,
            session: None,
            kinds: vec![],
            families: vec![],
            transcript: se_store::TranscriptFilter::All,
            since: None,
        },
        budget(20, 65536, None)?,
    )?;
    assert!(
        history.items().is_empty(),
        "metadata exception expanded history bodies"
    );
    assert!(
        alpha
            .messages(query(None, false), budget(10, 65536, None)?)?
            .items()
            .is_empty()
    );
    alpha.close()?;
    Ok(())
}
