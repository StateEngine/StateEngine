//! Development checks for selector catalog snapshots, independent of CLI live lists.
use se_store::*;
use se_types::Page;
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
fn registry(f: &Fixture) -> ReadScope {
    ReadScope {
        admission: f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
        visibility: Visibility::Owner,
    }
}
fn agent_ids(page: &Page<ProjectionRecord>) -> Vec<String> {
    page.items()
        .iter()
        .map(
            |r| match &r.original.as_deref().unwrap_or(&r.current).body {
                EventBody::PrincipalRegistered {
                    principal: Actor::Agent(a),
                    ..
                } => a.as_str().into(),
                _ => "invalid".into(),
            },
        )
        .collect()
}
#[test]
fn selectors_use_id_order_and_stale_on_catalog_changes_only() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    // Registration order is deliberately the opposite of ID order.
    for agent in ["agt-zzzz-zzzz-zzzz", "agt-0000-0000-0000"] {
        direct.append(
            f.batch(
                f.owner_project(),
                None,
                vec![EventBody::PrincipalRegistered {
                    principal: Actor::Agent(se_types::AgentId::from_legacy(agent)?),
                    kind: PrincipalKind::Agent,
                    owner: f.owner.clone(),
                    created_by: None,
                    name: agent.into(),
                    role: "builder".into(),
                    expected: Expected::Absent,
                }],
            )?,
            &*lease,
        )?;
    }
    let mut read = direct.snapshot(f.scoped(Visibility::Owner))?;
    let first = read.selector_agents(budget(1, 65536, None)?)?;
    assert_eq!(agent_ids(&first), vec![f.a.as_str().to_owned()]);
    assert!(!first.window().complete());
    let next = first.next().cloned().ok_or("no selector cursor")?;
    let all = read.selector_agents(budget(100, 65536, None)?)?;
    let mut expected = vec![
        f.a.as_str().to_owned(),
        f.b.as_str().to_owned(),
        "agt-zzzz-zzzz-zzzz".into(),
        "agt-0000-0000-0000".into(),
    ];
    expected.sort();
    assert_eq!(agent_ids(&all), expected);
    assert!(all.window().complete());
    read.close()?;
    direct.append(
        f.working(
            "mail/capture/working-state changes do not stale the roster",
            Expected::Absent,
            "unrelated",
        )?,
        &*lease,
    )?;
    let mut read = direct.snapshot(f.scoped(Visibility::Owner))?;
    let remaining = read.selector_agents(budget(100, 65536, Some(next.clone()))?)?;
    assert_eq!(agent_ids(&remaining), expected[1..]);
    let cross_generation = ReadScope {
        admission: Admission {
            generation: 99,
            ..f.owner_project()
        },
        visibility: Visibility::Owner,
    };
    read.close()?;
    let mut read = direct.snapshot(cross_generation)?;
    assert_eq!(
        read.selector_agents(budget(1, 65536, Some(next.clone()))?)
            .err()
            .ok_or("generation was not bound")?
            .code,
        StoreErrorCode::CursorStale
    );
    read.close()?;
    direct.append(
        f.batch(
            f.owner_project(),
            None,
            vec![EventBody::PrincipalRenamed {
                principal: Actor::Agent(f.a.clone()),
                name: "New Alpha".into(),
                expected: revision(1)?,
            }],
        )?,
        &*lease,
    )?;
    let mut read = direct.snapshot(f.scoped(Visibility::Owner))?;
    assert_eq!(
        read.selector_agents(budget(100, 65536, Some(next))?)
            .err()
            .ok_or("catalog update did not stale cursor")?
            .code,
        StoreErrorCode::CursorStale
    );
    read.close()?;
    Ok(())
}
#[test]
fn selectors_refuse_session_scope_and_project_roster_is_separate() -> Check {
    let f = Fixture::new()?;
    let (direct, _lease) = f.direct()?;
    let mut read = direct.snapshot(f.self_scope(&f.a))?;
    for result in [
        read.selector_agents(budget(100, 65536, None)?),
        read.selector_projects(budget(100, 65536, None)?),
    ] {
        assert_eq!(
            result
                .err()
                .ok_or("session enumerated owner selectors")?
                .code,
            StoreErrorCode::ScopeMismatch
        );
    }
    read.close()?;
    let mut read = direct.snapshot(registry(&f))?;
    let projects = read.selector_projects(budget(100, 65536, None)?)?;
    assert_eq!(projects.items().len(), 1);
    assert!(projects.window().complete());
    read.close()?;
    Ok(())
}

#[test]
fn project_pages_sort_ids_and_stale_after_registration() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let z = se_types::ProjectId::from_parts(1_700_000_100_000, [90; 10])?;
    let a = se_types::ProjectId::from_parts(1_699_999_000_000, [10; 10])?;
    for (name, project) in [("z-project", z.clone()), ("a-project", a.clone())] {
        direct.append(
            f.batch(
                f.admission(
                    Scope::Project(project.clone()),
                    Actor::Human(f.owner.clone()),
                ),
                None,
                vec![EventBody::ProjectRegistered {
                    project,
                    name: name.into(),
                    roots: vec![],
                    owner: f.owner.clone(),
                    history_from: None,
                    expected: Expected::Absent,
                }],
            )?,
            &*lease,
        )?;
    }
    let mut read = direct.snapshot(registry(&f))?;
    let first = read.selector_projects(budget(1, 65536, None)?)?;
    assert!(
        matches!(&first.items()[0].current.body,EventBody::ProjectRegistered { project,.. } if project == &a)
    );
    let next = first.next().cloned().ok_or("project cursor absent")?;
    let remaining = read.selector_projects(budget(100, 65536, Some(next.clone()))?)?;
    let ids = remaining
        .items()
        .iter()
        .map(|r| match &r.current.body {
            EventBody::ProjectRegistered { project, .. } => project.as_str(),
            _ => "invalid",
        })
        .collect::<Vec<_>>();
    assert_eq!(ids, vec![f.project.as_str(), z.as_str()]);
    assert!(remaining.window().complete());
    read.close()?;
    let added = se_types::ProjectId::from_parts(1_700_000_200_000, [50; 10])?;
    direct.append(
        f.batch(
            f.admission(Scope::Project(added.clone()), Actor::Human(f.owner.clone())),
            None,
            vec![EventBody::ProjectRegistered {
                project: added,
                name: "Added project".into(),
                roots: vec![],
                owner: f.owner.clone(),
                history_from: None,
                expected: Expected::Absent,
            }],
        )?,
        &*lease,
    )?;
    let mut read = direct.snapshot(registry(&f))?;
    assert_eq!(
        read.selector_projects(budget(1, 65536, Some(next))?)
            .err()
            .ok_or("project change did not stale cursor")?
            .code,
        StoreErrorCode::CursorStale
    );
    read.close()?;
    Ok(())
}
