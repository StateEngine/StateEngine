//! Independent wave-2 store judges. These persist typed store facts; they do
//! not claim native launch custody, provider execution or host authentication.
#![cfg(any(target_os = "linux", windows))]
use se_store::*;
use se_types::{AgentId, LifecycleId, Read, SessionId};
use std::time::Duration;
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "support/host_fixture.rs"]
mod native_host;
use native_host::*;
#[path = "support/capture_fixture.rs"]
#[allow(dead_code, reason = "only typed session preparation is shared")]
mod capture;

#[path = "support/wave2_control_fixture.rs"]
#[allow(
    dead_code,
    reason = "checkpoint and creator judges share typed store fixtures"
)]
mod control_fixture;
use control_fixture::*;
/// Protects: a creator controls only its direct child under a current grant; bounded metadata never widens ordinary private readers.
#[test]
fn creator_control_checks_grant_and_direct_child_in_one_snapshot() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let writer = host.start_writer(options(256)?, lease)?;
    let client = writer.client();
    let child = agent()?;
    let grandchild = agent()?;
    let other = agent()?;
    wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!(
            "fixture-wave2_control_independent-34-{}",
            serial()
        ))?),
        vec![
            grant(&f.a, true, Expected::Absent),
            helper(&f, &child, Some(&f.a)),
            helper(&f, &grandchild, Some(&child)),
            helper(&f, &other, Some(&f.b)),
            EventBody::ProfileSaved {
                agent: child.clone(),
                profile: Profile {
                    provider: Provider::Claude,
                    model: Some("private-model".into()),
                    permission: PermissionProfile::WorkspaceWrite,
                    named_profile: "workspace-write".into(),
                    effort: None,
                },
                expected: Expected::Absent,
            },
        ],
    )?)?)??;
    let session = capture::session()?;
    let admission = f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.a.clone()));
    let session_receipt = wait(client.submit(f.batch(
        admission.clone(),
        Some(request(&format!(
            "fixture-wave2_control_independent-57-{}",
            serial()
        ))?),
        vec![capture::prepared(&f, &session, &child)],
    )?)?)??;
    let source = capture::record()?;
    wait(client.submit(f.batch(
        admission.clone(),
        Some(request(&format!("creator-capture-source-{}", serial()))?),
        vec![capture::source(
            source,
            &session,
            b"child",
            Expected::Absent,
        )],
    )?)?)??;
    assert_eq!(
        wait(client.submit(f.batch(
            admission.clone(),
            Some(request(&format!(
                "creator-capture-replacement-{}",
                serial()
            ))?),
            vec![capture::source(
                source,
                &session,
                b"replacement",
                revision(1)?
            )],
        )?)?)?
        .err()
        .ok_or("creator replaced a child's private capture source")?
        .code,
        StoreErrorCode::ScopeMismatch
    );
    let foreign_session = capture::session()?;
    wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!("foreign-capture-session-{}", serial()))?),
        vec![capture::prepared(&f, &foreign_session, &f.b)],
    )?)?)??;
    assert_eq!(
        wait(client.submit(f.batch(
            admission.clone(),
            Some(request(&format!("foreign-capture-source-{}", serial()))?),
            vec![capture::source(
                capture::record()?,
                &foreign_session,
                b"foreign",
                Expected::Absent
            )],
        )?)?)?
        .err()
        .ok_or("creator registered capture for an unrelated agent")?
        .code,
        StoreErrorCode::CreatorControlRefused
    );
    let mut process = identity(&child)?;
    process.root_identity = RootIdentityState::NoChildCreated;
    process.session = Some(session.clone());
    wait(client.submit(f.batch(
        admission.clone(),
        Some(request(&format!(
            "fixture-wave2_control_independent-65-{}",
            serial()
        ))?),
        vec![registration(&process, ProcessState::Reserved)],
    )?)?)??;
    process.root_identity = RootIdentityState::Unpublished;
    wait(client.submit(f.batch(
        admission.clone(),
        Some(request(&format!(
            "fixture-wave2_control_independent-71-{}",
            serial()
        ))?),
        vec![transition(
            &process,
            1,
            ProcessState::Reserved,
            ProcessState::Starting,
            session_receipt.primary_event.clone(),
        )?],
    )?)?)??;
    let private_message = message()?;
    wait(client.submit(f.send(
        Actor::Human(f.owner.clone()),
        Actor::Agent(child.clone()),
        private_message.clone(),
        "child private mail",
        "child-mail",
    )?)?)??;
    wait(client.submit(f.batch(
        f.admission(
            Scope::Project(f.project.clone()),
            Actor::Agent(child.clone()),
        ),
        Some(request(&format!(
            "fixture-wave2_control_independent-90-{}",
            serial()
        ))?),
        vec![EventBody::WorkingStateSet {
            agent: child.clone(),
            text: InputText::Inline("child private continuity".into()),
            expected: Expected::Absent,
        }],
    )?)?)??;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut snapshot = reader.snapshot(f.self_scope(&f.a))?;
    let own_grant = present(snapshot.grant(
        Actor::Agent(f.a.clone()),
        GrantKey::AgentCanCreate(f.a.clone()),
    )?)?;
    assert!(matches!(
        own_grant.current.body,
        EventBody::GrantRecorded { active: true, .. }
    ));
    assert_eq!(
        snapshot
            .event(own_grant.current.header.event)
            .err()
            .ok_or("permission read widened ordinary event visibility")?
            .code,
        StoreErrorCode::ScopeMismatch
    );
    assert_eq!(
        reader
            .snapshot(f.self_scope(&f.b))?
            .grant(
                Actor::Agent(f.a.clone()),
                GrantKey::AgentCanCreate(f.a.clone()),
            )
            .err()
            .ok_or("other agent's private grant became visible")?
            .code,
        StoreErrorCode::ScopeMismatch
    );
    let control = present(snapshot.control_target(child.clone())?)?;
    assert!(
        matches!(control.profile, Read::Present { value } if matches!(&value.current.body, EventBody::ProfileSaved { agent, .. } if agent == &child))
    );
    assert_eq!(control.sessions.len(), 1);
    assert_eq!(control.processes.len(), 1);
    assert!(
        matches!(&control.sessions[0].current.body, EventBody::SessionPrepared { session: id, .. } if *id == session)
    );
    assert!(
        matches!(&control.processes[0].current.body, EventBody::ProcessTransition { identity, to: ProcessState::Starting, .. } if identity.record == process.record)
    );
    assert!(snapshot.profile(child.clone()).is_err());
    assert!(snapshot.working_state(child.clone()).is_err());
    assert!(snapshot.message(private_message).is_err());
    assert!(snapshot.session(session.clone()).is_err());
    assert!(
        snapshot
            .turns(child.clone(), budget(10, 32768, None)?)
            .is_err()
    );
    assert!(snapshot.resume_head(Actor::Agent(child.clone())).is_err());
    for forbidden in [f.b.clone(), grandchild.clone(), other.clone()] {
        assert_eq!(
            snapshot
                .control_target(forbidden.clone())
                .err()
                .ok_or("non-child control read admitted")?
                .code,
            StoreErrorCode::CreatorControlRefused
        );
        let attempted = capture::session()?;
        assert_eq!(
            wait(client.submit(f.batch(
                admission.clone(),
                Some(request(&format!(
                    "judge-nested-wave2_control_independent-152-{}",
                    serial()
                ))?),
                vec![capture::prepared(&f, &attempted, &forbidden)]
            )?)?)?
            .err()
            .ok_or("non-child session write admitted")?
            .code,
            StoreErrorCode::CreatorControlRefused
        );
        let wrong = identity(&forbidden)?;
        assert_eq!(
            wait(client.submit(f.batch(
                admission.clone(),
                Some(request(&format!(
                    "judge-nested-wave2_control_independent-164-{}",
                    serial()
                ))?),
                vec![registration(&wrong, ProcessState::Starting)]
            )?)?)?
            .err()
            .ok_or("non-child process write admitted")?
            .code,
            StoreErrorCode::CreatorControlRefused
        );
    }
    let missing_grant = f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.b.clone()));
    assert_eq!(
        reader
            .snapshot(f.self_scope(&f.b))?
            .control_target(other.clone())
            .err()
            .ok_or("creator without a grant read its child")?
            .code,
        StoreErrorCode::CreatorControlRefused
    );
    let ungranted_session = capture::session()?;
    assert_eq!(
        wait(client.submit(f.batch(
            missing_grant.clone(),
            Some(request(&format!(
                "judge-nested-wave2_control_independent-187-{}",
                serial()
            ))?),
            vec![capture::prepared(&f, &ungranted_session, &other)]
        )?)?)?
        .err()
        .ok_or("creator without a grant prepared its child")?
        .code,
        StoreErrorCode::CreatorControlRefused
    );
    assert_eq!(
        wait(client.submit(f.batch(
            missing_grant,
            Some(request(&format!(
                "judge-nested-wave2_control_independent-198-{}",
                serial()
            ))?),
            vec![registration(&identity(&other)?, ProcessState::Starting)]
        )?)?)?
        .err()
        .ok_or("creator without a grant wrote its child process")?
        .code,
        StoreErrorCode::CreatorControlRefused
    );
    let mut human = identity(&child)?;
    human.principal = Actor::Human(f.owner.clone());
    assert!(
        wait(client.submit(f.batch(
            admission.clone(),
            Some(request(&format!(
                "judge-nested-wave2_control_independent-211-{}",
                serial()
            ))?),
            vec![registration(&human, ProcessState::Starting)]
        )?)?)?
        .is_err(),
        "creator controlled a human principal"
    );
    wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!(
            "fixture-wave2_control_independent-204-{}",
            serial()
        ))?),
        vec![grant(&f.a, false, revision(1)?)],
    )?)?)??;
    assert_eq!(
        wait(client.submit(f.batch(
            admission.clone(),
            Some(request(&format!("revoked-capture-source-{}", serial()))?),
            vec![capture::source(
                capture::record()?,
                &session,
                b"revoked",
                Expected::Absent
            )],
        )?)?)?
        .err()
        .ok_or("revoked creator registered child capture")?
        .code,
        StoreErrorCode::CreatorControlRefused
    );
    // The already measured snapshot keeps its grant and child facts together.
    assert!(matches!(
        snapshot.control_target(child.clone())?,
        Read::Present { .. }
    ));
    let mut current = reader.snapshot(f.self_scope(&f.a))?;
    assert!(matches!(
        present(current.grant(
            Actor::Agent(f.a.clone()),
            GrantKey::AgentCanCreate(f.a.clone()),
        )?)?
        .current
        .body,
        EventBody::GrantRecorded { active: false, .. }
    ));
    assert!(matches!(
        present(snapshot.grant(
            Actor::Agent(f.a.clone()),
            GrantKey::AgentCanCreate(f.a.clone()),
        )?)?
        .current
        .body,
        EventBody::GrantRecorded { active: true, .. }
    ));
    assert_eq!(
        current
            .control_target(child.clone())
            .err()
            .ok_or("revoked creator read admitted")?
            .code,
        StoreErrorCode::CreatorControlRefused
    );
    drop(current);
    let new_session = capture::session()?;
    assert_eq!(
        wait(client.submit(f.batch(
            admission.clone(),
            Some(request(&format!(
                "judge-nested-wave2_control_independent-244-{}",
                serial()
            ))?),
            vec![capture::prepared(&f, &new_session, &child)]
        )?)?)?
        .err()
        .ok_or("revoked creator session write admitted")?
        .code,
        StoreErrorCode::CreatorControlRefused
    );
    process.root_identity = RootIdentityState::Unpublished;
    assert_eq!(
        wait(client.submit(f.batch(
            admission,
            Some(request(&format!(
                "judge-nested-wave2_control_independent-256-{}",
                serial()
            ))?),
            vec![transition(
                &process,
                2,
                ProcessState::Starting,
                ProcessState::StopRequested,
                session_receipt.primary_event
            )?]
        )?)?)?
        .err()
        .ok_or("revoked creator process write admitted")?
        .code,
        StoreErrorCode::CreatorControlRefused
    );
    assert_eq!(head(&f, process.record.clone())?.revision.value.get(), 2);
    assert!(matches!(
        reader
            .snapshot(f.scoped(Visibility::Owner))?
            .session(new_session)?,
        Read::Absent { .. }
    ));
    assert!(matches!(
        reader
            .snapshot(f.self_scope(&child))?
            .control_target(child)?,
        Read::Present { .. }
    ));
    drop(snapshot);
    drop(reader);
    drop(wait(writer.drain(Duration::from_secs(2)))??);
    Ok(())
}

/// Protects: control inventory refuses overflow rather than silently omitting a live session, and excludes revoked preparations.
#[test]
fn control_inventory_is_complete_or_refuses() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let writer = host.start_writer(options(256)?, lease)?;
    let client = writer.client();
    let child = agent()?;
    wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!(
            "fixture-wave2_control_independent-281-{}",
            serial()
        ))?),
        vec![
            grant(&f.a, true, Expected::Absent),
            helper(&f, &child, Some(&f.a)),
        ],
    )?)?)??;
    let mut sessions: Vec<SessionId> = Vec::new();
    for _ in 0..17 {
        sessions.push(capture::session()?);
    }
    let bodies = sessions
        .iter()
        .map(|id| capture::prepared(&f, id, &child))
        .collect();
    wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!(
            "fixture-wave2_control_independent-297-{}",
            serial()
        ))?),
        bodies,
    )?)?)??;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    assert_eq!(
        reader
            .snapshot(f.self_scope(&f.a))?
            .control_target(child.clone())
            .err()
            .ok_or("oversized live session inventory truncated")?
            .code,
        StoreErrorCode::ReadIncomplete
    );
    wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!(
            "fixture-wave2_control_independent-308-{}",
            serial()
        ))?),
        vec![EventBody::SessionRevoked {
            session: sessions[0].clone(),
            expected: revision(1)?,
            reason: InputText::Inline("failed preparation revoked by independent fixture".into()),
        }],
    )?)?)??;
    let control = present(reader.snapshot(f.self_scope(&f.a))?.control_target(child)?)?;
    assert_eq!(control.sessions.len(), 16);
    assert!(control.sessions.iter().all(|entry| matches!(&entry.current.body, EventBody::SessionPrepared { session, .. } if session != &sessions[0])));
    drop(reader);
    drop(wait(writer.drain(Duration::from_secs(2)))??);
    Ok(())
}

/// Protects: a launch that fails after session preparation revokes that preparation; the revoked
/// never-activated preparation must not shadow an older activated-then-ended session for auto-resume,
/// while latest_session keeps reporting the any-state newest for stop/status.
#[test]
fn resume_selector_skips_revoked_preparation_that_never_activated() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let writer = host.start_writer(options(256)?, lease)?;
    let client = writer.client();
    let child = agent()?;
    wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!(
            "fixture-wave2_control_independent-575-{}",
            serial()
        ))?),
        vec![
            grant(&f.a, true, Expected::Absent),
            helper(&f, &child, Some(&f.a)),
            EventBody::ProfileSaved {
                agent: child.clone(),
                profile: Profile {
                    provider: Provider::Claude,
                    model: None,
                    permission: PermissionProfile::WorkspaceWrite,
                    named_profile: "workspace-write".into(),
                    effort: None,
                },
                expected: Expected::Absent,
            },
        ],
    )?)?)??;
    let admission = f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.a.clone()));
    let first = capture::session()?;
    wait(client.submit(f.batch(
        admission.clone(),
        Some(request(&format!(
            "fixture-wave2_control_independent-594-{}",
            serial()
        ))?),
        vec![capture::prepared(&f, &first, &child)],
    )?)?)??;
    wait(client.submit(f.batch(
        admission.clone(),
        Some(request(&format!(
            "fixture-wave2_control_independent-602-{}",
            serial()
        ))?),
        vec![capture::activated(&first)?],
    )?)?)??;
    wait(client.submit(f.batch(
        admission.clone(),
        Some(request(&format!(
            "fixture-wave2_control_independent-609-{}",
            serial()
        ))?),
        vec![EventBody::SessionEnded {
            session: first.clone(),
            expected: revision(2)?,
            reason: InputText::Inline("finished before the failed relaunch".into()),
            final_turn: None,
            final_cursor: None,
        }],
    )?)?)??;
    let second = capture::session()?;
    wait(client.submit(f.batch(
        admission.clone(),
        Some(request(&format!(
            "fixture-wave2_control_independent-626-{}",
            serial()
        ))?),
        vec![capture::prepared(&f, &second, &child)],
    )?)?)??;
    wait(client.submit(f.batch(
        admission.clone(),
        Some(request(&format!(
            "fixture-wave2_control_independent-633-{}",
            serial()
        ))?),
        vec![EventBody::SessionRevoked {
            session: second.clone(),
            expected: revision(1)?,
            reason: InputText::Inline("launch failed before first use".into()),
        }],
    )?)?)??;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let control = present(reader.snapshot(f.self_scope(&f.a))?.control_target(child)?)?;
    let latest = present(control.latest_session)?;
    assert!(
        matches!(&latest.current.body, EventBody::SessionRevoked { session, .. } if session == &second)
    );
    let resume = present(control.resume_session)?;
    assert!(
        matches!(&resume.current.body, EventBody::SessionEnded { session, .. } if session == &first)
    );
    drop(reader);
    drop(wait(writer.drain(Duration::from_secs(2)))??);
    Ok(())
}
