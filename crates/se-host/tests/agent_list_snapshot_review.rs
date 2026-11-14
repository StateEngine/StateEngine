//! Saved-list consumers must retain the read pin and refresh independent facts.
#[path = "../../se-store/tests/support/capture_fixture.rs"]
#[allow(dead_code, reason = "only typed session preparation is needed")]
mod capture;
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
use se_core::{
    commit::Cx,
    ops::{AgentRow, AgentShow, agent_status, listing},
};
use se_store::*;
use se_types::{AgentId, Cursor};

fn profile(agent: &AgentId, model: &str, expected: Expected) -> EventBody<InputText> {
    EventBody::ProfileSaved {
        agent: agent.clone(),
        profile: Profile {
            provider: Provider::Claude,
            model: Some(model.into()),
            permission: PermissionProfile::WorkspaceWrite,
            harness: None,
            named_profile: format!("profile-{model}"),
            effort: None,
        },
        expected,
    }
}
fn seed(f: &Fixture, store: &mut SqliteDirect, lease: &Lease) -> Check {
    store.append(
        f.batch(
            f.owner_project(),
            Some(request("review-seed-profiles")?),
            vec![
                profile(&f.a, "first", Expected::Absent),
                profile(&f.b, "other", Expected::Absent),
            ],
        )?,
        lease,
    )?;
    Ok(())
}
fn list<R: Snapshot>(
    read: &mut R,
    admission: &Admission,
    limit: u16,
    cursor: Option<Cursor>,
) -> Result<listing::AgentPage, Box<dyn std::error::Error>> {
    Ok(listing::agents(
        listing::AgentList { limit, cursor },
        &mut Cx { read, admission },
    )?)
}
fn row(
    rows: &[AgentRow],
    agent: &AgentId,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::to_value(
        rows.iter()
            .find(|r| &r.id == agent)
            .ok_or("agent row absent")?,
    )?)
}
fn agrees_with_show<R: Snapshot>(read: &mut R, admission: &Admission, rows: &[AgentRow]) -> Check {
    for saved in rows {
        let shown = present(
            agent_status::show(
                AgentShow {
                    target_agent_id: Some(saved.id.clone()),
                },
                &mut Cx { read, admission },
            )?
            .agent,
        )?;
        assert_eq!(serde_json::to_value(saved)?, serde_json::to_value(shown)?);
    }
    Ok(())
}

#[test]
fn owner_pin_is_stable_and_new_snapshots_refresh_each_saved_fact() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    seed(&f, &mut store, &lease)?;
    let admission = f.owner_project();
    let mut pinned = store.snapshot(f.scoped(Visibility::Owner))?;
    let initial = list(&mut pinned, &admission, 20, None)?;
    assert_eq!(initial.page.items().len(), 2);
    let before = row(initial.page.items(), &f.a)?;
    assert_eq!(before["model"], "first");
    assert_eq!(before["unread"], 0);
    assert_eq!(before["session"]["state"], "never-launched");
    agrees_with_show(&mut pinned, &admission, initial.page.items())?;

    let session = capture::session()?;
    store.append(
        f.batch(
            admission.clone(),
            Some(request("review-refresh-row")?),
            vec![
                EventBody::PrincipalRenamed {
                    principal: Actor::Agent(f.a.clone()),
                    name: "Renamed".into(),
                    expected: revision(1)?,
                },
                profile(&f.a, "second", revision(1)?),
                capture::prepared(&f, &session, &f.a),
            ],
        )?,
        &*lease,
    )?;
    let mail = message()?;
    store.append(
        f.send(
            Actor::Agent(f.b.clone()),
            Actor::Agent(f.a.clone()),
            mail.clone(),
            "fresh unread evidence",
            "new-unread",
        )?,
        &*lease,
    )?;
    let same_pin = list(&mut pinned, &admission, 20, None)?;
    assert_eq!(row(same_pin.page.items(), &f.a)?, before);
    pinned.close()?;

    let mut fresh = store.snapshot(f.scoped(Visibility::Owner))?;
    let changed = list(&mut fresh, &admission, 20, None)?;
    let now = row(changed.page.items(), &f.a)?;
    assert_eq!(now["name"], "Renamed");
    assert_eq!(now["role"], "builder");
    assert_eq!(now["model"], "second");
    assert_eq!(now["profile"], "profile-second");
    assert_eq!(now["session"]["session_id"], session.as_str());
    assert_eq!(now["unread"], 1);
    assert_eq!(row(changed.page.items(), &f.b)?["unread"], 0);
    agrees_with_show(&mut fresh, &admission, changed.page.items())?;
    fresh.close()?;

    store.append(
        f.batch(
            f.self_scope(&f.a).admission,
            None,
            vec![EventBody::MessageRead {
                message: mail,
                recipient: Actor::Agent(f.a.clone()),
            }],
        )?,
        &*lease,
    )?;
    let next = capture::session()?;
    store.append(
        f.batch(
            admission.clone(),
            Some(request("review-refresh-session")?),
            vec![
                EventBody::SessionRevoked {
                    session,
                    expected: revision(1)?,
                    reason: InputText::Inline("fixture preparation replaced".into()),
                },
                capture::prepared(&f, &next, &f.a),
                profile(&f.a, "third", revision(2)?),
            ],
        )?,
        &*lease,
    )?;
    let mut newest = store.snapshot(f.scoped(Visibility::Owner))?;
    let changed = list(&mut newest, &admission, 20, None)?;
    let now = row(changed.page.items(), &f.a)?;
    assert_eq!(now["session"]["session_id"], next.as_str());
    assert_eq!(now["model"], "third");
    assert_eq!(now["unread"], 0);
    agrees_with_show(&mut newest, &admission, changed.page.items())?;
    newest.close()?;
    store.close()?;
    Ok(())
}

#[test]
fn bound_agent_keeps_self_control_and_refuses_foreign_inspection() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    seed(&f, &mut store, &lease)?;
    store.append(
        f.send(
            Actor::Agent(f.b.clone()),
            Actor::Agent(f.a.clone()),
            message()?,
            "own unread",
            "bound-unread",
        )?,
        &*lease,
    )?;
    let scope = f.self_scope(&f.a);
    let admission = scope.admission.clone();
    let mut read = store.snapshot(scope)?;
    let page = list(&mut read, &admission, 20, None)?;
    assert_eq!(page.page.items().len(), 1);
    let own = &page.page.items()[0];
    assert_eq!(own.id, f.a);
    assert_eq!(own.model.as_deref(), Some("first"));
    assert_eq!(own.unread, Some(1));
    agrees_with_show(&mut read, &admission, page.page.items())?;
    let error = agent_status::show(
        AgentShow {
            target_agent_id: Some(f.b.clone()),
        },
        &mut Cx {
            read: &mut read,
            admission: &admission,
        },
    )
    .err()
    .ok_or("foreign target exposed")?;
    assert!(matches!(
        error.body.detail(),
        se_types::Detail::OwnerRequired(_)
    ));
    read.close()?;
    store.close()?;
    Ok(())
}

#[test]
fn finite_owner_pages_keep_exact_rows_and_live_cursor_accounting() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    seed(&f, &mut store, &lease)?;
    let admission = f.owner_project();
    let mut read = store.snapshot(f.scoped(Visibility::Owner))?;
    let first = list(&mut read, &admission, 1, None)?;
    assert_eq!(first.consistency, "live-keyset");
    assert_eq!(first.page.items().len(), 1);
    let next = first
        .page
        .next()
        .cloned()
        .ok_or("first finite page lost continuation")?;
    let fields = first
        .page
        .window()
        .fields()
        .ok_or("missing finite fields")?;
    assert_eq!(fields.returned, 1);
    assert_eq!(
        fields.bytes,
        serde_json::to_vec(first.page.items())?.len() as u64
    );
    assert!(matches!(
        fields.omitted_after,
        se_types::Omission::Unknown { .. }
    ));
    let second = list(&mut read, &admission, 1, Some(next))?;
    assert_eq!(second.page.items().len(), 1);
    assert_ne!(first.page.items()[0].id, second.page.items()[0].id);
    assert!(second.page.next().is_none());
    agrees_with_show(&mut read, &admission, first.page.items())?;
    agrees_with_show(&mut read, &admission, second.page.items())?;
    read.close()?;
    store.close()?;
    Ok(())
}

#[test]
fn absent_profile_refuses_without_borrowing_another_agents_profile() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    store.append(
        f.batch(
            f.owner_project(),
            Some(request("review-missing-profile")?),
            vec![profile(&f.a, "only-first-agent", Expected::Absent)],
        )?,
        &*lease,
    )?;
    let admission = f.owner_project();
    let mut read = store.snapshot(f.scoped(Visibility::Owner))?;
    assert!(list(&mut read, &admission, 20, None).is_err());
    read.close()?;
    let scope = f.self_scope(&f.b);
    let admission = scope.admission.clone();
    let mut read = store.snapshot(scope)?;
    assert!(list(&mut read, &admission, 20, None).is_err());
    read.close()?;
    store.close()?;
    Ok(())
}
