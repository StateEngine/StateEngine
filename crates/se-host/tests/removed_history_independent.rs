//! Public core history consumers over the actual retained protected store.
#![cfg(any(target_os = "linux", windows))]
use se_core::{
    commit::Cx,
    ops::{
        event::{EventOutput, EventRead},
        history::HistoryList,
    },
};
use se_store::*;
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
fn exact(
    read: &mut impl Snapshot,
    admission: &Admission,
    id: &se_types::EventId,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let event = se_core::ops::event::read(
        EventRead {
            event_id: id.to_string(),
        },
        &mut Cx { read, admission },
    )?;
    match event {
        EventOutput::Present(event) => Ok(serde_json::to_value(event)?),
        _ => Err("retained event is not present".into()),
    }
}
fn tombstone(
    f: &Fixture,
    d: &mut SqliteDirect,
    lease: &Lease,
    witness: se_types::EventId,
) -> Check {
    d.append(
        f.batch(
            f.owner_project(),
            None,
            vec![EventBody::ProjectRemoved {
                project: f.project.clone(),
                expected: revision(1)?,
                witnesses: vec![witness],
                preserved: vec!["all public event bodies retained".into()],
            }],
        )?,
        lease,
    )?;
    Ok(())
}
/// Protects: a tombstone's matching registration supplies the same project
/// label for exact and paged public history without changing its saved content.
#[test]
fn removed_project_keeps_exact_and_paged_message_history_readable() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let batch = f.send(
        Actor::Agent(f.a.clone()),
        Actor::Agent(f.a.clone()),
        message()?,
        "retained-history-marker",
        "history-message",
    )?;
    let id = batch.events[0].header.event.clone();
    d.append(batch, &*lease)?;
    let admission = f.owner_project();
    let mut before = d.snapshot(f.scoped(Visibility::Owner))?;
    let original = exact(&mut before, &admission, &id)?;
    assert!(original.to_string().contains("retained-history-marker"));
    before.close()?;
    tombstone(&f, &mut d, &lease, id.clone())?;
    let mut after = d.snapshot(f.scoped(Visibility::Owner))?;
    let retained = exact(&mut after, &admission, &id)?;
    for field in [
        "event_id",
        "kind",
        "project",
        "actor",
        "payload",
        "recorded_at",
        "writer",
    ] {
        assert_eq!(retained[field], original[field], "retained {field} changed");
    }
    let page = se_core::ops::history::list(
        HistoryList {
            session: None,
            kinds: vec!["message.sent".into()],
            since: None,
            limit: 100,
            cursor: None,
            owner_agent: None,
        },
        &mut Cx {
            read: &mut after,
            admission: &admission,
        },
    )?;
    assert!(page.page.window().complete());
    assert!(page.page.next().is_none());
    assert_eq!(page.page.items().len(), 1);
    let event = serde_json::to_value(&page.page.items()[0])?;
    assert_eq!(event["payload"], original["payload"]);
    assert_eq!(event["event_id"], original["event_id"]);
    after.close()?;
    d.close()?;
    drop(lease);
    Ok(())
}
/// Protects: the metadata fallback does not grant another agent's private
/// events, and a foreign project ID never turns into retained local history.
#[test]
fn removed_metadata_fallback_does_not_widen_event_scope_or_privacy() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let batch = f.send(
        Actor::Agent(f.a.clone()),
        Actor::Agent(f.a.clone()),
        message()?,
        "A-private-retained",
        "private-a",
    )?;
    let private = batch.events[0].header.event.clone();
    d.append(batch, &*lease)?;
    let own = f.send(
        Actor::Agent(f.b.clone()),
        Actor::Agent(f.b.clone()),
        message()?,
        "B-private-retained",
        "private-b",
    )?;
    let own_id = own.events[0].header.event.clone();
    d.append(own, &*lease)?;
    let foreign = se_types::ProjectId::from_parts(1_700_000_000_000 + serial(), [79; 10])?;
    let body = EventBody::ProjectRegistered {
        project: foreign.clone(),
        name: "Foreign".into(),
        roots: vec![],
        owner: f.owner.clone(),
        history_from: None,
        expected: Expected::Absent,
    };
    let foreign_batch = f.batch(
        f.admission(Scope::Project(foreign), Actor::Human(f.owner.clone())),
        None,
        vec![body],
    )?;
    let foreign_id = foreign_batch.events[0].header.event.clone();
    d.append(foreign_batch, &*lease)?;
    tombstone(&f, &mut d, &lease, own_id.clone())?;
    let mut read = d.snapshot(f.self_scope(&f.b))?;
    let admission = f.self_scope(&f.b).admission;
    assert!(
        exact(&mut read, &admission, &private).is_err(),
        "retained metadata exposed another agent's private message"
    );
    assert!(
        exact(&mut read, &admission, &foreign_id).is_err(),
        "retained metadata crossed project scope"
    );
    assert!(
        exact(&mut read, &admission, &own_id)?
            .to_string()
            .contains("B-private-retained")
    );
    read.close()?;
    d.close()?;
    drop(lease);
    Ok(())
}
