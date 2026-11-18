//! Shared scope and thread membership round-trip through their real events.
//!
//! The subject is the transition table: each test drives the store through its
//! public batch API and reads the event back, because a write arm without a read
//! arm used to roll the commit back as unreadable.

use se_store::*;
use se_store_contract::{SharedScopePhase, ThreadEnd};
use se_types::LifecycleId;

#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "support/host_fixture.rs"]
mod native_host;
use native_host::*;

type Check = Result<(), Box<dyn std::error::Error>>;

/// Read one event back through the public reader.
///
/// The commit receipt carries only event ids, so this is also the assertion that
/// the event's own bytes decode: a write arm with no read arm fails here.
fn event_back(
    f: &Fixture,
    id: &se_types::EventId,
) -> Result<EventBody<StoredText>, Box<dyn std::error::Error>> {
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut snapshot = reader.snapshot(f.scoped(Visibility::Owner))?;
    let stored = present(snapshot.event(id.clone())?)?;
    Ok(stored.body)
}

fn serialized() -> LifecycleId {
    LifecycleId::from_parts(1_700_000_000_000 + serial(), [7; 10]).expect("lifecycle id")
}

fn scope_changed(
    scope: &LifecycleId,
    server: &LifecycleId,
    phase: SharedScopePhase,
    from: Option<SharedScopePhase>,
    expected: Expected,
) -> EventBody<InputText> {
    EventBody::SharedScopeChanged {
        scope: scope.clone(),
        login: "/home/fixture/.codex".into(),
        server_process: server.clone(),
        phase,
        from,
        expected,
    }
}

fn attached(
    scope: &LifecycleId,
    session: &se_types::SessionId,
    thread: &str,
    expected: Expected,
) -> EventBody<InputText> {
    EventBody::ThreadAttached {
        scope: scope.clone(),
        session: session.clone(),
        thread: thread.into(),
        expected,
    }
}

fn detached(
    scope: &LifecycleId,
    session: &se_types::SessionId,
    end: ThreadEnd,
    reason: &str,
    expected: Expected,
) -> EventBody<InputText> {
    EventBody::ThreadDetached {
        scope: scope.clone(),
        session: session.clone(),
        end,
        reason: reason.into(),
        expected,
    }
}

fn submit(
    writer: &mut SqliteWriter,
    f: &Fixture,
    body: EventBody<InputText>,
) -> Result<CommitReceipt, Box<dyn std::error::Error>> {
    let client = writer.client();
    Ok(wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!("shared-scope-{}", serial()))?),
        vec![body],
    )?)?)??)
}

/// A scope registers, serves, and stops, and each event reads back.
#[test]
fn scope_round_trips_registration_serving_and_stop() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let mut writer = host.start_writer(options(256)?, lease.clone())?;
    let scope = serialized();

    // A server process must exist before a scope may name it.
    let server = register_server(&f, &mut writer)?;
    let first = submit(
        &mut writer,
        &f,
        scope_changed(
            &scope,
            &server,
            SharedScopePhase::Starting,
            None,
            Expected::Absent,
        ),
    )?;
    let EventBody::SharedScopeChanged {
        phase,
        from,
        expected,
        ..
    } = event_back(&f, &first.primary_event)?
    else {
        return Err("scope registration lost its kind".into());
    };
    assert_eq!(phase, SharedScopePhase::Starting);
    assert_eq!(from, None);
    assert_eq!(expected, Expected::Absent);

    let live = revision(2)?;
    let second = submit(
        &mut writer,
        &f,
        scope_changed(
            &scope,
            &server,
            SharedScopePhase::Live,
            Some(SharedScopePhase::Starting),
            live,
        ),
    )?;
    let EventBody::SharedScopeChanged { phase, .. } = event_back(&f, &second.primary_event)? else {
        return Err("scope update lost its kind".into());
    };
    assert_eq!(phase, SharedScopePhase::Live);

    let stopped = submit(
        &mut writer,
        &f,
        scope_changed(
            &scope,
            &server,
            SharedScopePhase::Stopped,
            Some(SharedScopePhase::Live),
            revision(3)?,
        ),
    )?;
    let EventBody::SharedScopeChanged { phase, .. } = event_back(&f, &stopped.primary_event)?
    else {
        return Err("scope stop lost its kind".into());
    };
    assert_eq!(phase, SharedScopePhase::Stopped);
    Ok(())
}

/// A live scope accepts a thread, and the detach carries its reason.
#[test]
fn thread_attach_and_detach_round_trip_with_its_reason() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let mut writer = host.start_writer(options(256)?, lease.clone())?;
    let scope = serialized();
    let server = register_server(&f, &mut writer)?;
    let (agent, session) = register_agent_session(&f, &mut writer)?;
    let _ = agent;
    submit(
        &mut writer,
        &f,
        scope_changed(
            &scope,
            &server,
            SharedScopePhase::Live,
            None,
            Expected::Absent,
        ),
    )?;

    let attach = submit(
        &mut writer,
        &f,
        attached(&scope, &session, "th_01", revision(2)?),
    )?;
    let EventBody::ThreadAttached { thread, .. } = event_back(&f, &attach.primary_event)? else {
        return Err("attach lost its kind".into());
    };
    assert_eq!(thread, "th_01");

    let detach = submit(
        &mut writer,
        &f,
        detached(
            &scope,
            &session,
            ThreadEnd::Stopped,
            "the agent was stopped and its thread archived",
            revision(3)?,
        ),
    )?;
    let EventBody::ThreadDetached { end, reason, .. } = event_back(&f, &detach.primary_event)?
    else {
        return Err("detach lost its kind".into());
    };
    assert_eq!(end, ThreadEnd::Stopped);
    assert_eq!(reason, "the agent was stopped and its thread archived");
    Ok(())
}

/// A stale scope revision is refused, so two writers cannot both win.
#[test]
fn stale_scope_revision_is_refused() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let mut writer = host.start_writer(options(256)?, lease.clone())?;
    let scope = serialized();
    let server = register_server(&f, &mut writer)?;
    submit(
        &mut writer,
        &f,
        scope_changed(
            &scope,
            &server,
            SharedScopePhase::Live,
            None,
            Expected::Absent,
        ),
    )?;
    let client = writer.client();
    let refused = client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!("shared-scope-{}", serial()))?),
        vec![scope_changed(
            &scope,
            &server,
            SharedScopePhase::Stopped,
            Some(SharedScopePhase::Live),
            revision(2)?,
        )],
    )?);
    assert!(
        refused.is_err() || wait(refused?)?.is_err(),
        "a stale scope revision must be refused"
    );
    Ok(())
}

/// A live scope with an open membership cannot be stopped.
#[test]
fn a_live_scope_with_an_open_agent_is_not_stopped() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let mut writer = host.start_writer(options(256)?, lease.clone())?;
    let scope = serialized();
    let server = register_server(&f, &mut writer)?;
    let (_, session) = register_agent_session(&f, &mut writer)?;
    submit(
        &mut writer,
        &f,
        scope_changed(
            &scope,
            &server,
            SharedScopePhase::Live,
            None,
            Expected::Absent,
        ),
    )?;
    submit(
        &mut writer,
        &f,
        attached(&scope, &session, "th_02", revision(2)?),
    )?;
    let client = writer.client();
    let refused = client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!("shared-scope-{}", serial()))?),
        vec![scope_changed(
            &scope,
            &server,
            SharedScopePhase::Stopped,
            Some(SharedScopePhase::Live),
            revision(3)?,
        )],
    )?);
    assert!(
        refused.is_err() || wait(refused?)?.is_err(),
        "a scope with an attached agent must not report stopped"
    );
    Ok(())
}

fn register_server(
    f: &Fixture,
    writer: &mut SqliteWriter,
) -> Result<LifecycleId, Box<dyn std::error::Error>> {
    let id = serialized();
    let admission = f.owner_project();
    let client = writer.client();
    wait(client.submit(f.batch(
        admission,
        Some(request(&format!("shared-server-{}", serial()))?),
        vec![EventBody::ProcessRegistered {
            identity: Box::new(ProcessIdentityRecord {
                record: id.clone(),
                principal: Actor::Host,
                session: None,
                root_identity: RootIdentityState::NoChildCreated,
                instance: RecordedIdentity::Absent {
                    reason: "host scope fixture has no native child".into(),
                },
                custody: NativeCustody {
                    format_version: 1,
                    record: b"shared scope fixture".to_vec(),
                },
                containment: ContainmentFact::NotLaunched,
            }),
            initial: ProcessState::Starting,
        }],
    )?)?)??;
    Ok(id)
}

fn register_agent_session(
    f: &Fixture,
    writer: &mut SqliteWriter,
) -> Result<(se_types::AgentId, se_types::SessionId), Box<dyn std::error::Error>> {
    let agent = f.a.clone();
    let session = se_types::SessionId::from_parts(1_700_000_000_001 + serial(), [3; 10])?;
    let client = writer.client();
    wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!("shared-session-{}", serial()))?),
        vec![EventBody::SessionPrepared {
            session: session.clone(),
            agent: agent.clone(),
            provider: Provider::Codex,
            surface: Some(SessionSurface::Headless),
            native_ref: "shared scope fixture".into(),
            consent: Consent::Capture,
            generation: 1,
            expected: Expected::Absent,
        }],
    )?)?)??;
    Ok((agent, session))
}
