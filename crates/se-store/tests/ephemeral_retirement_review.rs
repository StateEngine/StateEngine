//! Reviewer checks of the writer's temporary-agent rules: only a temporary
//! agent retires, never while it still has live work, and a retired agent
//! takes no new session or mail. Typed store events stand in for native work;
//! nothing here claims a real provider process.
use se_store::*;
use se_types::{AgentId, LifecycleId, SessionId};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "support/capture_fixture.rs"]
#[allow(dead_code, reason = "only typed session helpers are used")]
mod capture;
#[path = "support/wave2_control_fixture.rs"]
#[allow(dead_code, reason = "only process and grant helpers are used")]
mod control;
#[path = "support/host_fixture.rs"]
#[allow(dead_code, reason = "only the host writer helpers are used")]
mod host_fixture;

type Boxed<T> = Result<T, Box<dyn std::error::Error>>;

/// The real host writer: process facts are only accepted from it.
struct Store {
    f: Fixture,
    writer: Option<SqliteWriter>,
    client: SqliteClient,
}

impl Store {
    fn new() -> Boxed<Self> {
        let f = Fixture::new()?;
        let (host, lease) = host_fixture::host(&f)?;
        let writer = host.start_writer(host_fixture::options(8)?, lease)?;
        let client = writer.client();
        Ok(Self {
            f,
            writer: Some(writer),
            client,
        })
    }
    fn submit(&self, batch: AtomicBatch) -> StoreResult<()> {
        let completion = self.client.submit(batch)?;
        host_fixture::wait(completion).map_err(boxed)?.map(|_| ())
    }
    fn write(&self, actor: Actor, bodies: Vec<EventBody<InputText>>) -> StoreResult<()> {
        let admission = self
            .f
            .admission(Scope::Project(self.f.project.clone()), actor);
        let batch = self
            .f
            .batch(
                admission,
                Some(request(&format!("review-{}", serial())).map_err(boxed)?),
                bodies,
            )
            .map_err(boxed)?;
        self.submit(batch)
    }
    fn finish(mut self) -> Check {
        if let Some(writer) = self.writer.take() {
            let drained = host_fixture::wait(writer.drain(std::time::Duration::from_secs(3)))??;
            drop(drained.host);
        }
        Ok(())
    }
    fn owner(&self) -> Actor {
        Actor::Human(self.f.owner.clone())
    }
    /// A temporary child of `f.a`, registered by the Owner.
    fn temporary(&self) -> Boxed<AgentId> {
        let child = agent()?;
        self.write(
            self.owner(),
            vec![EventBody::PrincipalRegistered {
                principal: Actor::Agent(child.clone()),
                kind: PrincipalKind::Agent,
                owner: self.f.owner.clone(),
                created_by: Some(Actor::Agent(self.f.a.clone())),
                name: format!("Helper {}", serial()),
                role: String::new(),
                ephemeral: Some(EphemeralSpec {
                    one_shot: false,
                    ttl_seconds: 3600,
                }),
                expected: Expected::Absent,
            }],
        )?;
        Ok(child)
    }
    fn live_session(&self, agent: &AgentId) -> Boxed<SessionId> {
        let id = capture::session()?;
        self.write(
            self.owner(),
            vec![
                capture::prepared(&self.f, &id, agent),
                capture::activated(&id)?,
            ],
        )?;
        Ok(id)
    }
    fn retire(&self, actor: Actor, agent: &AgentId, last: Option<SessionId>) -> StoreResult<()> {
        self.write(actor, vec![retired(agent, last)])
    }
}

fn boxed(error: Box<dyn std::error::Error>) -> Box<StoreError> {
    Box::new(StoreError {
        code: StoreErrorCode::EventInvalid,
        cause: error.to_string(),
        detail: StoreDetail::None,
        remedy: se_types::Remedy {
            text: "fixture setup failed".into(),
            command: None,
        },
        retry: se_types::Retry::Never,
    })
}

fn retired(agent: &AgentId, last: Option<SessionId>) -> EventBody<InputText> {
    EventBody::AgentRetired {
        agent: agent.clone(),
        reason: RetirementReason::Expired,
        final_session: last,
    }
}

fn ended(session: &SessionId, expected: u64) -> Boxed<EventBody<InputText>> {
    Ok(EventBody::SessionEnded {
        session: session.clone(),
        expected: revision(expected)?,
        reason: InputText::Inline("review session ended".into()),
        final_turn: None,
        final_cursor: None,
    })
}

fn refused(result: StoreResult<()>, code: StoreErrorCode, needle: &str, case: &str) -> Check {
    match result {
        Ok(()) => Err(format!("{case}: the writer accepted it").into()),
        Err(error) if error.code == code && error.cause.contains(needle) => Ok(()),
        Err(error) => {
            Err(format!("{case}: wrong refusal {:?}: {}", error.code, error.cause).into())
        }
    }
}

/// Protects: a saved seat never becomes permanently unusable through
/// retirement, whoever asks.
#[test]
fn a_saved_seat_cannot_be_retired() -> Check {
    let s = Store::new()?;
    let seat = s.f.b.clone();
    let owner = s.owner();
    refused(
        s.retire(owner, &seat, None),
        StoreErrorCode::InvalidTransition,
        "saved seats remain permanent",
        "owner retiring a saved seat",
    )?;
    s.finish()
}

/// Protects: retirement never strands live work. A prepared or active
/// session, or an unreleased process, refuses inside the writer transaction.
#[test]
fn live_work_refuses_retirement_in_the_writer() -> Check {
    let s = Store::new()?;
    let owner = s.owner();
    let busy = s.temporary()?;
    let session = s.live_session(&busy)?;
    refused(
        s.retire(owner.clone(), &busy, Some(session)),
        StoreErrorCode::InvalidTransition,
        "live sessions or unreleased processes",
        "active session",
    )?;

    let prepared = s.temporary()?;
    let id = capture::session()?;
    s.write(owner.clone(), vec![capture::prepared(&s.f, &id, &prepared)])?;
    refused(
        s.retire(owner.clone(), &prepared, Some(id)),
        StoreErrorCode::InvalidTransition,
        "live sessions or unreleased processes",
        "prepared session",
    )?;

    let running = s.temporary()?;
    let process = control::identity(&running)?;
    s.write(
        owner.clone(),
        vec![control::registration(&process, ProcessState::Starting)],
    )?;
    refused(
        s.retire(owner, &running, None),
        StoreErrorCode::InvalidTransition,
        "live sessions or unreleased processes",
        "unreleased process",
    )?;
    s.finish()
}

/// Protects: the child's own end-of-session batch can end its session and
/// retire it atomically, and then nothing reopens it.
#[test]
fn ending_and_retiring_in_one_batch_is_terminal() -> Check {
    let s = Store::new()?;
    let owner = s.owner();
    let child = s.temporary()?;
    let session = s.live_session(&child)?;
    s.write(
        owner.clone(),
        vec![ended(&session, 2)?, retired(&child, Some(session.clone()))],
    )?;
    refused(
        s.retire(owner.clone(), &child, Some(session)),
        StoreErrorCode::InvalidTransition,
        "already retired",
        "second retirement",
    )?;
    let next = capture::session()?;
    refused(
        s.write(owner.clone(), vec![capture::prepared(&s.f, &next, &child)]),
        StoreErrorCode::InvalidTransition,
        "retired",
        "new session for a retired agent",
    )?;
    let mail = s.f.send(
        owner,
        Actor::Agent(child.clone()),
        message()?,
        "late mail",
        &format!("late-{}", serial()),
    )?;
    let sent = s.submit(mail);
    refused(
        sent,
        StoreErrorCode::InvalidTransition,
        "retired",
        "mail to a retired agent",
    )?;
    let peer = s.f.send(
        Actor::Agent(s.f.a.clone()),
        Actor::Agent(child),
        message()?,
        "peer mail",
        &format!("peer-{}", serial()),
    )?;
    let sent = s.submit(peer);
    refused(
        sent,
        StoreErrorCode::InvalidTransition,
        "retired",
        "peer mail to a retired agent",
    )?;
    s.finish()
}

/// Protects: a creator retires its own temporary child only while it holds
/// the create grant; another agent never can.
#[test]
fn only_a_granted_creator_or_the_owner_retires() -> Check {
    let s = Store::new()?;
    let owner = s.owner();
    let child = s.temporary()?;
    refused(
        s.retire(Actor::Agent(s.f.b.clone()), &child, None),
        StoreErrorCode::CreatorControlRefused,
        "",
        "an unrelated agent",
    )?;
    refused(
        s.retire(Actor::Agent(s.f.a.clone()), &child, None),
        StoreErrorCode::CreatorControlRefused,
        "",
        "the creator without a grant",
    )?;
    let a = s.f.a.clone();
    s.write(owner, vec![control::grant(&a, true, Expected::Absent)])?;
    s.retire(Actor::Agent(a), &child, None)?;
    s.finish()
}
