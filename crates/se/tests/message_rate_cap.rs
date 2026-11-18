//! Agent-door send rate cap: one sender may not bury one recipient in
//! messages. Ten messages per pair inside ten minutes is refused by name with
//! the legal alternatives; the owner door, self-notes, floor work mail and an
//! exact retry of a committed send stay exempt.
use se_core::commit::{CoreOps, Cx, OpStep};
use se_core::dispatch::{CallFacts, Kernel};
use se_core::ops::MessageSend;
use se_core::store_error::store_error;
use se_store::*;
use se_types::{
    Class, Detail, IdempotencyKey, Result, SeError, SessionId, WorkAction, WorkAddressing,
};
use std::{
    error::Error,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
type Boxed<T> = std::result::Result<T, Box<dyn Error>>;
fn now_us() -> Boxed<i64> {
    let micros = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    Ok(i64::try_from(micros)?)
}
fn facts(occurred_at_us: i64) -> Boxed<CallFacts> {
    Ok(CallFacts {
        event: event()?,
        message: message()?,
        agent: agent()?,
        profile_event: event()?,
        occurred_at_us,
        door: Door::Mcp,
    })
}
fn scope_for(f: &Fixture, actor: &Actor) -> ReadScope {
    let visibility = match actor {
        Actor::Agent(agent) => Visibility::SelfOnly(agent.clone()),
        _ => Visibility::Owner,
    };
    ReadScope {
        admission: f.admission(Scope::Project(f.project.clone()), actor.clone()),
        visibility,
    }
}
struct Sender<'a> {
    f: &'a Fixture,
    direct: &'a mut SqliteDirect,
    lease: &'a Arc<Lease>,
    occurred_at_us: i64,
    actor: Actor,
    session: Option<SessionId>,
}
impl Sender<'_> {
    fn send(&mut self, to: String, key: &str, work: Option<WorkAddressing>) -> Result<()> {
        let input = MessageSend {
            to,
            body: "rate cap probe".into(),
            quiet: false,
            kind: Default::default(),
            refs: vec![],
            reply_to: None,
            supersedes: None,
            work,
            idempotency_key: IdempotencyKey::new(key)?,
        };
        let admission = Admission {
            scope: Scope::Project(self.f.project.clone()),
            actor: self.actor.clone(),
            session: self.session.clone(),
            generation: 1,
        };
        let mut snapshot = self
            .direct
            .snapshot(scope_for(self.f, &self.actor))
            .map_err(|e| store_error(&e))?;
        let cx = &mut Cx {
            read: &mut snapshot,
            admission: &admission,
        };
        let facts = facts(self.occurred_at_us)
            .map_err(|error| SeError::invalid("test facts", &error.to_string()))?;
        let step = Kernel::new(facts)?.message_send(input, cx)?;
        snapshot.close().map_err(|e| store_error(&e))?;
        if let OpStep::Commit { batch, .. } = step {
            self.direct
                .append(batch, &**self.lease)
                .map_err(|e| store_error(&e))?;
        }
        Ok(())
    }
}
fn make_sender<'a>(
    f: &'a Fixture,
    direct: &'a mut SqliteDirect,
    lease: &'a Arc<Lease>,
    actor: Actor,
    session: Option<SessionId>,
    occurred_at_us: i64,
) -> Sender<'a> {
    Sender {
        f,
        direct,
        lease,
        occurred_at_us,
        actor,
        session,
    }
}
fn floor_work(f: &Fixture) -> WorkAddressing {
    WorkAddressing {
        action: WorkAction::Notify,
        addressees: vec![f.b.clone()],
    }
}
fn eleven_ok(sender: &mut Sender, prefix: &str, to: String) -> Boxed<()> {
    for index in 0..11 {
        sender
            .send(to.clone(), &format!("{prefix}-{index}"), None)
            .map_err(|error| format!("{prefix} send {index} refused: {error}"))?;
    }
    Ok(())
}
fn assert_cap_refusal(error: &SeError, f: &Fixture) -> Check {
    assert_eq!(error.class(), Class::Refused);
    assert!(
        format!("{error}").contains("has sent 10 messages"),
        "refusal must name the counted window: {error}"
    );
    match error.body.detail() {
        Detail::MessageRateOverCap(detail) => {
            assert_eq!(detail.from, f.a.as_str());
            assert_eq!(detail.to, f.b.as_str());
            assert_eq!(detail.count, 10);
            assert_eq!(detail.limit, 10);
            assert_eq!(detail.window_minutes, 10);
        }
        other => return Err(format!("expected message-rate-over-cap, got {other:?}").into()),
    }
    Ok(())
}
/// Protects: #473 — an agent pair over ten messages in ten minutes is refused by name; the owner door, self-notes, floor work mail and an exact retry stay exempt.
#[test]
fn capped_pair_refused_by_name_and_exemptions_hold() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let actor = Actor::Agent(f.a.clone());
    let session = Some(SessionId::from_parts(
        1_700_000_000_000 + serial(),
        [9; 10],
    )?);
    let now = now_us()?;
    let to = f.b.as_str().to_owned();
    {
        let mut s = make_sender(&f, &mut direct, &lease, actor.clone(), session.clone(), now);
        for index in 0..10 {
            s.send(to.clone(), &format!("cap-fill-{index}"), None)?;
        }
        let refused = s
            .send(to.clone(), "cap-eleventh", None)
            .err()
            .ok_or("the eleventh send was accepted; the cap never tripped")?;
        assert_cap_refusal(&refused, &f)?;
    }
    // The owner door is never capped, even against the same recipient.
    {
        let mut s = make_sender(
            &f,
            &mut direct,
            &lease,
            Actor::Human(f.owner.clone()),
            None,
            now,
        );
        eleven_ok(&mut s, "owner", to.clone())?;
    }
    // A note to yourself is never capped.
    {
        let mut s = make_sender(&f, &mut direct, &lease, actor.clone(), session.clone(), now);
        eleven_ok(&mut s, "self", f.a.as_str().to_owned())?;
    }
    // Floor work mail is one fan-out act; the pair cap does not count it.
    {
        let mut s = make_sender(&f, &mut direct, &lease, actor.clone(), session.clone(), now);
        for index in 0..11 {
            s.send(
                "floor".into(),
                &format!("floor-{index}"),
                Some(floor_work(&f)),
            )
            .map_err(|error| format!("floor work mail {index} refused: {error}"))?;
        }
    }
    // Once the window rolls past the ten filled sends, the pair may write again.
    {
        let mut s = make_sender(
            &f,
            &mut direct,
            &lease,
            actor.clone(),
            session.clone(),
            now + 11 * 60 * 1_000_000,
        );
        s.send(to.clone(), "after-window", None)?;
    }
    // An exact retry of a committed send replays while the pair is still capped;
    // it never re-counts.
    {
        let mut s = make_sender(&f, &mut direct, &lease, actor.clone(), session, now);
        s.send(to, "cap-fill-0", None)?;
    }
    Ok(())
}
