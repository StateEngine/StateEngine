//! Agent-door send rate cap: one sender may not bury one recipient in
//! messages. Ten direct messages from one sender to one recipient inside
//! ten minutes is refused by name with the legal alternatives; the owner
//! door, self-notes and an exact retry of a committed send stay exempt.
//! Only direct messages count: floor work mail is not counted at all, and
//! its fan-out never counts against a recipient's direct pair.
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
        notification_event: event()?,
        notification_message: message()?,
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
            to: Some(to),
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
fn assert_cap_refusal(error: &SeError, from: &str, to: &str) -> Check {
    assert_eq!(error.class(), Class::Refused);
    assert!(
        format!("{error}").contains("has sent 10 messages"),
        "refusal must name the counted window: {error}"
    );
    match error.body.detail() {
        Detail::MessageRateOverCap(detail) => {
            assert_eq!(detail.from, from);
            assert_eq!(detail.to, to);
            assert_eq!(detail.count, 10);
            assert_eq!(detail.limit, 10);
            assert_eq!(detail.window_minutes, 10);
        }
        other => return Err(format!("expected message-rate-over-cap, got {other:?}").into()),
    }
    Ok(())
}
/// Protects: #473 — an agent pair over ten direct messages in ten minutes is refused by name; floor work mail is not counted and its fan-out never counts against a direct pair; the owner door, self-notes and an exact retry stay exempt.
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
        assert_cap_refusal(&refused, f.a.as_str(), f.b.as_str())?;
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
    // Floor work mail is not direct mail to a recipient: it is not
    // counted at all, so the eleventh broadcast inside the window passes.
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
    // Fan-out rows never count against the direct pair: the capped (a, b)
    // pair is still refused on exactly its ten direct sends, not the
    // floor deliveries toward b.
    {
        let mut s = make_sender(&f, &mut direct, &lease, actor.clone(), session.clone(), now);
        let refused = s
            .send(to.clone(), "cap-twelfth", None)
            .err()
            .ok_or("a send to the capped pair was accepted; the cap never tripped")?;
        assert_cap_refusal(&refused, f.a.as_str(), f.b.as_str())?;
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

/// Backdate the fixture pair's newest direct sends, exactly as a
/// backwards clock step would: the append stamps move while the send
/// order holds. The history trigger exists to protect real history from
/// the product, so the fixture lifts it for this simulated system step
/// and restores it unchanged; on schema 15 the stamp also lives on the
/// message row, so both rows move.
fn backdate_newest_stamps(f: &Fixture, stamp_us: i64, newest: usize) -> Check {
    let db = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    let project = f.project.canonical_bytes()?.ok_or("project bytes")?;
    let actor = f.a.canonical_bytes()?.ok_or("agent bytes")?;
    let mut rows = db.prepare(
        "SELECT seq FROM events
         WHERE project_id = ? AND actor_id = ? AND kind = 'message.sent'
         ORDER BY seq DESC",
    )?;
    let seqs: Vec<i64> = rows
        .query_map(rusqlite::params![&project, &actor], |r| r.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .take(newest)
        .collect();
    assert_eq!(
        seqs.len(),
        newest,
        "expected {newest} direct sends to backdate"
    );
    let list = seqs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    db.execute_batch("BEGIN IMMEDIATE")?;
    db.execute_batch("DROP TRIGGER events_no_update")?;
    db.execute(
        &format!("UPDATE events SET recorded_at_us = {stamp_us} WHERE seq IN ({list})"),
        rusqlite::params![],
    )?;
    let stamp_column: bool = db
        .prepare("SELECT EXISTS(SELECT 1 FROM pragma_table_info('messages') WHERE name='recorded_at_us')")?
        .query_row([], |r| r.get(0))?;
    if stamp_column {
        db.execute(
            &format!("UPDATE messages SET recorded_at_us = {stamp_us} WHERE sent_seq IN ({list})"),
            rusqlite::params![],
        )?;
    }
    db.execute_batch(
        "CREATE TRIGGER events_no_update BEFORE UPDATE ON events
         BEGIN SELECT RAISE(ABORT,'history-immutable'); END;",
    )?;
    db.execute_batch("COMMIT")?;
    Ok(())
}

/// Protects: #473 — the pair count is bounded by the window time, not by a fixed number of newest rows: after a backwards clock step, an in-window send must not slip under a row whose stamp is newer than rows sent after it.
#[test]
fn clock_step_cannot_hide_in_window_rows() -> Check {
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
            s.send(to.clone(), &format!("step-fill-{index}"), None)?;
        }
    }
    // The clock steps back past the window: the nine newest fills now carry
    // out-of-window stamps while the oldest fill stays inside it.
    backdate_newest_stamps(&f, now - 15 * 60 * 1_000_000, 9)?;
    {
        let mut s = make_sender(&f, &mut direct, &lease, actor, session, now);
        for index in 0..9 {
            s.send(to.clone(), &format!("step-after-{index}"), None)
                .map_err(|error| format!("post-step send {index} refused: {error}"))?;
        }
        let refused = s
            .send(to.clone(), "step-eleventh", None)
            .err()
            .ok_or("an in-window send slipped under the cap after a clock step")?;
        assert_cap_refusal(&refused, f.a.as_str(), f.b.as_str())?;
    }
    Ok(())
}
/// Protects: #473 — a home that a direct client opens before the schema-15 migration counts through the event stamp, and that count is bounded by the window time as well: a backwards clock step must not let an in-window send slip under the cap on the older home.
#[test]
fn clock_step_cannot_hide_rows_on_a_pre_migration_home() -> Check {
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
            s.send(to.clone(), &format!("pre-fill-{index}"), None)?;
        }
    }
    direct.close()?;
    // Recreate the pre-migration home: the stamp column and its pair index
    // are the migration's, so direct writes count through the event stamp.
    let db = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    db.execute_batch(
        "DROP INDEX messages_pair_time;
         DROP INDEX principals_retired;
         ALTER TABLE messages DROP COLUMN recorded_at_us;
         ALTER TABLE principals DROP COLUMN retired_seq;
         ALTER TABLE principals DROP COLUMN ephemeral_one_shot;
         ALTER TABLE principals DROP COLUMN ephemeral_ttl_seconds;
         PRAGMA user_version=14",
    )?;
    drop(db);
    // The clock steps back past the window: the nine newest fills now carry
    // out-of-window stamps while the oldest fill stays inside it.
    backdate_newest_stamps(&f, now - 15 * 60 * 1_000_000, 9)?;
    let mut direct = present(SqliteFactory::open_direct(&f.options, &*lease)?)?;
    {
        let mut s = make_sender(&f, &mut direct, &lease, actor, session, now);
        for index in 0..9 {
            s.send(to.clone(), &format!("pre-after-{index}"), None)
                .map_err(|error| format!("post-step send {index} refused: {error}"))?;
        }
        let refused = s
            .send(to.clone(), "pre-eleventh", None)
            .err()
            .ok_or("an in-window send slipped under the cap on a pre-migration home")?;
        assert_cap_refusal(&refused, f.a.as_str(), f.b.as_str())?;
    }
    Ok(())
}
