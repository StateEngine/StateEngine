//! Native store consumer for ordinary notification batches and durable delivery.
#![cfg(any(target_os = "linux", windows))]
use se_core::{
    commit::{Cx, OpStep},
    dispatch::{CallFacts, Kernel},
    ops::mail::*,
};
use se_store::*;
use se_types::{MessageId, Read};
use sha2::{Digest, Sha256};
use std::time::Duration;
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "../../se-store/tests/support/host_fixture.rs"]
mod native_host;
use native_host::*;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
#[allow(
    dead_code,
    reason = "The shared fixture also supports direct capture judges."
)]
mod capture_fixture;
use capture_fixture::{activated, capture, prepared, record, session, source};
type JudgeResult<T> = Result<T, Box<dyn std::error::Error>>;

fn kernel() -> JudgeResult<Kernel> {
    Ok(Kernel::new(CallFacts {
        event: event()?,
        message: message()?,
        agent: agent()?,
        profile_event: event()?,
        occurred_at_us: 1_700_000_000_000_000,
        door: Door::Cli,
    })?)
}

struct Case {
    f: Fixture,
    owner: SqliteWriter,
    reader: SqliteReader,
    scope: ReadScope,
    target: MailTarget,
    capture_source: RecordId,
}
impl Case {
    fn new() -> JudgeResult<Self> {
        let f = Fixture::new()?;
        let (host, lease) = host(&f)?;
        let owner = host.start_writer(options(64)?, lease)?;
        let sid = session()?;
        let capture_source = record()?;
        std::fs::write(f.home.join("transcript.jsonl"), b"ten bytes!")?;
        wait(owner.client().submit(f.batch(
            f.owner_project(),
            Some(request("load-session")?),
            vec![
                prepared(&f, &sid, &f.a),
                activated(&sid)?,
                source(capture_source, &sid, b"first", Expected::Absent),
            ],
        )?)?)??;
        let mut scope = f.self_scope(&f.a);
        scope.admission.session = Some(sid.clone());
        let target = MailTarget {
            project: f.project.clone(),
            agent: f.a.clone(),
            session: sid,
            epoch: epoch()?,
            generation: 1,
            fingerprint: [11; 32],
        };
        let reader = present(SqliteFactory::open_reader(&f.options)?)?;
        Ok(Self {
            f,
            owner,
            reader,
            scope,
            target,
            capture_source,
        })
    }

    fn send(&self, label: &str, quiet_value: bool) -> JudgeResult<MessageId> {
        let id = message()?;
        let mut batch = self.f.send(
            Actor::Human(self.f.owner.clone()),
            Actor::Agent(self.f.a.clone()),
            id.clone(),
            "fixture mail",
            label,
        )?;
        let EventBody::MessageSent { quiet, .. } = &mut batch.events[0].body else {
            return Err("fixture did not prepare an ordinary send".into());
        };
        *quiet = quiet_value;
        let receipt = wait(self.owner.client().submit(batch)?)??;
        if quiet_value {
            assert!(receipt.wakes.is_empty());
        }
        Ok(id)
    }

    fn reserve(&self, label: &str) -> JudgeResult<Read<Reservation>> {
        let k = kernel()?;
        let mut read = self.reader.snapshot(self.scope.clone())?;
        let step = reserve_coalesced(
            &k,
            &mut Cx {
                read: &mut read,
                admission: &self.scope.admission,
            },
            ReserveNotice {
                target: self.target.clone(),
                key: request(label)?.key,
                notice_id: record()?,
                effect_id: record()?,
            },
            false,
            Vec::new(),
        )?;
        read.close()?;
        match step {
            OpStep::Complete(result) => Ok(result),
            OpStep::Commit { batch, then } => {
                let receipt = wait(self.owner.client().submit(batch)?)??;
                let mut read = self.reader.snapshot(self.scope.clone())?;
                Ok(Read::Present {
                    value: committed(
                        &k,
                        &mut Cx {
                            read: &mut read,
                            admission: &self.scope.admission,
                        },
                        then,
                        receipt,
                    )?,
                })
            }
        }
    }

    fn deliver(&self, notice: &Reservation) -> Check {
        let text = "input accepted by the synthetic provider";
        let mut batch = capture(
            &self.f,
            &self.target.session,
            self.capture_source,
            b"first",
            0,
            1,
            "accepted-notice",
        )?;
        let EventBody::SessionTurn {
            role, text: input, ..
        } = &mut batch.events[0].body
        else {
            return Err("fixture did not prepare a captured turn".into());
        };
        *role = Role::User;
        *input = InputText::Inline(text.into());
        let event = wait(self.owner.client().submit(batch)?)??.primary_event;
        for message in &notice.ids {
            let mut read = self.reader.snapshot(self.scope.clone())?;
            let step = confirm_delivery(
                &kernel()?,
                &mut Cx {
                    read: &mut read,
                    admission: &self.scope.admission,
                },
                InputAccepted {
                    target: self.target.clone(),
                    effect: notice.effect_id,
                    message: message.clone(),
                    evidence: event.clone(),
                    accepted_text_sha256: Sha256::digest(text.as_bytes()).into(),
                    key: request(&format!("confirm-{message}"))?.key,
                },
            )?;
            read.close()?;
            let OpStep::Commit { batch, .. } = step else {
                return Err("delivery was not planned".into());
            };
            wait(self.owner.client().submit(batch)?)??;
            let mut read = self.reader.snapshot(self.scope.clone())?;
            let row = present(read.message(message.clone())?)?;
            assert!(row.delivered.is_some() && row.read.is_none() && row.dismissed.is_none());
            read.close()?;
        }
        Ok(())
    }

    fn finish(self) -> Check {
        drop(wait(self.owner.drain(Duration::from_secs(3)))??);
        Ok(())
    }
}

#[test]
fn quiet_only_stays_pending_and_full_batch_prefers_nonquiet_ids() -> Check {
    let case = Case::new()?;
    let quiet = case.send("quiet-first", true)?;
    assert!(matches!(case.reserve("quiet-only")?, Read::Absent { .. }));
    let mut nonquiet = Vec::new();
    for index in 0..33 {
        nonquiet.push(case.send(&format!("ordinary-{index}"), false)?);
    }
    let batch = present(case.reserve("ordinary-batch")?)?;
    let mut read = case.reader.snapshot(case.scope.clone())?;
    let quiet = present(read.message(quiet)?)?;
    assert!(quiet.read.is_none() && quiet.delivered.is_none());
    read.close()?;
    case.finish()?;
    assert_eq!(batch.ids, nonquiet[..32]);
    assert!(batch.more_pending);
    Ok(())
}

#[test]
fn ordinary_wake_does_not_repeat_delivered_unread_mail() -> Check {
    let case = Case::new()?;
    let first = case.send("first", false)?;
    let first_notice = present(case.reserve("first-notice")?)?;
    assert_eq!(first_notice.ids, [first.clone()]);
    assert!(!first_notice.more_pending);
    case.deliver(&first_notice)?;
    let fresh = case.send("fresh", false)?;
    let later_notice = present(case.reserve("fresh-notice")?)?;
    case.finish()?;
    assert_eq!(
        later_notice.ids,
        [fresh],
        "ordinary wake repeated an already delivered unread message"
    );
    Ok(())
}

#[test]
fn durable_backlog_does_not_strand_quiet_remainder_after_planner_restarts() -> Check {
    let case = Case::new()?;
    let quiet = case.send("quiet-backlog", true)?;
    for index in 0..32 {
        case.send(&format!("trigger-{index}"), false)?;
    }
    let batch = present(case.reserve("triggered-batch")?)?;
    assert_eq!(batch.ids.len(), 32);
    assert!(!batch.ids.contains(&quiet));
    assert!(batch.more_pending);
    case.deliver(&batch)?;
    // Recreate the planner with the committed store and an empty in-memory queue.
    let recovered = case.reserve("after-planner-restart")?;
    case.finish()?;
    let Read::Present { value } = recovered else {
        return Err("committed batch left its quiet remainder stranded on recovery".into());
    };
    assert_eq!(value.ids, [quiet]);
    Ok(())
}
