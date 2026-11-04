//! Public native store consumers; no installed account or provider is used.
#![cfg(target_os = "linux")]
use se_store::*;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
mod capture;
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
#[allow(
    dead_code,
    reason = "Shared native host helpers include startup used by other consumers."
)]
#[path = "../../se-store/tests/support/host_fixture.rs"]
mod native;
use fixture::*;
use native::wait;
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead, BufReader, Cursor, Write},
    num::NonZeroU32,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};
struct Port {
    lease: Arc<Lease>,
    files: se_host::state_files::Files,
}
impl RuntimeLease for Port {
    fn identity(&self) -> StoreResult<LeaseIdentity> {
        self.lease.identity()
    }
    fn files(&self) -> &dyn StateFiles {
        &self.files
    }
}
fn open_host(f: &Fixture) -> Result<(SqliteHost, Arc<Port>), Box<dyn std::error::Error>> {
    let lease = Lease::acquire(
        &f.options.state_directory,
        LeaseMode::Host,
        Some(f.store.clone()),
    )?;
    let port = Arc::new(Port {
        lease,
        files: se_host::state_files::Files::open_with_policy(
            &f.options.state_directory,
            se_host::state_files::FilePolicy::Host,
        )?,
    });
    Ok((
        present(SqliteFactory::open_host(&f.options, &*port)?)?,
        port,
    ))
}
fn pair(
    f: &Fixture,
    session: &se_types::SessionId,
    expected: u64,
) -> Result<FirstBinding, Box<dyn std::error::Error>> {
    Ok(FirstBinding {
        owner: f.batch(
            f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
            Some(request("judge-owner")?),
            vec![EventBody::RuntimeOwnerEstablished {
                epoch: native::epoch()?,
                generation: se_types::Generation::new(1)?,
                expected_owner_generation: None,
                expected: Expected::Absent,
                witnesses: vec![],
                recovered: None,
            }],
        )?,
        session: f.batch(
            f.owner_project(),
            Some(request("judge-session")?),
            vec![
                EventBody::SessionPrepared {
                    session: session.clone(),
                    agent: f.a.clone(),
                    provider: Provider::Claude,
                    surface: Some(SessionSurface::SeCode),
                    native_ref: "original-native-binding".into(),
                    consent: Consent::Capture,
                    generation: 1,
                    expected: Expected::Absent,
                },
                EventBody::SessionActivated {
                    session: session.clone(),
                    expected: revision(expected)?,
                    incumbent: None,
                    process: None,
                    containment: ContainmentFact::NotLaunched,
                    witnesses: vec![],
                },
            ],
        )?,
    })
}
fn outside(f: &Fixture, expected: (u64, u64), unlocked: bool) -> Check {
    let out = Command::new("python3").args(["-c", "import sqlite3,sys,json,fcntl\nc=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True)\nc.execute('begin')\nr=[c.execute('select count(*) from runtime_owner').fetchone()[0],c.execute('select count(*) from sessions').fetchone()[0]]\nc.close()\nif sys.argv[2]=='free':\n f=open(sys.argv[3],'r+b');fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\nprint(json.dumps(r))"])
        .arg(f.options.state_directory.join("state.db")).arg(if unlocked {"free"} else {"held"}).arg(f.options.state_directory.join("runtime.lock")).output()?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let read: Vec<u64> = serde_json::from_slice(&out.stdout)?;
    assert_eq!(read, vec![expected.0, expected.1]);
    Ok(())
}
#[test]
fn rejected_first_binding_leaves_no_owner_and_reopened_retry_keeps_both_receipts() -> Check {
    let f = Fixture::new()?;
    let (direct, lease) = f.direct()?;
    direct.close()?;
    drop(lease);
    let (mut host, port) = open_host(&f)?;
    let session = capture::session()?;
    assert_eq!(
        host.record_first_binding(pair(&f, &session, 99)?, &*port)
            .err()
            .ok_or("bad activation accepted")?
            .code,
        StoreErrorCode::RevisionConflict
    );
    outside(&f, (0, 0), false)?;
    let committed = host.record_first_binding(pair(&f, &session, 1)?, &*port)?;
    assert_eq!(committed.owner.durability, CommitDurability::Full);
    assert_eq!(committed.session.durability, CommitDurability::Full);
    outside(&f, (1, 1), false)?;
    drop(host);
    drop(port);
    outside(&f, (1, 1), true)?;
    let (mut reopened, port) = open_host(&f)?;
    let new_output = capture::session()?;
    let replay = reopened.record_first_binding(pair(&f, &new_output, 99)?, &*port)?;
    same_receipt(&committed.owner, &replay.owner);
    same_receipt(&committed.session, &replay.session);
    assert_eq!(replay.owner.state, CommitState::Replayed);
    assert_eq!(replay.session.state, CommitState::Replayed);
    let mut changed = pair(&f, &new_output, 1)?;
    changed
        .session
        .request
        .as_mut()
        .ok_or("session key absent")?
        .intent
        .sha256 = [77; 32];
    assert_eq!(
        reopened
            .record_first_binding(changed, &*port)
            .err()
            .ok_or("changed session intent replayed")?
            .code,
        StoreErrorCode::IdempotencyKeyReused
    );
    drop(reopened);
    drop(port);
    outside(&f, (1, 1), true)?;
    Ok(())
}
#[test]
fn two_staged_turns_fit_the_resident_queue_but_split_materialized_groups() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let session = capture::session()?;
    let source = capture::record()?;
    capture::active(&f, &mut direct, &lease, &session, source)?;
    direct.close()?;
    drop(lease);
    let (mut host, port) = open_host(&f)?;
    host.record_runtime_ownership(pair(&f, &session, 1)?.owner, &*port)?;
    let mut options = native::options(8)?;
    options.resident_bytes = NonZeroU32::new(16384).ok_or("resident")?;
    options.group_bytes = NonZeroU32::new(1048576).ok_or("group")?;
    let mut owner = host.start_writer(options, port.clone())?;
    let client = owner.client();
    let bodies = ["a".repeat(700000), "🦀".repeat(175000)];
    std::fs::write(f.home.join("transcript.jsonl"), bodies.concat())?;
    let mut batches = Vec::new();
    let mut turns = Vec::new();
    for (i, body) in bodies.iter().enumerate() {
        let staged =
            client.stage_text(&mut Cursor::new(body.as_bytes()), body.len() as u64, &*port)?;
        assert_eq!(staged.byte_length(), 700000);
        let mut batch = capture::capture(
            &f,
            &session,
            source,
            b"first",
            i as u64 * 700000,
            i as u64 + 1,
            &format!("split-{i}"),
        )?;
        if let EventBody::SessionTurn {
            text,
            turn,
            evidence,
            ..
        } = &mut batch.events[0].body
        {
            *text = InputText::Staged(staged);
            evidence.length = 700000;
            evidence.sha256 = Some(Sha256::digest(body.as_bytes()).into());
            turns.push(*turn);
        } else {
            return Err("turn body missing".into());
        }
        if let EventBody::CaptureProgress { new_offset, .. } = &mut batch.events[1].body {
            *new_offset = (i as u64 + 1) * 700000;
        }
        batches.push(batch);
    }
    assert_eq!(
        std::fs::read_dir(f.options.state_directory.join("staging"))?.count(),
        0
    );
    let mut blocker = Command::new("python3").args(["-u", "-c", "import sqlite3,sys\nc=sqlite3.connect(sys.argv[1]);c.execute('begin immediate');print('locked',flush=True);sys.stdin.readline();c.rollback();c.close()"])
        .arg(f.options.state_directory.join("state.db")).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
    let mut ready = String::new();
    BufReader::new(blocker.stdout.take().ok_or("blocker stdout")?).read_line(&mut ready)?;
    assert_eq!(ready.trim(), "locked");
    let gate = client.submit(f.working("gate", Expected::Absent, "judge-gate")?)?;
    let barrier = owner.flush(Duration::from_secs(5))?;
    let first = client.submit(batches.remove(0))?;
    let second = client.submit(batches.remove(0))?;
    blocker
        .stdin
        .take()
        .ok_or("blocker stdin")?
        .write_all(b"release\n")?;
    assert!(blocker.wait()?.success());
    wait(gate)??;
    wait(barrier)??;
    for result in [wait(first)??, wait(second)??] {
        assert_eq!(
            result
                .write_timings
                .as_ref()
                .ok_or("timing absent")?
                .group_requests,
            1
        );
        assert_eq!(result.durability, CommitDurability::Normal);
    }
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut read = reader.snapshot(f.self_scope(&f.a))?;
    for (turn, expected) in turns.into_iter().zip(bodies) {
        match present(read.turn(turn)?)?.body {
            EventBody::SessionTurn {
                text: StoredText::Present(actual),
                ..
            } => assert_eq!(actual, expected),
            _ => return Err("stored staged body missing".into()),
        }
    }
    read.close()?;
    drop(wait(owner.drain(Duration::from_secs(5)))??);
    drop(client);
    drop(port);
    assert_eq!(
        std::fs::read_dir(f.options.state_directory.join("staging"))?.count(),
        0
    );
    outside(&f, (1, 1), true)?;
    Ok(())
}
