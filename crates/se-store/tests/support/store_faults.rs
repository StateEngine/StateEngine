use super::*;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
#[allow(
    dead_code,
    reason = "Native fault tracing needs a longer completion bound than the shared fixture."
)]
#[path = "host_fixture.rs"]
mod native_host;
use native_host::{host, options};
fn wait<F: std::future::Future>(future: F) -> Result<F::Output, Box<dyn std::error::Error>> {
    use std::{
        sync::Arc,
        task::{Context, Poll, Wake, Waker},
    };
    struct Signal(std::thread::Thread);
    impl Wake for Signal {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Signal(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return Ok(value),
            Poll::Pending => std::thread::park_timeout(
                until
                    .checked_duration_since(Instant::now())
                    .ok_or("traced native writer completion timed out")?,
            ),
        }
    }
}
fn ready_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(PathBuf::from(
        std::env::var_os("SE_SQLITE_FAULT_ROOT").ok_or("native fault root absent")?,
    ))
}
fn wait_path(path: &std::path::Path) -> Check {
    let until = Instant::now() + Duration::from_secs(30);
    while !path.try_exists()? {
        if Instant::now() >= until {
            return Err("native fault controller did not release fixture".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}
fn outcome(value: StoreResult<CommitReceipt>) -> Value {
    match value {
        Ok(receipt) => {
            json!({"code":"Committed","event":receipt.primary_event.as_str(),"event_hex":receipt.primary_event.as_str().strip_prefix("ev_").map(|value|value.replace('-',"")),"state":format!("{:?}",receipt.state),"maintenance_pending":receipt.maintenance_pending,"checkpoint_ran":receipt.write_timings.as_ref().map(|timing|timing.checkpoint.is_some()),"timing_key":receipt.write_timings.as_ref().and_then(|timing|timing.request_key.as_ref()).map(ToString::to_string)})
        }
        Err(error) => {
            json!({"code":format!("{:?}",error.code),"cause":error.cause,"detail":format!("{:?}",error.detail)})
        }
    }
}
fn payload(
    f: &Fixture,
    key: &str,
    count: usize,
) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    let bodies = (0..count)
        .map(|number| {
            let pattern = format!("{key}-{number:02}-payload");
            let mut body = pattern.repeat(24500usize.div_ceil(pattern.len()));
            body.truncate(24500);
            Ok(EventBody::MessageSent {
                quiet: false,
                message: message()?,
                recipient: Actor::Agent(f.b.clone()),
                kind: "finding".into(),
                body: InputText::Inline(body),
                refs: vec![],
                reply_to: None,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    f.batch(
        f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.a.clone())),
        Some(request(key)?),
        bodies,
    )
}

/// Protects: store commit failure semantics — explicitly driven native fixture uses the public HostWriter while its real SQLite syscalls are traced outside the process.
#[test]
#[ignore = "explicitly spawned by the native syscall fault consumer"]
fn fault_child_fixture() -> Check {
    let root = ready_path()?;
    let mode = std::env::var("SE_SQLITE_FAULT_MODE")?;
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let mut owner = host.start_writer(options(256)?, lease.clone())?;
    let client = owner.client();
    let until = Instant::now() + Duration::from_secs(3);
    let tid = loop {
        let mut found = None;
        for entry in std::fs::read_dir("/proc/self/task")? {
            let entry = entry?;
            match std::fs::read_to_string(entry.path().join("comm")) {
                Ok(name) if name.trim() == "se-store-writer" => {
                    found = Some(entry.file_name());
                    break;
                }
                Ok(_) => (),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
        }
        if let Some(tid) = found {
            break tid;
        }
        if Instant::now() >= until {
            return Err("owned writer thread did not start".into());
        }
    };
    std::fs::write(
        root.join("ready.json"),
        serde_json::to_vec(
            &json!({"pid":std::process::id(),"tid":tid.to_str().ok_or("non-UTF8 tid")?,"database":f.options.state_directory.join("state.db")}),
        )?,
    )?;
    wait_path(&root.join("go"))?;
    let mut results = Vec::new();
    if mode == "before" {
        let blocker = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
        blocker.execute_batch("BEGIN IMMEDIATE")?;
        let gate = client.submit(f.working("gate", Expected::Absent, "fault-gate")?)?;
        let flush = owner.flush(Duration::from_secs(10))?;
        let first = client.submit(payload(&f, "fault-primary", 16)?)?;
        let second = client.submit(payload(&f, "fault-secondary", 16)?)?;
        blocker.execute_batch("ROLLBACK")?;
        wait(gate)??;
        wait(flush)??;
        results.push(outcome(wait(first)?));
        results.push(outcome(wait(second)?));
    } else {
        results.push(outcome(wait(client.submit(payload(
            &f,
            "fault-primary",
            if mode == "checkpoint" { 40 } else { 1 },
        )?)?)?));
    }
    let timing_keys: Vec<_> = results
        .iter()
        .filter_map(|result| result.get("timing_key").and_then(Value::as_str))
        .map(str::to_owned)
        .collect();
    let returned = results.clone();
    if mode == "checkpoint" {
        // The receipt precedes idle maintenance. Keep its original fields and
        // let the external syscall tracer observe the later checkpoint fault.
        std::fs::write(root.join("returned.json"), serde_json::to_vec(&returned)?)?;
        std::thread::sleep(Duration::from_millis(600));
    }
    let reopen_deadline = Instant::now() + Duration::from_secs(3);
    let mut reopen_busy = 0usize;
    let next = loop {
        match client.submit(f.working(
            "after-fault",
            if mode == "before" {
                revision(1)?
            } else {
                Expected::Absent
            },
            "after-fault",
        )?) {
            Ok(pending) => break outcome(wait(pending)?),
            Err(error)
                if error.code == StoreErrorCode::Busy && Instant::now() < reopen_deadline =>
            {
                reopen_busy += 1;
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => {
                break json!({"code":format!("{:?}",error.code),"cause":error.cause,"detail":format!("{:?}",error.detail)});
            }
        }
    };
    let drained = wait(owner.drain(Duration::from_secs(10)))?;
    let (drain, close) = match drained {
        Ok(drained) => {
            let pending: Vec<_> = drained
                .report
                .indeterminate
                .iter()
                .map(|key| format!("{key:?}"))
                .collect();
            let report = json!({"code":"Drained","indeterminate":pending});
            let close = match drained.host.close_clean(&*lease, Duration::from_secs(5)) {
                Ok(_) => json!({"code":"Closed"}),
                Err(error) => {
                    json!({"code":format!("{:?}",error.code),"cause":error.cause,"detail":format!("{:?}",error.detail)})
                }
            };
            (report, close)
        }
        Err(error) => (
            json!({"code":format!("{:?}",error.code),"cause":error.cause,"detail":format!("{:?}",error.detail)}),
            Value::Null,
        ),
    };
    let database = rusqlite::Connection::open_with_flags(
        f.options.state_directory.join("state.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let integrity: String = database.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    let retained_primary: i64 = database.query_row(
        "SELECT count(*) FROM events WHERE lower(hex(event_id))=?",
        [results[0].get("event_hex").and_then(Value::as_str)],
        |r| r.get(0),
    )?;
    let report = json!({"mode":mode,"database":f.options.state_directory.join("state.db"),"results":results,"returned":returned,"retained_primary":retained_primary,"timing_keys":timing_keys,"reopen_busy":reopen_busy,"next":next,"drain":drain,"close":close,"integrity":integrity});
    std::fs::write(
        root.join("outcome.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(())
}

fn native_case(case: &str) -> Check {
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/store_faults.py");
    let output = std::process::Command::new("python3")
        .arg(script)
        .arg(case)
        .arg(std::env::current_exe()?)
        .output()?;
    assert!(
        output.status.success(),
        "native SQLite {case} failure semantics:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

/// Protects: store ENOSPC before COMMIT — every group member gets DiskFull after a real pager spill fails and a full rollback keeps the same writer usable.
#[test]
fn disk_full_before_commit_rolls_back_the_entire_group() -> Check {
    native_case("before")
}

/// Protects: store ENOSPC during COMMIT — outcome-unknown keys remain named by drain and clean close rather than disappearing from the shutdown report.
#[test]
fn disk_full_during_commit_preserves_indeterminate_keys() -> Check {
    native_case("commit")
}

/// Protects: store IO during COMMIT — an actual native write error preserves the original indeterminate key through drain and clean close.
#[test]
fn io_failure_during_commit_preserves_indeterminate_keys() -> Check {
    native_case("commit-io")
}

/// Protects: store checkpoint failure — actual ENOSPC after COMMIT preserves known committed receipts and leaves write admission usable for maintenance retry.
#[test]
fn checkpoint_failure_never_relabels_known_commits() -> Check {
    native_case("checkpoint")
}
