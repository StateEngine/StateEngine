use super::*;
use serde_json::{Value, json};
use std::process::{Child, Command, Stdio};
use std::time::Instant;
const CHILD: &str = "crash::committed_child";
const ROOT: &str = "SE_CHECKPOINT_CRASH_ROOT";
fn canonical(receipt: &CommitReceipt) -> Value {
    json!({"key":receipt.request_key.as_ref().map(|key|key.as_str()),
        "state":format!("{:?}",receipt.state),
        "primary":receipt.primary_event.as_str(),
        "events":receipt.events.iter().map(|id|id.as_str()).collect::<Vec<_>>(),
        "first":format!("{:?}",receipt.first),"last":format!("{:?}",receipt.last),
        "writer":format!("{:?}",receipt.writer),
        "durability":format!("{:?}",receipt.durability),
        "wakes":format!("{:?}",receipt.wakes)})
}
fn wait_file(path: &Path) -> Check {
    let until = Instant::now() + Duration::from_secs(15);
    while !path.try_exists()? {
        if Instant::now() >= until {
            return Err(format!("child boundary absent: {}", path.display()).into());
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    Ok(())
}
fn terminate(child: &mut Child) -> Check {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    let command = std::fs::read(format!("/proc/{}/cmdline", child.id()))?;
    assert!(
        command
            .windows(CHILD.len())
            .any(|part| part == CHILD.as_bytes()),
        "owned child identity changed"
    );
    child.kill()?;
    child.wait()?;
    Ok(())
}
struct OwnedChild {
    process: Child,
    home: Option<std::path::PathBuf>,
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Err(error) = terminate(&mut self.process) {
            eprintln!(
                "owned crash fixture cleanup: {error}; retained {:?}",
                self.home
            );
            return;
        }
        if let Some(home) = &self.home
            && let Err(error) = std::fs::remove_dir_all(home)
        {
            eprintln!("private child home cleanup: {error}");
        }
    }
}
/// Protects: the native crash fixture uses the actual public writer and emits
/// receipt facts only after its completion returns, then waits for its owner.
#[test]
#[ignore = "spawned and terminated only by the owned crash consumer"]
fn committed_child() -> Check {
    let control =
        std::path::PathBuf::from(std::env::var_os(ROOT).ok_or("crash control root absent")?);
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let writer = host.start_writer(options(256)?, lease.clone())?;
    std::fs::write(
        control.join("ready.json"),
        serde_json::to_vec(
            &json!({"pid":std::process::id(), "home":f.home,"state":f.options.state_directory,
                "project":f.project,"owner":f.owner,"agent":f.a}),
        )?,
    )?;
    wait_file(&control.join("go"))?;
    let receipt = wait(writer.client().submit(payload(&f, "crash-returned")?)?)??;
    let ids: Vec<_> = receipt
        .events
        .iter()
        .map(|id| {
            id.as_str()
                .strip_prefix("ev_")
                .map(|value| value.replace('-', ""))
        })
        .collect();
    let value = json!({"key":receipt.request_key.as_ref().map(|k| k.as_str()),
        "ids":ids,"last":format!("{:?}",receipt.last),
        "canonical":canonical(&receipt),
        "state":format!("{:?}",receipt.state),"durability":format!("{:?}",receipt.durability),
        "maintenance_pending":receipt.maintenance_pending,
        "checkpoint_ran":receipt.write_timings.as_ref().map(|t|t.checkpoint.is_some())});
    // Atomic rename prevents the controller observing a partial receipt.
    std::fs::write(control.join("returned.tmp"), serde_json::to_vec(&value)?)?;
    std::fs::rename(control.join("returned.tmp"), control.join("returned.json"))?;
    wait_file(&control.join("release"))?;
    drop(wait(writer.drain(Duration::from_secs(4)))??);
    Ok(())
}
/// Protects: terminating an owned process after its receipt returns but while a
/// separate reader prevents complete checkpointing loses no receipt membership.
#[test]
fn crash_between_commit_and_complete_checkpoint_preserves_receipt() -> Check {
    let control = Fixture::new()?;
    let log = std::fs::File::create(control.home.join("child.log"))?;
    let mut child = OwnedChild {
        home: None,
        process: Command::new(std::env::current_exe()?)
            .args(["--exact", CHILD, "--ignored", "--nocapture"])
            .env(ROOT, &control.home)
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?,
    };
    wait_file(&control.home.join("ready.json"))?;
    let ready: Value = serde_json::from_slice(&std::fs::read(control.home.join("ready.json"))?)?;
    assert_eq!(ready["pid"].as_u64(), Some(child.process.id() as u64));
    child.home = Some(std::path::PathBuf::from(
        ready["home"].as_str().ok_or("home missing")?,
    ));
    let state = std::path::PathBuf::from(ready["state"].as_str().ok_or("state missing")?);
    assert_eq!(state.parent(), child.home.as_deref());
    let path = state.join("state.db");
    let pinned = observer(&path)?;
    pin(&pinned)?;
    std::fs::write(control.home.join("go"), b"independent old snapshot pinned")?;
    wait_file(&control.home.join("returned.json"))?;
    let receipt: Value =
        serde_json::from_slice(&std::fs::read(control.home.join("returned.json"))?)?;
    assert_eq!(receipt["state"], "Committed");
    assert_eq!(receipt["key"], "crash-returned");
    assert_eq!(receipt["maintenance_pending"], true);
    assert_eq!(receipt["checkpoint_ran"], false);
    let outside = observer(&path)?;
    let (log, done, _) = wal(&outside)?;
    assert!(
        log >= 256 && log > done,
        "crash boundary was already checkpointed: {log}/{done}"
    );
    terminate(&mut child.process)?;
    assert!(
        child.process.try_wait()?.is_some(),
        "process termination not joined"
    );
    let (after_log, after_done, _) = wal(&outside)?;
    assert!(
        after_log > after_done,
        "termination checkpointed the receipt"
    );
    let options = StoreOptions {
        state_directory: state.clone(),
        busy_timeout: Duration::from_secs(2),
    };
    let reader = present(SqliteFactory::open_reader(&options)?)?;
    assert_eq!(
        reader.info()?.head.map(|position| format!("{position:?}")),
        receipt["last"].as_str().map(str::to_owned)
    );
    let mut snapshot = reader.snapshot(ReadScope {
        admission: Admission {
            scope: Scope::Project(serde_json::from_value(ready["project"].clone())?),
            actor: Actor::Human(serde_json::from_value(ready["owner"].clone())?),
            session: None,
            generation: 1,
        },
        visibility: Visibility::Owner,
    })?;
    let retained = present(snapshot.operation_receipt(
        Actor::Agent(serde_json::from_value(ready["agent"].clone())?),
        request("crash-returned")?.key,
    )?)?;
    assert_eq!(
        canonical(&retained),
        receipt["canonical"],
        "crash changed a returned receipt"
    );
    assert!(
        retained.write_timings.is_none(),
        "lookup invented submission timings"
    );
    snapshot.close()?;
    let recovered = observer(&path)?;
    let ids: Vec<String> = member_ids(&recovered, "crash-returned")?
        .iter()
        .map(|id| se_types::hex_lower(id))
        .collect();
    assert_eq!(serde_json::to_value(&ids)?, receipt["ids"]);
    assert_eq!(ids.len(), 40);
    healthy(&recovered)?;
    // Keep the old pin and outside connections alive through readback: closing
    // the last SQLite connection can itself checkpoint and mask this boundary.
    pinned.execute_batch("ROLLBACK")?;
    eprintln!(
        "native process crash: returned receipt with 40 members recovered; pre-termination WAL {log}/{done}"
    );
    // A process crash proves recovery from existing WAL, not simulated power loss.
    Ok(())
}
