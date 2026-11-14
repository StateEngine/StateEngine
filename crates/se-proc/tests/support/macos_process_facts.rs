//! Darwin reader agreement; Linux comm-byte parsing is not exercised here.
#[path = "../../../test-support/macos_process.rs"]
mod outside;
use se_proc::{
    MachineId, NativeState, OwnerTarget, ProcessId, ProcessRead, StartIdentity, observe_owner,
    read_process,
};
use std::{
    io::{BufRead, Write},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn machine() -> Result<MachineId> {
    Ok(MachineId::new("native-facts-fixture")?)
}
fn live(pid: ProcessId) -> Result<se_proc::LiveObservation> {
    match read_process(machine()?, pid).map_err(|e| format!("{e:?}"))? {
        ProcessRead::Present(value) => Ok(value),
        other => Err(format!("expected live native child: {other:?}").into()),
    }
}
fn child() -> Result {
    let pid = ProcessId(std::process::id());
    let process = live(pid)?;
    let peer = se_proc::native_ipc::observe_ipc_self()?;
    let (
        se_types::StartIdentity::MacOs {
            seconds: ipc_seconds,
            microseconds: ipc_micros,
        },
        StartIdentity::MacOs {
            seconds,
            microseconds,
        },
    ) = (peer.started(), &process.identity.start)
    else {
        return Err("Darwin readers returned another platform's birth".into());
    };
    assert_eq!((ipc_seconds, ipc_micros), (seconds, microseconds));
    let owner = observe_owner(OwnerTarget::Current, &[])?;
    assert_eq!(owner.pid(), pid);
    assert_eq!(owner.start(), &process.identity.start);
    assert!(owner.agent_trees().is_empty());
    println!("NATIVE-FACTS-READY");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(())
}
struct Held(Child);
impl Drop for Held {
    fn drop(&mut self) {
        drop(self.0.stdin.take());
        if let Err(error) = self.0.wait() {
            eprintln!("join exact owned native-facts child: {error}");
        }
    }
}
fn start() -> Result<Held> {
    let mut child = Held(
        Command::new(std::env::current_exe()?)
            .arg("--facts-child")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let mut ready = String::new();
    std::io::BufReader::new(child.0.stdout.take().ok_or("owned child stdout absent")?)
        .read_line(&mut ready)?;
    assert_eq!(ready, "NATIVE-FACTS-READY\n");
    Ok(child)
}
fn exits(child: &mut Held, expected: &se_proc::ProcessIdentity) -> Result {
    let pid = ProcessId(child.0.id());
    drop(child.0.stdin.take());
    let end = Instant::now() + Duration::from_secs(10);
    while outside::bsd(pid.0)?.pbi_status != libc::SZOMB {
        assert!(
            Instant::now() < end,
            "owned child did not reach native zombie"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    match read_process(machine()?, pid).map_err(|e| format!("{e:?}"))? {
        ProcessRead::ExitedRecord {
            pid: found,
            boot,
            start,
            state: NativeState::ExitedAwaitingReap,
            ..
        } => {
            assert_eq!(found, pid);
            assert_eq!(boot, expected.boot);
            assert_eq!(start, expected.start);
        }
        other => return Err(format!("native zombie lost its exited record: {other:?}").into()),
    }
    assert!(
        observe_owner(
            OwnerTarget::Process {
                pid,
                start: &expected.start
            },
            &[]
        )
        .is_err(),
        "native zombie admitted as an owner"
    );
    assert!(child.0.wait()?.success());
    match read_process(machine()?, pid).map_err(|e| format!("{e:?}"))? {
        ProcessRead::Absent {
            pid: found,
            observed_at_unix_ns,
        } => {
            assert_eq!(found, pid);
            assert!(observed_at_unix_ns > 0);
        }
        other => return Err(format!("reaped child was not absent: {other:?}").into()),
    }
    assert!(
        observe_owner(
            OwnerTarget::Process {
                pid,
                start: &expected.start
            },
            &[]
        )
        .is_err(),
        "reaped child admitted as an owner"
    );
    Ok(())
}
pub(super) fn run() -> Result {
    if std::env::args().nth(1).as_deref() == Some("--facts-child") {
        return child();
    }
    let mut child = start()?;
    let pid = ProcessId(child.0.id());
    let expected = outside::outside(pid.0, machine()?)?;
    let process = live(pid)?;
    assert_eq!(process.identity, expected);
    let owner = observe_owner(
        OwnerTarget::Process {
            pid,
            start: &expected.start,
        },
        &[],
    )?;
    assert_eq!(owner.pid(), pid);
    assert_eq!(owner.start(), &expected.start);
    assert!(owner.agent_trees().is_empty());
    let StartIdentity::MacOs {
        seconds,
        microseconds,
    } = expected.start
    else {
        return Err("outside native birth is not Darwin".into());
    };
    let wrong = StartIdentity::MacOs {
        seconds: seconds + 1,
        microseconds,
    };
    let error = observe_owner(OwnerTarget::Process { pid, start: &wrong }, &[])
        .err()
        .ok_or("wrong native birth admitted as an owner")?;
    assert_eq!(error.operation, "bind observed owner");
    assert!(
        error
            .source
            .to_string()
            .contains("target process start changed")
    );
    exits(&mut child, &expected)?;
    println!(
        "macos_process_facts: 4 passed, 0 failed; outside native birth, process/owner/IPC agreement, wrong-birth refusal, zombie/reaped distinctions; Linux comm-byte parsing NOT GRADED"
    );
    Ok(())
}
