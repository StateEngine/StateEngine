//! Public decoder with actual native observations; no process-reader injection.
#![cfg(target_os = "linux")]
use se_proc::*;
use se_store::*;
use se_types::{Code, Retry};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, Command, Stdio},
    time::Duration,
};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
fn native(e: impl std::fmt::Debug) -> String {
    format!("{e:?}")
}
fn inventory(
    owner: ProcessIdentity,
) -> Result<(Fixture, OwnerGuardInventory), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let (direct, lease) = f.direct()?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut inventory = reader.owner_guard(&lease.files, budget(20, 65536, None)?)?;
    let lifecycle = LifecycleId::from_parts(1_700_000_000_000 + serial(), [83; 10])?;
    let checkpoint = Checkpoint {
        format_version: 1,
        lifecycle: lifecycle.clone(),
        principal: CheckpointPrincipal::Agent(f.a.clone()),
        session: None,
        root_identity: RootPublication::NoChildCreated,
        checkpoint: CheckpointKind::Reservation(LaunchReservation {
            format_version: 1,
            lifecycle: lifecycle.clone(),
            host: HostInstanceId([31; 16]),
            owner,
            generation: GenerationId::new(1)?,
            scope_nonce: [37; 16],
            parent: ReservationParent::LinuxTracked,
            created_at_unix_ns: 1,
        }),
    };
    let custody = encode_checkpoint(&checkpoint)?;
    inventory.has_process_records = true;
    inventory.processes = vec![OwnerGuardProcess {
        project: f.project.clone(),
        revision: Revision {
            value: std::num::NonZeroU64::MIN,
        },
        state: ProcessState::Reserved,
        identity: ProcessIdentityRecord {
            record: lifecycle,
            principal: Actor::Agent(f.a.clone()),
            session: None,
            root_identity: RootIdentityState::NoChildCreated,
            instance: RecordedIdentity::Absent {
                reason: "not published yet".into(),
            },
            custody: NativeCustody {
                format_version: 1,
                record: custody,
            },
            containment: ContainmentFact::NotLaunched,
        },
    }];
    direct.close()?;
    drop(lease);
    Ok((f, inventory))
}
fn owner() -> Result<ProcessIdentity, Box<dyn std::error::Error>> {
    current_process_identity(MachineId::new("independent-owner-retry")?)
        .map_err(|e| native(e).into())
}
fn refusal(
    inventory: &OwnerGuardInventory,
) -> Result<se_types::SeError, Box<dyn std::error::Error>> {
    se_host::decode_owner_inventory(inventory)
        .err()
        .ok_or_else(|| "unpublished custody granted owner admission".into())
}
#[test]
fn exact_live_original_owner_only_gets_a_bounded_retry() -> Check {
    let (_f, inventory) = inventory(owner()?)?;
    let error = refusal(&inventory)?;
    assert_eq!(error.body.code(), Code::StateConflict);
    assert_eq!(error.body.retry(), &Retry::After(Duration::from_secs(1)));
    Ok(())
}
/// Protects: a reused owner PID is not the original live host and cannot deadlock C1 recovery.
#[test]
fn replaced_owner_birth_admits_c1_without_signalling_the_new_process() -> Check {
    let mut stale = owner()?;
    let StartIdentity::Linux { start_ticks } = &mut stale.start else {
        return Err("native Linux owner required".into());
    };
    *start_ticks = start_ticks
        .checked_sub(1)
        .ok_or("earlier native birth required")?;
    let (_f, inventory) = inventory(stale)?;
    let custody = inventory.processes[0].identity.custody.record.clone();
    assert!(se_host::decode_owner_inventory(&inventory)?.is_empty());
    assert_eq!(inventory.processes[0].identity.custody.record, custody);
    assert!(matches!(
        read_process(owner()?.machine, ProcessId(std::process::id())).map_err(native)?,
        ProcessRead::Present(_)
    ));
    Ok(())
}
struct ChildOwner {
    child: Child,
    output: BufReader<std::process::ChildStdout>,
    identity: ProcessIdentity,
}
impl ChildOwner {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let code = "import ctypes,sys; print('ready',flush=True); input(); ctypes.CDLL(None).prctl(4,0); print('sealed',flush=True); input()";
        let mut child = Command::new("/usr/bin/python3")
            .args(["-c", code])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let mut output = BufReader::new(child.stdout.take().ok_or("child stdout")?);
        let mut ready = String::new();
        output.read_line(&mut ready)?;
        if ready.trim() != "ready" {
            return Err("native child did not reach observation barrier".into());
        }
        let identity = match read_process(
            MachineId::new("independent-owner-retry")?,
            ProcessId(child.id()),
        )
        .map_err(native)?
        {
            ProcessRead::Present(value) => value.identity,
            _ => return Err("live child owner unreadable before barrier".into()),
        };
        Ok(Self {
            child,
            output,
            identity,
        })
    }
    fn seal(&mut self) -> Check {
        self.child
            .stdin
            .as_mut()
            .ok_or("child stdin")?
            .write_all(b"seal\n")?;
        let mut line = String::new();
        self.output.read_line(&mut line)?;
        assert_eq!(line.trim(), "sealed");
        Ok(())
    }
    fn finish(&mut self) -> Check {
        if let Some(mut input) = self.child.stdin.take() {
            input.write_all(b"seal\nexit\n")?;
        }
        assert!(self.child.wait()?.success());
        Ok(())
    }
}
impl Drop for ChildOwner {
    fn drop(&mut self) {
        if self.child.stdin.is_some() {
            let _ = self.finish();
        }
    }
}
#[test]
fn dead_original_owner_retains_its_refusal_without_retry_advice() -> Check {
    let mut child = ChildOwner::new()?;
    let identity = child.identity.clone();
    child.finish()?;
    let (_f, inventory) = inventory(identity)?;
    let error = refusal(&inventory)?;
    assert_eq!(error.body.code(), Code::SourceUnreadable);
    assert_eq!(error.body.retry(), &Retry::Never);
    Ok(())
}
#[test]
fn actual_unreadable_native_owner_stays_closed() -> Check {
    let mut child = ChildOwner::new()?;
    let identity = child.identity.clone();
    child.seal()?;
    let native_error = read_process(identity.machine.clone(), identity.pid)
        .err()
        .ok_or("fixture did not make the real native identity unreadable")?;
    assert_eq!(native_error.code, ProcErrorCode::IdentityUnreadable);
    let (_f, inventory) = inventory(identity)?;
    let error = refusal(&inventory)?;
    child.finish()?;
    assert_eq!(error.body.code(), Code::SourceUnreadable);
    assert_eq!(error.body.retry(), &Retry::Never);
    Ok(())
}
#[test]
fn corrupt_and_mismatched_custody_never_become_retryable_or_empty() -> Check {
    let (_f, mut inventory) = inventory(owner()?)?;
    let original = inventory.processes[0].identity.custody.record.clone();
    for bytes in [b"{broken".to_vec(), vec![], original.clone()] {
        inventory.processes[0].identity.custody.record = bytes;
        if inventory.processes[0].identity.custody.record == original {
            inventory.processes[0].identity.root_identity = RootIdentityState::Identified;
        }
        let error = refusal(&inventory)?;
        assert_eq!(error.body.code(), Code::SourceUnreadable);
        assert_eq!(error.body.retry(), &Retry::Never);
    }
    Ok(())
}

/// Protects: a changed owner executable proves the old C1 owner gone, without touching its successor.
#[test]
fn changed_owner_image_admits_c1_without_consuming_custody() -> Check {
    let mut stale = owner()?;
    stale.image = std::path::PathBuf::from("/usr/bin/false");
    let (_f, inventory) = inventory(stale)?;
    let custody = inventory.processes[0].identity.custody.record.clone();
    assert!(se_host::decode_owner_inventory(&inventory)?.is_empty());
    assert_eq!(inventory.processes[0].identity.custody.record, custody);
    Ok(())
}
