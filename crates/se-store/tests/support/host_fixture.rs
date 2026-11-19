use super::*;
#[cfg(any(target_os = "linux", windows))]
use se_types::StartIdentity;
use se_types::{
    BootId, Generation, HostEpoch, HostGeneration, MachineId, NativePath, ProcessFields,
    ProcessInstance, Sha256,
};
use std::{
    future::Future,
    num::{NonZeroU16, NonZeroU32},
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
    time::{Duration, Instant},
};

/// Single-step observation window; load phases that budget their whole
/// workload pass one shared deadline to `wait_until` instead.
const STEP: Duration = Duration::from_secs(5);
pub fn wait<F: Future>(future: F) -> Result<F::Output, Box<dyn std::error::Error>> {
    wait_until(future, Instant::now() + STEP)
}
/// Poll a completion against an absolute deadline. A load phase passes one
/// deadline to every step so the allowance scales with the workload instead
/// of slicing a fixed window off each commit: a slow runner spends the
/// allowance rather than failing the case, and a stuck completion still
/// times out.
pub fn wait_until<F: Future>(
    future: F,
    end: Instant,
) -> Result<F::Output, Box<dyn std::error::Error>> {
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
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return Ok(value),
            Poll::Pending => {
                let left = end
                    .checked_duration_since(Instant::now())
                    .ok_or("public completion timed out")?;
                std::thread::park_timeout(left);
            }
        }
    }
}
pub fn options(queue: u16) -> Result<WriterOptions, Box<dyn std::error::Error>> {
    Ok(WriterOptions {
        maximum_requests: NonZeroU16::new(256).ok_or("max")?,
        queue_requests: NonZeroU16::new(queue).ok_or("queue")?,
        resident_bytes: NonZeroU32::new(1024 * 1024).ok_or("resident")?,
        group_bytes: NonZeroU32::new(2 * 1024 * 1024).ok_or("group")?,
    })
}
pub fn epoch() -> Result<HostEpoch, Box<dyn std::error::Error>> {
    // The same native self-observation the real host uses, so a fixture epoch
    // and a fixture checkpoint describe one host instance.
    let machine = MachineId::new("public-store-consumer")?;
    let identity = se_proc::current_runtime_identity(machine.clone())
        .map_err(|e| format!("native self identity: {e:?}"))?;
    let started = match identity.process.start {
        se_proc::StartIdentity::Linux { start_ticks } => StartIdentity::Linux { start_ticks },
        se_proc::StartIdentity::Windows { creation_filetime } => StartIdentity::Windows {
            creation_filetime: std::num::NonZeroU64::new(creation_filetime)
                .ok_or("zero creation time")?,
        },
        se_proc::StartIdentity::MacOs {
            seconds,
            microseconds,
        } => StartIdentity::Macos {
            start_seconds: seconds,
            start_micros: microseconds,
        },
    };
    let owner = ProcessInstance::from_observation(ProcessFields {
        machine,
        boot: identity.boot_id,
        pid: NonZeroU32::new(std::process::id()).ok_or("pid")?,
        started,
        executable: NativePath::from_local(identity.process.image.clone())?,
        argv_sha256: Sha256::from_bytes([0; 32]),
    })?;
    Ok(HostEpoch {
        owner,
        generation: HostGeneration::new(1)?,
    })
}
/// A version-1 reservation checkpoint for a host-owned shared scope, bound to
/// the fixture epoch's own native host instance. The scope tag is the shared
/// scope's lifecycle, which the server record also uses.
#[allow(
    dead_code,
    reason = "Only the shared-scope binaries reserve a host server."
)]
pub fn host_reservation(
    scope: &se_types::LifecycleId,
    epoch: &HostEpoch,
) -> Result<se_proc::Checkpoint, Box<dyn std::error::Error>> {
    let fields = epoch.owner.fields();
    let start = match &fields.started {
        StartIdentity::Linux { start_ticks } => se_proc::StartIdentity::Linux {
            start_ticks: *start_ticks,
        },
        StartIdentity::Windows { creation_filetime } => se_proc::StartIdentity::Windows {
            creation_filetime: creation_filetime.get(),
        },
        StartIdentity::Macos {
            start_seconds,
            start_micros,
        } => se_proc::StartIdentity::MacOs {
            seconds: *start_seconds,
            microseconds: *start_micros,
        },
    };
    let parent = match &start {
        se_proc::StartIdentity::Linux { .. } => se_proc::ReservationParent::LinuxTracked,
        se_proc::StartIdentity::Windows { .. } => se_proc::ReservationParent::Windows,
        se_proc::StartIdentity::MacOs { .. } => se_proc::ReservationParent::MacOs,
    };
    Ok(se_proc::Checkpoint {
        format_version: 1,
        lifecycle: scope.clone(),
        principal: se_proc::CheckpointPrincipal::Host {
            scope: scope.clone(),
        },
        session: None,
        root_identity: se_proc::RootPublication::NoChildCreated,
        checkpoint: se_proc::CheckpointKind::Reservation(se_proc::LaunchReservation {
            format_version: 1,
            lifecycle: scope.clone(),
            host: se_proc::HostInstanceId([41; 16]),
            owner: se_proc::ProcessIdentity {
                machine: fields.machine.clone(),
                boot: native_boot(&fields.boot)?,
                pid: se_proc::ProcessId(fields.pid.get()),
                start,
                image: fields.executable.to_local()?,
            },
            generation: se_proc::GenerationId::new(epoch.generation.get())
                .map_err(|e| format!("host generation: {e}"))?,
            scope_nonce: [43; 16],
            parent,
            created_at_unix_ns: 1_700_000_000_000_000_000,
        }),
    })
}
/// The typed native boot fact for the epoch's recorded platform boot string.
#[allow(
    dead_code,
    reason = "Only the shared-scope binaries reserve a host server."
)]
fn native_boot(boot: &BootId) -> Result<se_proc::BootIdentity, Box<dyn std::error::Error>> {
    if let Some(text) = boot.as_str().strip_prefix("linux:") {
        let id = uuid::Uuid::parse_str(text)?;
        return Ok(se_proc::BootIdentity::Linux {
            boot_id: *id.as_bytes(),
        });
    }
    if let Some(text) = boot.as_str().strip_prefix("macos-") {
        let (seconds, micros) = text.split_once('-').ok_or("macos boot shape")?;
        return Ok(se_proc::BootIdentity::MacOs {
            seconds: seconds.parse()?,
            microseconds: micros.parse()?,
        });
    }
    if boot.as_str().starts_with("windows:") {
        return Ok(se_proc::BootIdentity::WindowsAbsoluteCreationClock);
    }
    Err("unrecognized platform boot identity".into())
}
pub fn host(f: &Fixture) -> Result<(SqliteHost, Arc<Lease>), Box<dyn std::error::Error>> {
    let (direct, lease) = f.direct()?;
    direct.close()?;
    drop(lease);
    host_from_existing(f)
}
pub fn host_from_existing(
    f: &Fixture,
) -> Result<(SqliteHost, Arc<Lease>), Box<dyn std::error::Error>> {
    let lease = Lease::acquire(
        &f.options.state_directory,
        LeaseMode::Host,
        Some(f.store.clone()),
    )?;
    let mut host = present(SqliteFactory::open_host(&f.options, &*lease)?)?;
    let receipt = host.record_runtime_ownership(
        f.batch(
            f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
            Some(request("runtime-owner")?),
            vec![EventBody::RuntimeOwnerEstablished {
                epoch: epoch()?,
                generation: Generation::new(1)?,
                expected_owner_generation: None,
                expected: Expected::Absent,
                witnesses: vec![],
                recovered: None,
            }],
        )?,
        &*lease,
    )?;
    assert_eq!(receipt.durability, CommitDurability::Full);
    assert_eq!(receipt.writer.kind(), WriterKind::Host { generation: 1 });
    Ok((host, lease))
}
