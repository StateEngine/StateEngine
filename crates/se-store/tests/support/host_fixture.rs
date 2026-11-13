use super::*;
use se_types::{
    BootId, Generation, HostEpoch, HostGeneration, MachineId, NativePath, ProcessFields,
    ProcessInstance, Sha256, StartIdentity,
};
use std::{
    future::Future,
    num::{NonZeroU16, NonZeroU32},
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
    time::{Duration, Instant},
};

pub fn wait<F: Future>(future: F) -> Result<F::Output, Box<dyn std::error::Error>> {
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
    let end = Instant::now() + Duration::from_secs(5);
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
    #[cfg(target_os = "linux")]
    let (boot, started) = {
        let stat = std::fs::read_to_string("/proc/self/stat")?;
        let suffix = stat.rsplit_once(')').ok_or("proc stat delimiter")?.1;
        let ticks = suffix
            .split_whitespace()
            .nth(19)
            .ok_or("proc start time")?
            .parse()?;
        (
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                .trim()
                .to_string(),
            StartIdentity::Linux { start_ticks: ticks },
        )
    };
    #[cfg(windows)]
    let (boot, started) = {
        let output = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "(Get-Process -Id {}).StartTime.ToFileTimeUtc()",
                    std::process::id()
                ),
            ])
            .output()?;
        if !output.status.success() {
            return Err("native creation time unavailable".into());
        }
        let time = String::from_utf8(output.stdout)?.trim().parse()?;
        (
            "windows-absolute-creation-clock".to_string(),
            StartIdentity::Windows {
                creation_filetime: std::num::NonZeroU64::new(time).ok_or("zero creation time")?,
            },
        )
    };
    #[cfg(target_os = "macos")]
    let (boot, started) = {
        let peer = se_proc::native_ipc::observe_ipc_self()?;
        (
            se_proc::observe_boot_id()?.as_str().to_owned(),
            peer.started().clone(),
        )
    };
    let owner = ProcessInstance::from_observation(ProcessFields {
        machine: MachineId::new("public-store-consumer")?,
        boot: BootId::new(boot)?,
        pid: NonZeroU32::new(std::process::id()).ok_or("pid")?,
        started,
        executable: NativePath::from_local(std::env::current_exe()?)?,
        argv_sha256: Sha256::from_bytes([0; 32]),
    })?;
    Ok(HostEpoch {
        owner,
        generation: HostGeneration::new(1)?,
    })
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
