//! Native facts and value mapping for the embedded host. Nothing here trusts a
//! caller-supplied identity: the epoch is observed from this process, the
//! configuration and machine identity are read through retained custody.
use crate::client::{ClientOptions, lease::Deadline};
use se_types::{
    HostEpoch, HostGeneration, NativePath, ProcessFields, ProcessInstance, Result, SeError, Sha256,
};
use secode_stateengine_api as api;
use sha2::{Digest, Sha256 as Hasher};
use std::{
    num::{NonZeroU16, NonZeroU32},
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

/// The epoch of this exact SE Code server process at `generation`, verified
/// against its own executable image like the standalone child's.
pub(super) fn current_epoch(generation: u64, home: &Path) -> Result<HostEpoch> {
    let files =
        crate::state_files::Files::open(home).map_err(|e| se_core::store_error::store_error(&e))?;
    let machine = crate::state_files::machine_identity(&files)?;
    let identity = se_proc::current_runtime_identity(machine).map_err(native)?;
    let peer = se_proc::native_ipc::observe_ipc_self().map_err(native)?;
    let epoch = HostEpoch {
        owner: ProcessInstance::from_observation(ProcessFields {
            machine: identity.process.machine,
            boot: identity.boot_id,
            pid: NonZeroU32::new(peer.pid())
                .ok_or_else(|| SeError::invalid("host pid", "a nonzero process id"))?,
            started: peer.started().clone(),
            executable: NativePath::from_local(identity.process.image)?,
            argv_sha256: argv_digest(),
        })?,
        generation: HostGeneration::new(generation)?,
    };
    peer.verify_instance(&epoch.owner, peer.image_sha256())
        .map_err(native)?;
    Ok(epoch)
}

/// Length-prefixed native argv bytes, the same digest the standalone child uses.
fn argv_digest() -> Sha256 {
    let mut digest = Hasher::new();
    for arg in std::env::args_os() {
        #[cfg(unix)]
        let bytes = std::os::unix::ffi::OsStrExt::as_bytes(arg.as_os_str()).to_vec();
        #[cfg(windows)]
        let bytes: Vec<u8> = std::os::windows::ffi::OsStrExt::encode_wide(arg.as_os_str())
            .flat_map(u16::to_le_bytes)
            .collect();
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    Sha256::from_bytes(digest.finalize().into())
}

/// The owner's config.toml, validated; absent is a refusal, never a default.
pub(super) fn load_config(home: &Path) -> Result<se_core::config_policy::ConfigFile> {
    let path = home.join("config.toml");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| se_core::scope::unreadable("config.toml", &e.to_string()).with_cause(e))?;
    let config: se_core::config_policy::ConfigFile = toml::from_str(&text)
        .map_err(|e| se_core::scope::unreadable("config.toml", &e.to_string()))?;
    config.validate()?;
    Ok(config)
}

/// The standalone child's writer bounds.
pub(super) fn writer_options() -> Result<se_store::WriterOptions> {
    let requests = |value| {
        NonZeroU16::new(value).ok_or_else(|| SeError::invalid("writer", "positive requests"))
    };
    Ok(se_store::WriterOptions {
        maximum_requests: requests(16)?,
        queue_requests: requests(64)?,
        resident_bytes: positive(1024 * 1024)?,
        group_bytes: positive(1024 * 1024)?,
    })
}

/// The standalone child's limits, with SE Code's negotiated payload and
/// notice bounds applied where the linked API names them.
pub(super) fn limits(
    linked: &api::Limits,
    config: &se_core::config_policy::ConfigFile,
) -> Result<crate::HostLimits> {
    let cores = std::thread::available_parallelism().ok();
    Ok(crate::HostLimits {
        sessions: positive(256)?,
        active_connections: positive(64)?,
        preauth_connections: positive(32)?,
        parked_mail_waits: positive(64)?,
        resident_queue_bytes: positive(1024 * 1024)?,
        session_notice_ids: linked.notice_ids,
        aggregate_notice_ids: positive(4096)?,
        response_bytes: linked.payload_bytes,
        blocking_jobs: config.runtime.resolve_blocking_jobs(cores)?,
    })
}

pub(super) fn deadline(timeout: Duration) -> Result<Deadline> {
    Deadline::from_options(&ClientOptions {
        expected_generation: None,
        timeout,
        cancelled: Arc::new(AtomicBool::new(false)),
    })
}

/// Link the public cancellation callback to the same absolute deadline used
/// by blocking admission and the accepted-write completion observer.
pub(super) struct CallCancellation {
    flag: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for CallCancellation {
    fn drop(&mut self) {
        self.flag.store(true, std::sync::atomic::Ordering::Release);
        self.task.abort();
    }
}
pub(super) fn call_deadline(
    runtime: &tokio::runtime::Handle,
    options: &api::CallOptions,
) -> Result<(Deadline, CallCancellation)> {
    let flag = Arc::new(AtomicBool::new(options.cancellation.is_cancelled()));
    let deadline = Deadline::from_options(&ClientOptions {
        expected_generation: None,
        timeout: options.timeout,
        cancelled: flag.clone(),
    })?;
    let signal = flag.clone();
    let cancellation = options.cancellation.clone();
    let task = runtime.spawn(async move {
        cancellation.cancelled().await;
        signal.store(true, std::sync::atomic::Ordering::Release);
    });
    Ok((deadline, CallCancellation { flag, task }))
}

/// The canonical rendered error; a rendering failure is reported, not hidden.
pub(super) use crate::linked::api_error;
pub(super) fn refused(subject: &str, expected: &str) -> api::ApiError {
    api_error(&SeError::invalid(subject, expected))
}
/// A linked method outside this slice: named, typed, never a fake outcome.
pub(super) fn unavailable(subject: &str) -> api::ApiError {
    api_error(&SeError::new(se_types::Detail::FeatureUnavailable(
        se_types::details::FeatureUnavailable {
            subject: subject.into(),
            reason: "the embedded host does not implement this yet".into(),
            next_step: "Use the standalone host for this; it arrives with live handover in wave 4."
                .into(),
        },
    )))
}

fn positive(value: u32) -> Result<NonZeroU32> {
    NonZeroU32::new(value).ok_or_else(|| SeError::invalid("host limit", "a positive bound"))
}
fn native(error: impl std::fmt::Debug) -> SeError {
    se_core::scope::unreadable("native host self", &format!("{error:?}"))
}

const STORE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Read-only: the store's identity/schema and the next owner generation.
pub(super) fn observe_store(home: PathBuf) -> se_types::Result<Option<(se_store::StoreInfo, u64)>> {
    use se_store::ReadStore;
    let options = se_store::StoreOptions {
        state_directory: home,
        busy_timeout: STORE_BUSY_TIMEOUT,
    };
    let capacity = std::num::NonZeroU32::MIN.saturating_add(1);
    let store = |e: Box<se_store::StoreError>| se_core::store_error::store_error(&e);
    let reader = match se_store::SqliteFactory::open_reader_with_capacity(&options, capacity)
        .map_err(store)?
    {
        se_types::Read::Present { value } => value,
        se_types::Read::Absent { .. } => return Ok(None),
        se_types::Read::Unreadable { reason, .. } => {
            return Err(se_core::scope::unreadable("state store", &reason));
        }
        se_types::Read::Unknown { what } => {
            return Err(se_core::scope::unreadable("state store", &what));
        }
    };
    let info = reader.info().map_err(store)?;
    let next = match reader.runtime_owner().map_err(store)? {
        se_types::Read::Present { value } => value.generation.get().saturating_add(1),
        se_types::Read::Absent { .. } => 1,
        se_types::Read::Unreadable { reason, .. } => {
            return Err(se_core::scope::unreadable("runtime owner", &reason));
        }
        se_types::Read::Unknown { what } => {
            return Err(se_core::scope::unreadable("runtime owner", &what));
        }
    };
    Ok(Some((info, next)))
}
