//! Public linked-host controls shared with the embedded consumer; no crate internals.
#![allow(dead_code, reason = "shared linked boundary helpers")]
use secode_stateengine_api as api;
use sha2::{Digest, Sha256};
use std::{future::Future, path::Path, pin::Pin, sync::Arc, time::Duration};
#[derive(Debug, Default)]
pub struct NoopCancellation;
impl api::Cancellation for NoopCancellation {
    fn is_cancelled(&self) -> bool {
        false
    }
    fn cancelled(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(std::future::pending())
    }
}
pub fn call_options(generation: api::Generation, timeout: Duration) -> api::CallOptions {
    api::CallOptions {
        generation,
        timeout,
        cancellation: Arc::new(NoopCancellation),
    }
}

/// SE Code's service half of the integration. This judge targets the engine
/// side of the linked boundary; services are driven by the product consumer
/// judge, so every method refuses by name instead of inventing an outcome.
pub struct SilentServices;
fn services_refused() -> api::ApiError {
    api::ApiError {
        kind: api::ApiFailure::NotIncluded,
        code: "judge-services".into(),
        message: "the host-level judge does not exercise SE Code services".into(),
        remedy: api::ApiRemedy {
            text: "Drive services through the product consumer judge.".into(),
            command: None,
        },
        retry: api::ApiRetry::Never,
    }
}
impl api::HostServices for SilentServices {
    fn hold<'a>(
        &'a self,
        _target: &'a api::HostSessionTarget,
        _reason: api::HoldReason,
        _key: api::IdempotencyKey,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::HoldReceipt> {
        Box::pin(async { Err(services_refused()) })
    }
    fn interrupt<'a>(
        &'a self,
        _held: &'a api::HoldReceipt,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::InterruptReceipt> {
        Box::pin(async { Err(services_refused()) })
    }
    fn active_session<'a>(
        &'a self,
        _target: &'a api::HostSessionTarget,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<Option<api::ActiveSession>>> {
        Box::pin(async { Err(services_refused()) })
    }
    fn active_sessions<'a>(
        &'a self,
        _epoch: &'a api::HostEpoch,
        _page: api::PageRequest,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::Page<api::ActiveSession>>> {
        Box::pin(async { Err(services_refused()) })
    }
    fn idle<'a>(
        &'a self,
        _target: &'a api::HostSessionTarget,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::SessionActivity>> {
        Box::pin(async { Err(services_refused()) })
    }
    fn binding_state<'a>(
        &'a self,
        _target: &'a api::HostSessionTarget,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::BindingObservation>> {
        Box::pin(async { Err(services_refused()) })
    }
    fn adopt_binding<'a>(
        &'a self,
        _request: api::AdoptBinding,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::BindingObservation>> {
        Box::pin(async { Err(services_refused()) })
    }
    fn update_mail_target<'a>(
        &'a self,
        _transition: api::TargetTransition,
        _key: api::IdempotencyKey,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::TargetReceipt> {
        Box::pin(async { Err(services_refused()) })
    }
    fn deliver_notice<'a>(
        &'a self,
        _notice: &'a api::MailNotice,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::NoticeAdmission> {
        Box::pin(async { Err(services_refused()) })
    }
    fn notice_status<'a>(
        &'a self,
        _target: &'a api::HostSessionTarget,
        _notice: &'a api::NoticeId,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::NoticeAdmission>> {
        Box::pin(async { Err(services_refused()) })
    }
}

/// The epoch of this exact judge process at `generation`, observed through the
/// same public native facts the embedded host verifies against.
pub fn build_epoch(generation: u64, home: &Path) -> Result<api::HostEpoch, String> {
    let files =
        se_host::state_files::Files::open(home).map_err(|e| format!("state files: {e:?}"))?;
    let machine = se_host::state_files::machine_identity(&files)
        .map_err(|e| format!("machine identity: {e}"))?;
    #[cfg(any(target_os = "linux", windows))]
    let boot = se_proc::current_runtime_identity(machine.clone())
        .map_err(|e| format!("runtime identity: {e:?}"))?
        .boot_id;
    #[cfg(target_os = "macos")]
    let boot = se_proc::observe_boot_id().map_err(|e| format!("boot identity: {e:?}"))?;
    // This debug judge binary is ~150 MiB and the workspace SHA-256 is
    // software-only on the shared box, so the one-time self-proof hash needs
    // more than the 5 s default proof bound (measured: a 28 MiB probe hashes
    // in ~2.3 s of user CPU, i.e. ~12 s for this binary). The bound is a
    // latency guard, not the integrity check: the full executable hash is
    // still computed and verified, just on a harness-sized budget.
    let bound = se_proc::native_ipc::IpcIoBound {
        deadline: std::time::Instant::now() + Duration::from_secs(120),
        cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let peer = se_proc::native_ipc::observe_ipc_self_bounded(&bound)
        .map_err(|e| format!("native self proof: {e:?}"))?;
    let pid = std::num::NonZeroU32::new(peer.pid()).ok_or("the judge process has a zero pid")?;
    let owner = se_types::ProcessInstance::from_observation(se_types::ProcessFields {
        machine,
        boot,
        pid,
        started: peer.started().clone(),
        executable: peer.image().clone(),
        argv_sha256: argv_digest(),
    })
    .map_err(|e| format!("process observation: {e}"))?;
    peer.verify_instance(&owner, peer.image_sha256())
        .map_err(|e| format!("instance verification: {e}"))?;
    let core = se_types::HostEpoch {
        owner,
        generation: se_types::HostGeneration::new(generation)
            .map_err(|e| format!("host generation: {e}"))?,
    };
    se_host::linked::host_epoch(&core).map_err(|e| format!("linked epoch: {e}"))
}
/// Length-prefixed native argv bytes, the same digest the standalone child uses.
fn argv_digest() -> se_types::Sha256 {
    #[cfg(windows)]
    use std::os::windows::ffi::OsStrExt;
    let mut hasher = Sha256::new();
    for arg in std::env::args_os() {
        #[cfg(unix)]
        let bytes = arg.as_encoded_bytes().to_vec();
        #[cfg(not(unix))]
        let bytes: Vec<u8> = arg.encode_wide().flat_map(u16::to_le_bytes).collect();
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    se_types::Sha256::from_bytes(hasher.finalize().into())
}
