//! Narrow host port trait and small crate-local runtime adapters for SE Code services.
use crate::{Prepared, Service, Services};
use se_harness::{Deadline, ProviderIoPlatform, SessionIdentity, secode_process::SecodeHarness};
use se_proc::{ExitNotice, ExitSink, NativeProcessRuntime, StateFileError};
use se_store::{Admission, CommitReceipt, SqliteSnapshot, StoreDetail, StoreError, StoreErrorCode};
use se_types::{Read, Remedy, Result, Retry};
use std::{
    future::Future,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

pub type PortFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Host-supplied runtime, store, and rebind capabilities required by SE Code service management.
pub trait HostPort: Send + Sync {
    fn services(&self) -> &Services;
    fn native(&self) -> &Arc<NativeProcessRuntime>;
    fn io(&self) -> &Arc<dyn ProviderIoPlatform>;
    fn secode_harness(&self) -> &Arc<SecodeHarness>;
    fn owner(&self) -> &se_proc::ProcessIdentity;
    fn host_id(&self) -> se_proc::HostInstanceId;
    fn home(&self) -> &Path;
    fn epoch(&self) -> &se_types::HostEpoch;
    fn generation(&self) -> se_types::Generation;
    fn configuration(&self) -> &se_config::config_policy::ConfigFile;
    fn configuration_file(&self) -> Option<&Path>;
    fn http_port(&self) -> u16;
    fn maximum_sessions(&self) -> u32;
    fn runtime_handle(&self) -> tokio::runtime::Handle;

    fn run_blocking<'a, T: Send + 'static>(
        &'a self,
        deadline: &'a Deadline,
        op: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> PortFuture<'a, T>;

    fn store_read<'a, T: Send + 'static>(
        &'a self,
        admission: Admission,
        deadline: &'a Deadline,
        op: impl FnOnce(&mut se_core::commit::Cx<'_, SqliteSnapshot>) -> Result<T> + Send + 'static,
    ) -> PortFuture<'a, T>;

    fn commit_step<'a, O: Send + 'static, T: Send + 'static>(
        &'a self,
        admission: Admission,
        deadline: &'a Deadline,
        plan: impl FnOnce(
            &se_core::dispatch::Kernel,
            &mut se_core::commit::Cx<'_, SqliteSnapshot>,
        ) -> Result<se_core::commit::OpStep<O, T>>
        + Send
        + 'static,
        finish: impl FnOnce(
            &se_core::dispatch::Kernel,
            &mut se_core::commit::Cx<'_, SqliteSnapshot>,
            T,
            CommitReceipt,
        ) -> Result<O>
        + Send
        + 'static,
    ) -> PortFuture<'a, O>;

    fn resolve_secode_provider<'a>(&'a self, deadline: &'a Deadline) -> PortFuture<'a, PathBuf>;

    fn saved_session_capability<'a>(
        &'a self,
        profile: PathBuf,
        policy_hash: Option<se_types::Sha256>,
        expected: SessionIdentity,
        deadline: &'a Deadline,
    ) -> PortFuture<'a, se_types::Secret>;

    fn is_job_unsettled(
        &self,
        project: &se_types::ProjectId,
        agent: &se_types::AgentId,
    ) -> Result<bool>;

    fn mark_job_mail_pending(
        &self,
        project: &se_types::ProjectId,
        agent: &se_types::AgentId,
    ) -> Result<()>;

    fn observe_client_stream(
        &self,
        project: &se_types::ProjectId,
        agent: &se_types::AgentId,
    ) -> Result<Read<String>>;

    fn adopt_restart<'a>(
        &'a self,
        service: &'a mut Service,
        deadline: &'a Deadline,
    ) -> PortFuture<'a, ()>;

    fn restore_restart_state<'a>(
        &'a self,
        service: &'a mut Service,
        deadline: &'a Deadline,
    ) -> PortFuture<'a, ()>;

    fn verify_captured_end<'a>(
        &'a self,
        admission: Admission,
        source: se_store::RecordId,
        end: u64,
        deadline: &'a Deadline,
    ) -> PortFuture<'a, ()>;

    fn native_instance(
        &self,
        root: &se_proc::ProcessIdentity,
        argv: [u8; 32],
        boot: &se_types::BootId,
    ) -> Result<se_types::ProcessInstance>;
}

/// Host-owned lifecycle work state accessed by SE Code service operations.
pub trait SecodeWork: Send {
    fn project_id(&self) -> &se_types::ProjectId;
    fn agent_id(&self) -> &se_types::AgentId;
    fn owner(&self) -> &se_types::HumanId;
    fn session(&self) -> &se_types::SessionId;
    fn lifecycle(&self) -> &se_types::LifecycleId;
    fn provider(&self) -> se_store::Provider;
    fn capture_enabled(&self) -> bool;
    fn conversation(&self) -> &se_types::Read<se_types::ProviderSessionId>;
    fn set_conversation(&mut self, conversation: se_types::Read<se_types::ProviderSessionId>);
    fn cleanup_admission(&self) -> &Admission;
    fn secode(&self) -> Option<&Prepared>;
    fn secode_mut(&mut self) -> &mut Option<Prepared>;
    fn binding_mut(&mut self) -> &mut Option<se_harness::HarnessBinding>;
    fn secode_service_lost(&self) -> bool;
    fn set_secode_service_lost(&mut self, lost: bool);
    fn capture_source(&self) -> Option<se_store::RecordId>;
    fn set_capture_source(&mut self, source: Option<se_store::RecordId>);
    fn set_last_capture(&mut self, event: Option<se_types::EventId>);
    fn capture_failure(&self) -> Option<&se_types::ErrorBody>;
    fn set_capture_failure(&mut self, failure: Option<se_types::ErrorBody>);
    fn capture_flushed(&self) -> bool;
    fn set_capture_flushed(&mut self, flushed: bool);
    fn set_model(&mut self, model: Option<String>);
    fn process_retired(&self) -> bool;
    fn native_already_reconciled(&self) -> bool;
    fn session_retired(&self) -> bool;
    fn credentials_revoked(&self) -> bool;
    fn active(&self) -> bool;
    fn set_active(&mut self, active: bool);
    fn activated(&self) -> bool;
    fn stop_key(&self) -> Option<&se_types::IdempotencyKey>;
    fn mail_in_flight(&self) -> bool;
    fn nudge_secode_completion(&self);
    fn report_mail_diagnostic(&self, failure: &se_types::SeError);
}

pub(crate) fn error(subject: &str, cause: impl std::fmt::Debug) -> se_types::SeError {
    se_core::scope::unreadable(subject, &format!("{cause:?}"))
}

pub(crate) fn prepare_error(e: se_proc::ProcError) -> se_types::SeError {
    let missing_root = matches!(
        e.detail.as_ref(),
        se_proc::ProcErrorDetail::Input { field, reason }
            if e.code == se_proc::ProcErrorCode::LaunchFailed
                && field == "native operation"
                && reason == "resolve cwd"
                && e.native
                    .as_ref()
                    .is_some_and(|n| n.api == "resolve cwd" && n.code == Some(2))
    );
    if missing_root {
        return se_types::SeError::new(se_types::Detail::SourceUnreadable(
            se_types::details::SourceUnreadable {
                subject: "native scope preparation".into(),
                reason: format!("the recorded project root is missing: {e:?}"),
                next_step: "If the repository was renamed or moved, run `se project move <new-folder>` (it verifies the recorded git identity) and retry; otherwise restore the folder at the recorded path and retry.".into(),
            },
        ));
    }
    error("native scope preparation", e)
}

pub(crate) fn retain_recovery_artifact(path: &Path) -> Result<bool> {
    if !path
        .file_name()
        .is_some_and(se_proc::NativeStateFiles::is_recovery_artifact)
    {
        return Ok(false);
    }
    se_proc::OwnedFile::open(path)
        .map_err(|e| error("retained native recovery artifact", e))?
        .ok_or_else(|| {
            error(
                "retained native recovery artifact",
                "listed file disappeared",
            )
        })?
        .read(1024 * 1024)
        .map_err(|e| error("retained native recovery artifact", e))?;
    Ok(true)
}

pub(crate) fn allocate_facts() -> Result<se_core::dispatch::CallFacts> {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| se_core::scope::unreadable("system clock", &e.to_string()))?;
    let mut random = [0; 60];
    se_proc::fill_entropy(&mut random)
        .map_err(|e| se_core::scope::unreadable("host identity entropy", &e.to_string()))?;
    let chunk = |start: usize| {
        let mut out = [0; 10];
        out.copy_from_slice(&random[start..start + 10]);
        out
    };
    let ms = time.as_millis() as u64;
    Ok(se_core::dispatch::CallFacts {
        event: se_types::EventId::from_parts(ms, chunk(0))?,
        message: se_types::MessageId::from_parts(ms, chunk(10))?,
        agent: se_types::AgentId::from_parts(ms, chunk(20))?,
        profile_event: se_types::EventId::from_parts(ms, chunk(30))?,
        notification_event: se_types::EventId::from_parts(ms, chunk(40))?,
        notification_message: se_types::MessageId::from_parts(ms, chunk(50))?,
        occurred_at_us: i64::try_from(time.as_micros()).map_err(|_| {
            se_types::SeError::invalid("system clock", "representable microseconds")
        })?,
        door: se_store::Door::Host,
    })
}

pub(crate) fn call_context(
    generation: se_types::Generation,
    deadline: &Deadline,
) -> Result<se_harness::CallContext> {
    Ok(se_harness::CallContext {
        generation,
        timeout: deadline.remaining()?,
        cancellation: Arc::new(se_harness::CancellationState { _private: () }),
    })
}

#[derive(Default)]
pub(crate) struct Wake {
    event: Arc<tokio::sync::Notify>,
}

impl ExitSink for Wake {
    fn notify(&self, _notice: ExitNotice) {
        self.event.notify_waiters();
        self.event.notify_one();
    }
}

pub(crate) async fn wait_wake(wake: &Wake, deadline: &Deadline) -> Result<()> {
    tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline.at()),
        wake.event.notified(),
    )
    .await
    .map_err(|_| {
        se_core::scope::unreadable(
            "native process wait",
            "original launch/stop deadline expired; native custody is retained",
        )
    })?;
    deadline.remaining()?;
    Ok(())
}

pub(crate) struct AcquisitionError {
    error: StateFileError,
    waited: Duration,
}

impl AcquisitionError {
    pub(crate) fn into_public(
        self,
        fallback: impl FnOnce(StateFileError) -> se_types::SeError,
    ) -> se_types::SeError {
        if !self.error.is_contended() {
            return fallback(self.error);
        }
        let store = StoreError {
            code: StoreErrorCode::Busy,
            cause: format!("Native file acquisition remains contended: {}", self.error),
            detail: StoreDetail::NativeContention {
                waited_ms: self.waited.as_millis().try_into().unwrap_or(u64::MAX),
            },
            remedy: Remedy {
                text: "Wait for the current file operation to finish, reread the protected state, then retry the same request; preserve the existing files.".into(),
                command: None,
            },
            retry: Retry::AfterReread,
        };
        se_core::store_error::store_error(&store)
    }
}

pub(crate) struct AcquisitionRetry {
    deadline: Instant,
    started: Instant,
    contended: Option<StateFileError>,
}

pub(crate) enum Acquisition<T> {
    Ready(T),
    Wait(Duration),
}

impl AcquisitionRetry {
    pub(crate) fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            started: Instant::now(),
            contended: None,
        }
    }

    pub(crate) fn acquire<T>(
        &mut self,
        acquire: impl FnOnce() -> std::result::Result<T, StateFileError>,
    ) -> std::result::Result<Acquisition<T>, AcquisitionError> {
        let failed = |error| AcquisitionError {
            error,
            waited: self.started.elapsed(),
        };
        if Instant::now() >= self.deadline
            && let Some(error) = self.contended.take()
        {
            return Err(failed(error));
        }
        match acquire() {
            Ok(value) => Ok(Acquisition::Ready(value)),
            Err(error) if error.is_contended() => {
                let remaining = self.deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(failed(error));
                }
                self.contended = Some(error);
                Ok(Acquisition::Wait(remaining.min(Duration::from_millis(10))))
            }
            Err(error) => Err(failed(error)),
        }
    }
}
