//! Native source admission has finished before the broker awaits any network.
use super::*;
use crate::remote::broker::RemoteBroker;
use se_types::{Result, SeError};
use std::sync::Arc;
#[cfg(feature = "remote")]
mod setup;
impl HostedRuntime {
    /// Integration installs only native-guarded bindings and protected signers.
    /// Ordinary/disabled hosts leave this slot empty and start no remote work.
    pub fn install_remote_broker(&self, broker: Arc<RemoteBroker>) -> Result<()> {
        self.execution.mail_waits.install_remote(broker)
    }
}
pub(super) async fn execute(
    context: &ExecutionContext,
    call: HostedCall,
    deadline: &crate::client::lease::Deadline,
) -> Result<ExecutedCall> {
    let HostedInput::Operation(operation) = call.input else {
        return Err(SeError::invalid(
            "remote input",
            "a closed remote operation",
        ));
    };
    #[cfg(feature = "remote")]
    let _work = context.mail_waits.remote_work()?;
    #[cfg(feature = "remote")]
    setup::ensure(context, deadline).await?;
    let broker = context.mail_waits.remote().ok_or_else(|| {
        SeError::invalid(
            "remote binding",
            "an Owner-configured source broker; remote mode is disabled, with no Owner fallback",
        )
    })?;
    if call.admission.generation != context.generation.get() {
        return Err(SeError::invalid(
            "remote source generation",
            "the exact current source host generation",
        ));
    }
    let source = if matches!(call.admission.actor, se_store::Actor::Agent(_)) {
        let (credential, hash) = call.remote_credential.ok_or_else(|| {
            SeError::invalid(
                "remote source credential",
                "the exact native-admitted session; no human fallback",
            )
        })?;
        let source = broker.verified_source(&call.admission, credential)?;
        let expected = call.admission.clone();
        let reads = context.reads.clone();
        let generation = context.generation;
        context
            .blocking
            .run_owned(deadline, move || {
                let phase = super::executor::checked_pooled_phase(&reads, generation)?;
                let result = validate_source(&phase, &expected, credential, hash);
                super::executor::close_read(result, phase.close())
            })
            .await?;
        Some(source)
    } else {
        None
    };
    let key = operation.idempotency_key().map(ToString::to_string);
    let timeout = deadline.remaining()?;
    let output = tokio::time::timeout(
        timeout,
        broker.execute(operation, &call.admission, &call.terminal, source, deadline),
    )
    .await
    .map_err(|_| {
        let mut error = if key.is_some() {
            SeError::new(se_types::Detail::CommitOutcomeUnknown(
                se_types::details::CommitOutcomeUnknown {
                    operation: "remote.send".into(),
                    key,
                    natural_events: vec![],
                },
            ))
        } else {
            SeError::new(se_types::Detail::DeadlineExceeded(
                se_types::details::DeadlineExceeded {
                    op: "remote read".into(),
                    deadline_ms: timeout.as_millis().min(u128::from(u64::MAX)) as u64,
                },
            ))
        };
        error.body = error.body.with_retry(se_types::Retry::AfterReread);
        error
    })??;
    Ok(ExecutedCall {
        host_phases: Default::default(),
        output,
        write_timings: None,
        committed: None,
        capture_commits: vec![],
        capture_keys: vec![],
    })
}

pub(super) fn validate_source(
    phase: &se_store::ReadPhase,
    expected: &se_store::Admission,
    credential: se_store::RecordId,
    hash: [u8; 32],
) -> Result<()> {
    use se_core::store_error::store_error;
    let record = se_core::scope::require_present(
        phase.credential(hash).map_err(|e| store_error(&e))?,
        "remote source credential",
        "Reconnect through a current launched session; no human fallback.",
    )?;
    let now = super::start::now_unix_micros()?;
    let current = record.credential == credential
        && record.state == se_store::CredentialState::Active
        && record.expires_at_us > now
        && expected.session.as_ref() == Some(&record.session)
        && expected.scope == se_store::Scope::Project(record.project)
        && expected.actor == se_store::Actor::Agent(record.agent)
        && !phase
            .credential_superseded(hash)
            .map_err(|e| store_error(&e))?
        && !phase
            .credential_stop_unproved(hash)
            .map_err(|e| store_error(&e))?;
    if !current {
        return Err(SeError::invalid(
            "remote source credential",
            "the same active non-superseded source session/generation after fence registration",
        ));
    }
    Ok(())
}
