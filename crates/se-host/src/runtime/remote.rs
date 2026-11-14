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
    let mut operation = operation;
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
    let source = admit_source(
        context,
        broker,
        &call.admission,
        call.remote_credential,
        deadline,
    )
    .await?;
    #[cfg(feature = "remote")]
    if let Some(source) = &source {
        // Reconnects that first list or watch must also resume saved return mail.
        let _retained_status = broker.start_mail(context, source.clone()).await?;
    }
    #[cfg(feature = "remote")]
    if let (Some(source), se_core::ops::AnyOp::RemoteSend(input)) = (&source, &mut operation) {
        broker
            .prepare_contact(context, source, input, &call.terminal, deadline)
            .await?;
    }
    let key = operation.idempotency_key().map(ToString::to_string);
    #[cfg(feature = "remote")]
    let outgoing = match &operation {
        se_core::ops::AnyOp::RemoteSend(input) => Some(input.clone()),
        _ => None,
    };
    #[cfg(feature = "remote")]
    let mailing_source = source.clone();
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
    #[cfg(feature = "remote")]
    if let (Some(input), Some(source), se_core::ops::AnyOutput::RemoteSend(result)) =
        (outgoing, mailing_source, &output)
    {
        broker
            .remember_send(context, &source, &input, &result.value)
            .await
            .map_err(|cause| {
                SeError::new(se_types::Detail::CommitOutcomeUnknown(
                    se_types::details::CommitOutcomeUnknown {
                        operation: "remote.send".into(),
                        key: Some(input.request.idempotency_key.to_string()),
                        natural_events: Vec::new(),
                    },
                ))
                .with_cause(cause)
            })?;
    }
    Ok(ExecutedCall {
        host_phases: Default::default(),
        output,
        write_timings: None,
        committed: None,
        capture_commits: vec![],
        capture_keys: vec![],
    })
}

#[cfg(feature = "remote")]
pub(super) async fn resume_mail(
    context: &ExecutionContext,
    call: &HostedCall,
    deadline: &crate::client::lease::Deadline,
) -> Result<()> {
    if !context.mail_waits.has_return_mail()
        || !matches!(call.admission.actor, se_store::Actor::Agent(_))
    {
        return Ok(());
    }
    setup::ensure(context, deadline).await?;
    let broker = context
        .mail_waits
        .remote()
        .ok_or_else(|| SeError::invalid("return mail", "the original saved source binding"))?;
    let (credential, hash) = call.remote_credential.ok_or_else(|| {
        SeError::invalid(
            "return mail",
            "a current native-admitted source agent session",
        )
    })?;
    let source = broker.verified_source(&call.admission, credential)?;
    let reads = context.reads.clone();
    let generation = context.generation;
    let admission = call.admission.clone();
    context
        .blocking
        .run_owned(deadline, move || {
            let phase = super::executor::checked_pooled_phase(&reads, generation)?;
            let result = validate_source(&phase, &admission, credential, hash);
            super::executor::close_read(result, phase.close())
        })
        .await?;
    broker
        .start_mail(context, source)
        .await?
        .map_or(Ok(()), |body| Err(body.into()))
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

async fn admit_source(
    context: &ExecutionContext,
    broker: &Arc<RemoteBroker>,
    admission: &se_store::Admission,
    credential: Option<(se_store::RecordId, [u8; 32])>,
    deadline: &crate::client::lease::Deadline,
) -> Result<Option<crate::remote::broker::VerifiedSourceSession>> {
    if admission.generation != context.generation.get() {
        return Err(SeError::invalid(
            "remote source generation",
            "the exact current source host generation",
        ));
    }
    if matches!(admission.actor, se_store::Actor::Agent(_)) {
        let (credential, hash) = credential.ok_or_else(|| {
            SeError::invalid(
                "remote source credential",
                "the exact native-admitted session; no human fallback",
            )
        })?;
        let source = broker.verified_source(admission, credential)?;
        let expected = admission.clone();
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
        Ok(Some(source))
    } else {
        Ok(None)
    }
}
