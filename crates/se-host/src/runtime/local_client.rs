//! The local connector preserves native human admission; it creates no device grant.
use super::*;
use crate::client::lease::Deadline;
use se_core::ops::{AnyOp, Validate};
use se_types::{Result, SeError};

pub(super) async fn watch(
    router: &HostedRouter,
    call: HostedCall,
    deadline: &Deadline,
) -> Result<ExecutedCall> {
    let HostedInput::Operation(AnyOp::ClientWatch(input)) = call.input else {
        return Err(SeError::invalid(
            "local client",
            "the closed local watch request",
        ));
    };
    input.validate()?;
    if call.admission.generation != router.execution.generation.get() {
        return Err(SeError::invalid(
            "local client",
            "this admitted host generation",
        ));
    }
    se_core::admission::authorize(AnyOp::ClientWatch(input.clone()).meta(), &call.admission)?;
    #[cfg(feature = "remote")]
    {
        let output = crate::remote::control::Control::local_watch(
            router,
            call.admission,
            input.request,
            input.wait_ms,
            deadline,
        )
        .await?;
        Ok(ExecutedCall {
            host_phases: Default::default(),
            output: output.body.into(),
            write_timings: None,
            committed: None,
            capture_commits: vec![],
            capture_keys: vec![],
        })
    }
    #[cfg(not(feature = "remote"))]
    {
        let _ = deadline;
        Err(SeError::invalid(
            "local client",
            "an installed release with the optional native client enabled",
        ))
    }
}
