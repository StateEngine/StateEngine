//! Verify the exact committed capture range through a fresh native file pin.
use super::*;
use sha2::{Digest, Sha256};

pub(super) fn observe(plan: &mut AgentObservationPlan, deadline: Instant) -> Result<()> {
    if plan.row.provider == se_types::Provider::SeCode {
        // This provider's canonical source is authenticated HTTP, not a file.
        // Current service facts are joined by the owning runtime separately.
        plan.row.resume.ready = false;
        plan.row.resume.mode = "compatible-service-required".into();
        let mut reason = se_core::ops::AgentCommand::SECODE_RESUME_UNAVAILABLE.to_owned();
        if let Read::Unreadable {
            reason: failure, ..
        } = &plan.capture
        {
            reason.push_str(&format!(" Capture is unverified: {failure}"));
        }
        plan.row.resume.reason = Some(reason);
        plan.row.resume.command = None;
        plan.row.resume.argv = None;
        plan.row.conversation.state = "retained".into();
        return Ok(());
    }
    let target = plan
        .identity
        .as_ref()
        .ok_or_else(|| invalid("a launched session target"))?;
    let running = matches!(plan.row.session.state.as_str(), "running" | "stopping");
    plan.row.resume.mode = if running { "running" } else { "resume" }.into();
    plan.row.resume.command = None;
    plan.row.resume.argv = None;
    let verified = match &plan.capture {
        Read::Present { value } if plan.row.provider == se_types::Provider::Acp => {
            verify_acp(plan, value)
        }
        Read::Present { value } => verify(value, deadline),
        Read::Absent { checked } => Err(invalid(checked)),
        Read::Unknown { what } => Err(invalid(what)),
        Read::Unreadable { reason, .. } => Err(invalid(reason)),
    };
    match verified {
        Ok(()) => {
            plan.row.conversation.state = "saved".into();
            let stopped = plan.row.session.state == "stopped"
                && matches!(
                    plan.row.session.recorded_state.as_deref(),
                    Some("ended" | "revoked")
                )
                && matches!(&plan.row.session.process_state, Read::Present { value } if value == "exited");
            plan.row.resume.ready = stopped;
            plan.row.resume.reason = if stopped {
                None
            } else if plan.row.session.state == "stopped" {
                Some("The exact provider process exited; session or native-scope cleanup is still pending. Reconcile before resuming the saved conversation.".into())
            } else if let Read::Unreadable { reason, .. } = &plan.row.session.liveness {
                Some(reason.clone())
            } else {
                Some(if plan.row.provider==se_types::Provider::Acp { "The canonical protocol prefix is retained; stop or reconcile the existing scope before loading and verifying its saved conversation." } else { "The captured conversation prefix is verified; stop or reconcile the existing scope before resuming its saved conversation." }.into())
            };
            if stopped {
                let command = se_core::ops::AgentCommand::launch(
                    &target.agent,
                    None,
                    Some(&target.project),
                    false,
                );
                plan.row.resume.command = Some(command.command);
                plan.row.resume.argv = Some(command.argv);
            }
        }
        Err(error) => {
            if plan.row.session.state == "stopped"
                && plan.row.session.recorded_state.as_deref() == Some("activated")
            {
                plan.control_failure.get_or_insert_with(|| format!(
                    "Final transcript capture is pending: {error}. Restore the original transcript and protected binding without replacing their native identity"
                ));
            }
            plan.row.conversation.state = "unverifiable".into();
            plan.row.resume.ready = false;
            plan.row.resume.reason = Some(error.to_string());
            plan.row.resume.command = None;
            plan.row.resume.argv = None;
        }
    }
    Ok(())
}
fn verify(evidence: &SourceEvidence, deadline: Instant) -> Result<()> {
    const MAX_RANGE: u64 = 4 * 1024 * 1024;
    if evidence.length == 0 || evidence.length > MAX_RANGE {
        return Err(invalid(
            "a nonempty committed capture range within the 4 MiB native status bound",
        ));
    }
    let path = evidence
        .path
        .as_ref()
        .ok_or_else(|| invalid("native turn evidence has no provider transcript file to verify"))?
        .to_local()?;
    let mut pin = se_proc::NativeSourcePin::open(&path)
        .map_err(|e| invalid(&e.to_string()))?
        .ok_or_else(|| invalid("the original captured provider file is absent"))?;
    if evidence.incarnation.as_slice() != pin.identity() {
        return Err(invalid(
            "the original captured file incarnation; a replacement cannot verify resume",
        ));
    }
    let expected = evidence
        .sha256
        .ok_or_else(|| invalid("the committed capture range digest"))?;
    let end = evidence
        .offset
        .checked_add(evidence.length)
        .ok_or_else(|| invalid("a bounded capture offset"))?;
    let mut position = evidence.offset;
    let mut digest = Sha256::new();
    while position < end {
        bound(deadline)?;
        let chunk = pin
            .read_at(position, (end - position).min(256 * 1024) as usize)
            .map_err(|e| invalid(&e.to_string()))?;
        if chunk.bytes.is_empty() {
            return Err(invalid("the complete original captured source range"));
        }
        digest.update(&chunk.bytes);
        position = chunk.next_offset;
    }
    let actual: [u8; 32] = digest.finalize().into();
    if actual != expected {
        return Err(invalid(
            "unchanged bytes in the original committed capture range",
        ));
    }
    pin.validate_path(&path)
        .map_err(|e| invalid(&e.to_string()))?;
    bound(deadline)
}

// Structured protocol facts are committed by the owned adapter, not a vendor file.
// A later load still has to match the complete committed text before new input.
fn verify_acp(plan: &AgentObservationPlan, evidence: &SourceEvidence) -> Result<()> {
    if evidence.path.is_some() || evidence.length == 0 || evidence.sha256.is_none() {
        return Err(invalid("the original complete structured protocol range"));
    }
    let source: serde_json::Value = serde_json::from_slice(&evidence.incarnation)
        .map_err(|_| invalid("the original protocol binding"))?;
    let identity = plan
        .identity
        .as_ref()
        .ok_or_else(|| invalid("a saved protocol session"))?;
    if source["schema"] != "se.acp-completed-source/v1"
        || source["project"].as_str() != Some(identity.project.as_str())
        || source["agent"].as_str() != Some(identity.agent.as_str())
        || source["session"].as_str() != Some(identity.session.as_str())
        || source["conversation"].as_str() != plan.row.conversation.id.as_deref()
        || source["root"].is_null()
    {
        return Err(invalid(
            "the exact original protocol conversation and native instance",
        ));
    }
    Ok(())
}
