//! Verify the exact committed capture range through a fresh native file pin.
use super::*;
use sha2::{Digest, Sha256};

pub(super) fn observe(plan: &mut AgentObservationPlan, deadline: Instant) -> Result<()> {
    let target = plan
        .identity
        .as_ref()
        .ok_or_else(|| invalid("a launched session target"))?;
    let verified = match &plan.capture {
        Read::Present { value } => verify(value, deadline),
        Read::Absent { checked } => Err(invalid(checked)),
        Read::Unknown { what } => Err(invalid(what)),
        Read::Unreadable { reason, .. } => Err(invalid(reason)),
    };
    match verified {
        Ok(()) => {
            plan.row.conversation.state = "verified".into();
            let stopped = plan.row.session.state == "stopped";
            plan.row.resume.ready = stopped;
            plan.row.resume.mode = "resume".into();
            plan.row.resume.reason = if stopped {
                None
            } else {
                Some("The captured conversation prefix is verified; stop or reconcile the existing scope before resuming its saved conversation.".into())
            };
            plan.row.resume.command = Some(format!("se launch {} --detach", target.agent));
            plan.row.resume.argv = Some(vec![
                "se".into(),
                "launch".into(),
                target.agent.to_string(),
                "--detach".into(),
            ]);
        }
        Err(error) => {
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
    let path = evidence.path.to_local()?;
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
