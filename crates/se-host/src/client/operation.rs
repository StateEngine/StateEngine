//! Closed operation encoding and error preservation at the native client boundary.
use crate::{IpcEnvelope, IpcRequest, OperationOutput, RawOperation};
use se_core::ops::{AnyOp, AnyOutput, CliSelections};
use se_types::{Detail, Result, SeError, details};

/// The complete closed input, including its original request key, is unchanged.
/// CLI route metadata is encoded separately and must be admitted by the host.
pub fn operation(
    op: AnyOp,
    selections: &CliSelections,
    generation: se_types::Generation,
) -> Result<IpcEnvelope> {
    op.validate()?;
    selections.validate()?;
    let name = op.meta().name.to_owned();
    let launch = matches!(op, AnyOp::AgentLaunch(_));
    let key = op.idempotency_key().cloned();
    let mut encoded = serde_json::to_value(op).map_err(|_| invalid("serializable closed input"))?;
    let arguments = encoded
        .get_mut("input")
        .map(serde_json::Value::take)
        .ok_or_else(|| invalid("registered operation input"))?;
    Ok(IpcEnvelope {
        version: se_types::API_VERSION,
        // Each forward owns a fresh connection and exactly one call.
        request_id: 1,
        generation,
        authority: None,
        presence: None,
        cli_selections: Some({
            let mut encoded = serde_json::to_value(selections)
                .map_err(|_| invalid("serializable CLI routing metadata"))?;
            if launch {
                crate::launch_sign_in::attach(&mut encoded);
            }
            encoded
        }),
        request: IpcRequest::Operation(RawOperation {
            name,
            arguments,
            key,
        }),
    })
}

/// `value` is the complete core family envelope. The host never strips its
/// read/window/completeness facts or synthesizes a different family at this seam.
pub fn decode(output: OperationOutput, expected: &str) -> Result<AnyOutput> {
    if output.schema != expected {
        return Err(invalid("the registered operation's output family"));
    }
    let decoded: AnyOutput = serde_json::from_value(output.value)
        .map_err(|_| invalid("a complete closed core family output"))?;
    if decoded.family().schema() != expected {
        return Err(invalid("matching transport and core output families"));
    }
    Ok(decoded)
}
pub fn uncertain(keyed: Option<&(String, se_types::IdempotencyKey)>, error: SeError) -> SeError {
    match keyed {
        Some((operation, key)) => {
            let mut unknown = SeError::new(Detail::CommitOutcomeUnknown(
                details::CommitOutcomeUnknown {
                    operation: operation.clone(),
                    key: Some(key.to_string()),
                    natural_events: Vec::new(),
                },
            ));
            // Preserve the safe public transport/decode refusal in both human
            // and JSON output. Arbitrary internal source chains stay private.
            let mut remedy = unknown.body.remedy(&se_types::RenderCx::default())
                .unwrap_or_else(|failure| se_types::Remedy {
                    text: format!("Retry the original request key; its recovery advice could not be rendered: {failure}"),
                    command: None,
                });
            remedy.text = format!(
                "Cause [{}]: {}. {}",
                error.code().as_str(),
                error.body.message(),
                remedy.text
            );
            unknown.body = unknown.body.with_remedy(remedy);
            if operation.starts_with("remote.") || operation == "remote authority control" {
                unknown.body = unknown.body.with_retry(se_types::Retry::AfterReread);
            }
            unknown.with_cause(error)
        }
        None => error,
    }
}

fn invalid(expected: &str) -> SeError {
    SeError::invalid("CLI IPC", expected)
}
