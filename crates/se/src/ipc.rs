//! One synchronous call through the authenticated native client. Connection loss
//! is returned to the caller with its existing operation key; this layer retries nothing.
use se_core::ops::{AnyOp, AnyOutput, CliSelections};
use se_host::{
    EndpointRecord, IpcEnvelope, IpcRequest, OperationOutput, RawOperation,
    client::{
        BlockingIpcClient, ClientOptions, lease::ClientCredential, wire::DEFAULT_REPLY_BYTES,
    },
};
use se_types::{Detail, Result, SeError, details};
use std::{num::NonZeroU32, time::Instant};

pub fn forward(
    endpoint: &EndpointRecord,
    credential: ClientCredential,
    op: AnyOp,
    selections: &CliSelections,
    options: &ClientOptions,
) -> Result<AnyOutput> {
    let expected = op.meta().family.schema();
    let call = operation(op, selections, endpoint.generation)?;
    exchange(endpoint, credential, call, &expected, options)
}

/// Hooks use their closed native request branch with no CLI scope metadata and
/// no direct-write fallback. The caller retains its source's natural identity.
pub fn forward_hook(
    endpoint: &EndpointRecord,
    credential: ClientCredential,
    hook: se_host::ClaudeHookInput,
    options: &ClientOptions,
) -> Result<AnyOutput> {
    exchange(
        endpoint,
        credential,
        IpcEnvelope {
            version: se_types::API_VERSION,
            request_id: 1,
            generation: endpoint.generation,
            authority: None,
            cli_selections: None,
            request: IpcRequest::Hook(hook),
        },
        &se_core::ops::HookClaude::META.family.schema(),
        options,
    )
}
fn exchange(
    endpoint: &EndpointRecord,
    credential: ClientCredential,
    call: IpcEnvelope,
    expected: &str,
    options: &ClientOptions,
) -> Result<AnyOutput> {
    let started = Instant::now();
    let mut connection = BlockingIpcClient::connect_authenticated(
        endpoint,
        credential,
        NonZeroU32::new(DEFAULT_REPLY_BYTES).ok_or_else(|| invalid("nonzero reply budget"))?,
        options,
    )?;
    // Authentication and exchange consume one caller budget, including discovery
    // already charged by the route. A new connection never renews that budget.
    let remaining = options
        .timeout
        .min(se_host::client::lease::CALL_TIMEOUT)
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| {
            SeError::new(Detail::DeadlineExceeded(details::DeadlineExceeded {
                op: call_operation(&call).into(),
                deadline_ms: options.timeout.as_millis().min(u128::from(u64::MAX)) as u64,
            }))
        })?;
    let exchange_options = ClientOptions {
        expected_generation: Some(endpoint.generation),
        timeout: remaining,
        cancelled: options.cancelled.clone(),
    };
    let output = connection.exchange(call, &exchange_options)?;
    decode(output, expected)
}

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
        cli_selections: Some(
            serde_json::to_value(selections)
                .map_err(|_| invalid("serializable CLI routing metadata"))?,
        ),
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
fn call_operation(call: &IpcEnvelope) -> &str {
    match &call.request {
        IpcRequest::Operation(op) => &op.name,
        IpcRequest::Hook(_) => "hook.claude",
    }
}
fn invalid(expected: &str) -> SeError {
    SeError::invalid("CLI IPC", expected)
}
