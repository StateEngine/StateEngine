//! Atlas has one compact representation by default; JSON is explicit.
use super::*;
use se_types::code::AtlasFormat;
pub(super) async fn call(
    backend: &mut impl McpBackend,
    capability: Arc<Secret>,
    id: Value,
    operation: se_core::ops::AnyOp,
) -> Value {
    let Some(options) = operation.atlas_options() else {
        return rpc_error(id, -32603, "Atlas operation required");
    };
    let expected = operation.meta().family;
    let format = options.format;
    let explain = options.explain;
    let limit = (options.byte_budget as usize).min(backend.response_limit());
    let outcome = backend.call(capability, operation).await;
    let result = match outcome {
        Ok(value) => {
            let output = match serde_json::from_value::<se_core::ops::AnyOutput>(value.clone()) {
                Ok(output) => output,
                Err(_) => {
                    return rpc_error(
                        id,
                        -32603,
                        "Atlas backend returned an invalid typed output family",
                    );
                }
            };
            if output.family() == expected {
                let text = if format == AtlasFormat::Json {
                    Ok(value.to_string())
                } else {
                    crate::atlas_queries::compact(&output, limit.saturating_sub(256), explain)
                        .and_then(|text| {
                            text.ok_or_else(|| {
                                SeError::invalid(
                                    "Atlas compact output",
                                    "the requested Atlas family",
                                )
                            })
                        })
                };
                match text {
                    Ok(text) => json!({"content":[{"type":"text","text":text}],"isError":false}),
                    Err(error) => return failure(id, &error, limit),
                }
            } else {
                return rpc_error(
                    id,
                    -32603,
                    "Atlas backend returned a different operation family",
                );
            }
        }
        Err(error) => return failure(id, &error, limit),
    };
    let response = success(id, result);
    if serde_json::to_vec(&response).is_ok_and(|bytes| bytes.len() <= limit) {
        response
    } else {
        rpc_error(
            Value::Null,
            -32602,
            "Atlas response exceeds the requested wire budget; narrow the query or increase byte_budget (at most 32768)",
        )
    }
}
fn failure(id: Value, error: &SeError, limit: usize) -> Value {
    let response = match error_value(error) {
        Ok(value) => success(
            id,
            json!({"content":[{"type":"text","text":value.to_string()}],"isError":true}),
        ),
        Err(_) => rpc_error(id, -32603, "Atlas error encoding failed"),
    };
    if serde_json::to_vec(&response).is_ok_and(|bytes| bytes.len() <= limit) {
        response
    } else {
        rpc_error(
            Value::Null,
            -32602,
            "Atlas error exceeds the requested wire budget; retry with a larger byte_budget",
        )
    }
}
