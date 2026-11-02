//! The one MCP protocol consumer (section 40 §7.3, H18), shared by the host's
//! loopback HTTP route and the CLI's stdio bridge. Each transport supplies only
//! its capability source and an `McpBackend`; JSON-RPC handling, tool
//! discovery, argument decoding, result shape and the final budget live here.
//! POST JSON semantics: no batching, SSE or server-initiated requests.
use se_types::{Result, SeError, Secret};
use serde_json::{Value, json};
use std::{future::Future, sync::Arc};

/// Protocol revisions spoken here, newest first. An unknown requested
/// revision is answered with the newest, as the MCP lifecycle prescribes.
const PROTOCOLS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];
/// JSON-RPC server-defined code for a missing or refused session capability.
const SESSION_REQUIRED: i32 = -32001;

pub enum McpReply {
    /// A complete JSON-RPC response object.
    Json(Value),
    /// A notification, or a client's response to a request: no reply body.
    Accepted,
}

/// What a transport supplies. Both methods authenticate the capability
/// themselves on every call; the consumer never caches a grant.
pub trait McpBackend {
    fn check_session(&mut self, capability: Arc<Secret>)
    -> impl Future<Output = Result<()>> + Send;
    /// Execute one core-decoded operation as the capability's bound session and
    /// return its schema-tagged output value.
    fn call(
        &mut self,
        capability: Arc<Secret>,
        operation: se_core::ops::AnyOp,
    ) -> impl Future<Output = Result<Value>> + Send;
    /// The complete JSON-RPC response budget for this transport, in bytes.
    fn response_limit(&self) -> usize;
    /// Resolve the capability for a selected tool method, after lifecycle
    /// methods were answered. `metadata` is the request's `params._meta`. The
    /// default uses the transport-supplied capability (HTTP's bearer); a
    /// transport that reads metadata must refuse a malformed explicit value
    /// rather than fall back to another identity.
    fn capability(
        &mut self,
        metadata: Option<&Value>,
        supplied: Option<Arc<Secret>>,
    ) -> Result<Option<Arc<Secret>>> {
        let _ = metadata;
        Ok(supplied)
    }
}

pub async fn dispatch(
    body: &[u8],
    capability: Option<Arc<Secret>>,
    backend: &mut impl McpBackend,
) -> McpReply {
    // The common decoder refuses duplicate keys and excessive depth before any
    // field is interpreted. Batches were removed from MCP in 2025-06-18.
    let message: Value =
        match crate::client::wire::decode_json(body, crate::client::wire::MAX_FRAME_BYTES) {
            Ok(Value::Object(message)) => Value::Object(message),
            Ok(_) => {
                return McpReply::Json(rpc_error(
                    Value::Null,
                    -32600,
                    "one JSON-RPC request object",
                ));
            }
            Err(_) => {
                return McpReply::Json(rpc_error(Value::Null, -32700, "unreadable JSON body"));
            }
        };
    if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return McpReply::Json(rpc_error(Value::Null, -32600, "jsonrpc 2.0 required"));
    }
    let Some(method) = message.get("method").and_then(Value::as_str) else {
        // A client response to a server request; this server sends none.
        return McpReply::Accepted;
    };
    let Some(id) = message.get("id").cloned().filter(valid_id) else {
        // Notifications (initialized, cancelled) carry no reply.
        return McpReply::Accepted;
    };
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    // Lifecycle methods are anonymous and open no store; every tool method
    // needs a capability the host validates on that same call.
    match method {
        "initialize" => return McpReply::Json(success(id, initialize(&params))),
        "ping" => return McpReply::Json(success(id, json!({}))),
        "tools/list" | "tools/call" => (),
        _ => return McpReply::Json(rpc_error(id, -32601, "method not found")),
    }
    let capability = match backend.capability(params.get("_meta"), capability) {
        Ok(Some(capability)) => capability,
        Ok(None) => {
            return McpReply::Json(rpc_error(
                id,
                SESSION_REQUIRED,
                "session-required: tools need the launched session's capability",
            ));
        }
        Err(error) => return McpReply::Json(rpc_error(id, SESSION_REQUIRED, &error.to_string())),
    };
    let response = if method == "tools/list" {
        match backend
            .check_session(Arc::clone(&capability))
            .await
            .and_then(|()| tools())
        {
            Ok(result) => success(id, result),
            Err(error) => rpc_error(id, SESSION_REQUIRED, &error.to_string()),
        }
    } else {
        call(backend, capability, id, &params).await
    };
    McpReply::Json(budgeted(response, backend.response_limit()))
}

fn valid_id(id: &Value) -> bool {
    matches!(id, Value::String(_)) || id.as_i64().is_some() || id.as_u64().is_some()
}

fn initialize(params: &Value) -> Value {
    let requested = params.get("protocolVersion").and_then(Value::as_str);
    let version = PROTOCOLS
        .iter()
        .find(|known| Some(**known) == requested)
        .unwrap_or(&PROTOCOLS[0]);
    json!({
        "protocolVersion": version,
        "capabilities": {"tools": {"listChanged": false}},
        "serverInfo": {"name": "stateengine", "version": env!("CARGO_PKG_VERSION")},
    })
}

/// Discovery comes only from core's generated registry; listing is read-only.
fn tools() -> Result<Value> {
    let tools: Vec<Value> = se_core::ops::mcp_tools()?
        .into_iter()
        .map(|tool| {
            json!({
                "name": tool.name,
                "title": tool.title,
                "description": tool.description,
                "inputSchema": tool.input_schema,
                "outputSchema": tool.output_schema,
            })
        })
        .collect();
    Ok(json!({"tools": tools}))
}

async fn call(
    backend: &mut impl McpBackend,
    capability: Arc<Secret>,
    id: Value,
    params: &Value,
) -> Value {
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return rpc_error(id, -32602, "tools/call requires a tool name");
    };
    let arguments = match params.get("arguments") {
        None | Some(Value::Null) => json!({}),
        Some(Value::Object(arguments)) => Value::Object(arguments.clone()),
        Some(_) => return rpc_error(id, -32602, "tools/call arguments must be an object"),
    };
    // A domain refusal, including a bad argument, is a typed tool result the
    // model can read and act on, never an empty success.
    let outcome = match se_core::ops::decode_tool(name, arguments) {
        Ok(operation) => backend.call(capability, operation).await,
        Err(error) => Err(error),
    };
    let result = match outcome {
        Ok(output) => tool_result(&output, false),
        Err(error) => match error_value(&error) {
            Ok(envelope) => tool_result(&envelope, true),
            Err(encoding) => return rpc_error(id, -32603, &encoding.to_string()),
        },
    };
    success(id, result)
}

/// Budget the complete final envelope, both copies included. An unfit result
/// is a precise refusal, never a silent truncation.
fn budgeted(response: Value, limit: usize) -> Value {
    match serde_json::to_vec(&response) {
        Ok(bytes) if bytes.len() <= limit => response,
        Ok(bytes) => rpc_error(
            response.get("id").cloned().unwrap_or(Value::Null),
            -32603,
            &SeError::too_large("MCP response", limit, bytes.len()).to_string(),
        ),
        Err(error) => rpc_error(Value::Null, -32603, &error.to_string()),
    }
}

/// One typed outcome feeds both the text and the structured copy.
fn tool_result(structured: &Value, is_error: bool) -> Value {
    json!({
        "content": [{"type": "text", "text": structured.to_string()}],
        "structuredContent": structured,
        "isError": is_error,
    })
}

/// The same rendered envelope an IPC caller receives, as JSON.
pub(crate) fn error_value(error: &SeError) -> Result<Value> {
    let envelope =
        se_types::ErrorEnvelope::new(error.body.clone(), &se_types::RenderCx::default())?;
    serde_json::to_value(envelope)
        .map_err(|e| se_core::scope::unreadable("error envelope encoding", &e.to_string()))
}

fn success(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn rpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}
