//! The one MCP protocol consumer (section 40 §7.3, H18), shared by the host's
//! loopback HTTP route and the CLI's stdio bridge. Each transport supplies only
//! its capability source and an `McpBackend`; JSON-RPC handling, tool
//! discovery, argument decoding, result shape and the final budget live here.
//! POST JSON semantics: no batching, SSE or server-initiated requests.
use se_types::{Result, SeError, Secret};
use serde_json::{Value, json};
use std::{future::Future, sync::Arc};
mod arguments;
mod atlas;
mod resume;

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
#[derive(Clone)]
pub struct McpPrincipal {
    pub project: se_types::ProjectId,
    pub agent: se_types::AgentId,
}

pub trait McpBackend {
    /// An authenticated transport can witness possession during initialization.
    /// Anonymous initialization stays read-only and grants no tool authority.
    fn witness_initialization(
        &mut self,
        _capability: Option<Arc<Secret>>,
    ) -> impl Future<Output = Result<()>> + Send {
        async { Ok(()) }
    }
    fn check_session(&mut self, capability: Arc<Secret>)
    -> impl Future<Output = Result<()>> + Send;
    /// Authenticate discovery and report this host's installed controller.
    /// Backends without an Atlas installation advertise only core tools.
    fn atlas_available(
        &mut self,
        capability: Arc<Secret>,
    ) -> impl Future<Output = Result<bool>> + Send {
        let checked = self.check_session(capability);
        async move {
            checked.await?;
            Ok(false)
        }
    }
    /// Execute one core-decoded operation as the capability's bound session and
    /// return its schema-tagged output value.
    fn call(
        &mut self,
        capability: Arc<Secret>,
        operation: se_core::ops::AnyOp,
    ) -> impl Future<Output = Result<Value>> + Send;
    /// A current authenticated principal, never selected by tool arguments.
    /// The stdio bridge memoizes one authenticated identity read per
    /// capability; HTTP returns the principal from its credential admission.
    fn bound_principal(
        &mut self,
        capability: Arc<Secret>,
    ) -> impl Future<Output = Result<McpPrincipal>> + Send {
        let read = self.call(
            capability,
            se_core::ops::AnyOp::ProjectStatus(Default::default()),
        );
        async move {
            let status = read.await?;
            let id = |path| {
                status.pointer(path).and_then(Value::as_str).ok_or_else(|| {
                    se_core::scope::unreadable(
                        "MCP bound principal",
                        "authenticated status did not supply an exact project and agent",
                    )
                })
            };
            Ok(McpPrincipal {
                project: id("/principal/project/id")?.parse()?,
                agent: id("/principal/agent/id")?.parse()?,
            })
        }
    }
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
    let id = match message.get("id") {
        // Only an absent id is a notification (initialized, cancelled).
        None => return McpReply::Accepted,
        Some(id) if valid_id(id) => id.clone(),
        Some(_) => {
            return McpReply::Json(rpc_error(
                Value::Null,
                -32600,
                "a request id must be a string or an integer",
            ));
        }
    };
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    // Ordinary lifecycle discovery stays anonymous. A transport may verify an
    // explicit first-use pair; every tool still checks its current capability.
    match method {
        "initialize" => {
            return McpReply::Json(match backend.witness_initialization(capability).await {
                Ok(()) => success(id, initialize(&params)),
                Err(error) => rpc_error(
                    id,
                    SESSION_REQUIRED,
                    &format!(
                        "{error}. Use the paired headers from one current StateEngine launch; stop and relaunch the affected agent in the same project if its configuration is stale."
                    ),
                ),
            });
        }
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
            .atlas_available(Arc::clone(&capability))
            .await
            .and_then(tools)
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
/// It advertises input schemas only: MCP makes outputSchema optional, the
/// output schemas are ~97% of the catalogue's bytes, and they remain public
/// through `se schema`. Results still carry the schema-tagged structuredContent.
fn tools(atlas_available: bool) -> Result<Value> {
    let tools: Vec<Value> = se_core::ops::mcp_tools()?
        .into_iter()
        .filter(|tool| {
            atlas_available || !se_core::ops::CATALOGUE.iter().any(|meta| {
                meta.feature == se_core::registry::Feature::Atlas
                    && matches!(meta.mcp, se_core::registry::McpExposure::Tool { name, .. } if name == tool.name)
            })
        })
        .map(|tool| {
            json!({
                "name": tool.name,
                "title": tool.title,
                "description": tool.description,
                "inputSchema": tool.input_schema,
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
    let arguments = match arguments::bound(backend, Arc::clone(&capability), name, arguments).await
    {
        Ok(arguments) => arguments,
        Err(error) => return resume::failure(id, &error),
    };
    let outcome = match se_core::ops::decode_tool(name, arguments) {
        Ok(mut operation) => {
            if operation.atlas_options().is_some() {
                return atlas::call(backend, capability, id, operation).await;
            }
            if let se_core::ops::AnyOp::Resume(input) = operation {
                return resume::call(backend, capability, id, input).await;
            }
            if operation.is_remote() {
                let id_bytes = serde_json::to_vec(&id)
                    .map(|b| b.len())
                    .unwrap_or(usize::MAX);
                let available = backend
                    .response_limit()
                    .saturating_sub(id_bytes)
                    .saturating_sub(8192)
                    / 3;
                let budget = match &mut operation {
                    se_core::ops::AnyOp::RemoteList(input) => Some(&mut input.request.budget),
                    se_core::ops::AnyOp::RemoteWatch(input) => Some(&mut input.request.budget),
                    _ => None,
                };
                if let Some(budget) = budget {
                    if available < 1024 {
                        return rpc_error(
                            id,
                            -32603,
                            "MCP envelope leaves insufficient remote page budget",
                        );
                    }
                    *budget = (*budget).min(available.min(65536) as u32);
                }
            }
            if let se_core::ops::AnyOp::MessageRead(input) = &mut operation {
                // A JSON value contributes one structured copy and at most two
                // encoded copies inside the text string. Reserve fixed space
                // for marker/transport diagnostics before any recipient mark.
                let id_bytes = serde_json::to_vec(&id)
                    .map(|bytes| bytes.len())
                    .unwrap_or(usize::MAX);
                let available = backend
                    .response_limit()
                    .saturating_sub(id_bytes)
                    .saturating_sub(8192)
                    / 3;
                if available < 512 {
                    return rpc_error(
                        id,
                        -32603,
                        &SeError::too_large(
                            "MCP reply metadata before message read",
                            backend.response_limit(),
                            id_bytes.saturating_add(8192),
                        )
                        .to_string(),
                    );
                }
                input.budget = input
                    .budget
                    .min(u32::try_from(available).unwrap_or(u32::MAX));
            }
            backend.call(capability, operation).await
        }
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
