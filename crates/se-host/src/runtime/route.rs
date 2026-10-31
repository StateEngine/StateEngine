//! Native handshake and per-call routing around the sole core operation decoder.
//! The concrete executor consumes RoutedCall; no second dispatcher trait exists.
use super::{
    admission::{AdmissionContext, ConnectionGrant},
    *,
};
use crate::client::{
    endpoint::{RuntimeStopReply, RuntimeStopRequest},
    lease::Deadline,
};
use crate::{
    AuthorizedConnection, HandshakeInput, IpcConnection, IpcRequest, IpcResponse, IpcResult,
    OperationOutput, PendingIpcHandshake,
};
use se_types::{ErrorEnvelope, RenderCx, Result, SeError};

pub enum AcceptedPeer {
    Operation(Box<HostedConnection>),
    Stop(Box<AuthorizedStop>),
}
pub struct HostedConnection {
    connection: IpcConnection,
    grant: ConnectionGrant,
    _slot: tokio::sync::OwnedSemaphorePermit,
}
pub struct AuthorizedStop {
    pending: PendingIpcHandshake,
}
impl AuthorizedStop {
    pub fn request(&self) -> &RuntimeStopRequest {
        match self.pending.input() {
            HandshakeInput::Stop(request) => request,
            HandshakeInput::Call(_) => unreachable!("constructed only after a stop handshake"),
        }
    }
    pub async fn reply(self, reply: &RuntimeStopReply, deadline: &Deadline) -> Result<()> {
        self.pending
            .finish_stop(AuthorizedConnection { _private: () }, reply, deadline)
            .await
    }
}
pub struct RoutedCall {
    pub admitted: HostedCall,
    /// An untrusted signal only. Source authority comes from the already held
    /// supervisor pin; a hook cannot create or replace that pin.
    pub hook: Option<crate::ClaudeHookInput>,
}
pub struct AdmittedExchange {
    connection: HostedConnection,
    request_id: u64,
    call: Option<Result<RoutedCall>>,
}
#[derive(Clone)]
pub struct HostedRouter {
    pub(crate) execution: ExecutionContext,
    pub(crate) sources: TranscriptBindings,
    context: AdmissionContext,
    response_bytes: std::num::NonZeroU32,
    connections: std::sync::Arc<tokio::sync::Semaphore>,
    fenced: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl HostedRuntime {
    pub fn router(&self) -> Result<HostedRouter> {
        if self.phase != crate::HostPhase::Ready {
            return Err(SeError::invalid("host router", "a ready runtime"));
        }
        Ok(HostedRouter {
            execution: self.execution.clone(),
            sources: self.sources.clone(),
            context: self.admission_context(),
            response_bytes: self.response_bytes,
            connections: std::sync::Arc::clone(&self.connections),
            fenced: std::sync::Arc::clone(&self.fenced),
        })
    }
}
impl HostedRouter {
    pub(crate) fn check_open(&self) -> Result<()> {
        if self.fenced.load(std::sync::atomic::Ordering::Acquire) {
            return Err(SeError::invalid(
                "host admission",
                "a ready runtime before its drain fence",
            ));
        }
        Ok(())
    }
    /// Run once in each accepted connection task, independently of OS accept.
    pub async fn authenticate_stream(
        &self,
        stream: crate::AcceptedIpcStream,
        deadline: &Deadline,
    ) -> Result<AcceptedPeer> {
        self.check_open()?;
        self.authenticate(stream.handshake().await?, deadline).await
    }
    pub async fn authenticate(
        &self,
        mut pending: PendingIpcHandshake,
        deadline: &Deadline,
    ) -> Result<AcceptedPeer> {
        self.check_open()?;
        let context = self.context.clone();
        let (pending, grant) = self
            .execution
            .blocking
            .run_owned(deadline, move || {
                let grant = context.handshake(&mut pending);
                Ok((pending, grant))
            })
            .await?;
        let grant = match grant {
            Ok(grant) => grant,
            Err(error) => {
                pending.refuse(envelope(&error)?).await?;
                return Err(error);
            }
        };
        self.check_open()?;
        if matches!(pending.input(), HandshakeInput::Stop(_)) {
            return Ok(AcceptedPeer::Stop(Box::new(AuthorizedStop { pending })));
        }
        let slot = match std::sync::Arc::clone(&self.connections).try_acquire_owned() {
            Ok(slot) => slot,
            Err(_) => {
                let error=SeError::new(se_types::Detail::StoreBusy(se_types::details::StoreBusy {waited_ms:0,reason:"host connection capacity is occupied".into(),next_step:"Close an existing connection and retry with the same original operation key.".into()}));
                pending.refuse(envelope(&error)?).await?;
                return Err(error);
            }
        };
        let connection = pending
            .finish(AuthorizedConnection { _private: () }, self.response_bytes)
            .await?;
        Ok(AcceptedPeer::Operation(Box::new(HostedConnection {
            connection,
            grant,
            _slot: slot,
        })))
    }
    pub async fn read_call(
        &self,
        mut connection: HostedConnection,
        deadline: &Deadline,
    ) -> Result<Option<AdmittedExchange>> {
        self.check_open()?;
        let Some(wire) = connection
            .connection
            .read_request_or_closed(deadline)
            .await?
        else {
            return Ok(None);
        };
        let request_id = wire.request_id;
        self.check_open()?;
        let context = self.context.clone();
        let fenced = std::sync::Arc::clone(&self.fenced);
        self.execution
            .blocking
            .run_owned(deadline, move || {
                let call = if fenced.load(std::sync::atomic::Ordering::Acquire) {
                    Err(SeError::invalid(
                        "host admission",
                        "a call admitted before its drain fence",
                    ))
                } else {
                    route(&context, &connection, wire)
                };
                Ok(Some(AdmittedExchange {
                    connection,
                    request_id,
                    call: Some(call),
                }))
            })
            .await
    }
}
impl AdmittedExchange {
    pub fn take_call(&mut self) -> Result<RoutedCall> {
        self.call
            .take()
            .ok_or_else(|| SeError::invalid("admitted exchange", "one owned call consumer"))?
    }
    /// The original id/API/G are taken from the admitted exchange. A complete
    /// response is budgeted and written once; an incomplete write consumes it.
    pub async fn reply(
        self,
        output: Result<ExecutedCall>,
        deadline: &Deadline,
    ) -> Result<HostedConnection> {
        let mut connection = self.connection;
        let result = match output {
            Ok(completed) => {
                let output = match completed.write_timings {
                    Some(measured) => {
                        let timings = se_core::ops::ReceiptWriteTimings::from_store(&measured);
                        timings.validate()?;
                        completed.output.with_write_timings(timings)
                    }
                    None => completed.output,
                };
                let schema = output.family().schema();
                let value = serde_json::to_value(output).map_err(|e| {
                    se_core::scope::unreadable("core output encoding", &e.to_string())
                })?;
                // Preserve the complete core family envelope for CLI/MCP readers;
                // the outer transport family/window never replaces those facts.
                let window = value
                    .get("window")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()
                    .map_err(|_| {
                        SeError::invalid("core output window", "the canonical complete Window")
                    })?;
                IpcResult::Output(Box::new(OperationOutput {
                    schema,
                    value,
                    window,
                }))
            }
            Err(error) => IpcResult::Error(envelope(&error)?),
        };
        connection
            .connection
            .reply(
                &IpcResponse {
                    version: se_types::API_VERSION,
                    request_id: self.request_id,
                    generation: connection.connection.negotiated().generation,
                    result,
                },
                deadline,
            )
            .await?;
        Ok(connection)
    }
}
fn route(
    context: &AdmissionContext,
    connection: &HostedConnection,
    wire: crate::IpcEnvelope,
) -> Result<RoutedCall> {
    let (raw, hook) = match wire.request {
        IpcRequest::Operation(raw) => {
            if raw.name == "hook.claude" {
                return Err(SeError::invalid(
                    "Claude hook",
                    "the fixed native Hook frame with its bounded payload",
                ));
            }
            (raw, None)
        }
        IpcRequest::Hook(hook) => {
            let event = match hook.kind {
                crate::ClaudeHookKind::SessionStart => "session-start",
                crate::ClaudeHookKind::Prompt => "prompt",
                crate::ClaudeHookKind::Stop => "stop",
                crate::ClaudeHookKind::StopFailure => "stop-failure",
            };
            (
                crate::RawOperation {
                    name: "hook.claude".into(),
                    arguments: serde_json::json!({"event":event}),
                    key: None,
                },
                Some(hook),
            )
        }
    };
    let admitted = context.operation(
        connection.connection.peer(),
        connection.connection.connection_authority(),
        wire.authority.as_ref(),
        &connection.grant,
        raw,
        super::admission::OperationMetadata {
            selections: wire.cli_selections,
            presence: wire.presence,
        },
    )?;
    Ok(RoutedCall { admitted, hook })
}
fn envelope(error: &SeError) -> Result<ErrorEnvelope> {
    ErrorEnvelope::new(error.body.clone(), &RenderCx::default())
}
