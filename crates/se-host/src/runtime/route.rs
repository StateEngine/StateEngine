//! Native handshake and per-call routing around the sole core operation decoder.
//! The concrete executor consumes RoutedCall; no second dispatcher trait exists.
use super::timings::{self, Mode};
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
use std::time::Instant;

pub enum AcceptedPeer {
    Operation(Box<HostedConnection>),
    Stop(Box<AuthorizedStop>),
}
pub struct HostedConnection {
    pub(super) connection: IpcConnection,
    grant: ConnectionGrant,
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
    pub(super) connection: HostedConnection,
    pub(super) request_id: u64,
    call: Option<Result<RoutedCall>>,
    pub(super) channels: Option<crate::channels::ChannelRequest>,
    admission: Option<se_core::ops::HostPhaseSpan>,
    admitted_at: Instant,
}
#[derive(Clone)]
pub struct HostedRouter {
    pub(crate) image_sha256: se_types::Sha256,
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(super) memory_reclaim: Option<super::memory::MemoryReclaim>,
    pub(crate) execution: ExecutionContext,
    pub(crate) sources: TranscriptBindings,
    pub(crate) context: AdmissionContext,
    pub(crate) channels: std::sync::Arc<crate::channels::Channels>,
    response_bytes: std::num::NonZeroU32,
    pub(crate) fenced: std::sync::Arc<std::sync::atomic::AtomicBool>,
    http_port: std::sync::Arc<std::sync::OnceLock<u16>>,
}
impl HostedRuntime {
    pub fn router(&self) -> Result<HostedRouter> {
        if self.phase != crate::HostPhase::Ready {
            return Err(SeError::invalid("host router", "a ready runtime"));
        }
        Ok(HostedRouter {
            image_sha256: self.image_sha256,
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            memory_reclaim: self.memory_reclaim.clone(),
            execution: self.execution.clone(),
            sources: self.sources.clone(),
            context: self.admission_context(),
            channels: self.channels()?,
            response_bytes: self.response_bytes,
            fenced: std::sync::Arc::clone(&self.fenced),
            http_port: std::sync::Arc::clone(&self.http_port),
        })
    }
}
impl HostedRouter {
    pub(crate) fn check_open(&self) -> Result<()> {
        if self.fenced.load(std::sync::atomic::Ordering::Acquire)
            || self
                .execution
                .ownership_fault
                .failed
                .load(std::sync::atomic::Ordering::Acquire)
        {
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
        let connection = pending
            .finish(AuthorizedConnection { _private: () }, self.response_bytes)
            .await?;
        Ok(AcceptedPeer::Operation(Box::new(HostedConnection {
            connection,
            grant,
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
        self.admit_request(connection, wire, deadline).await
    }
    pub(crate) async fn read_call_idle(
        &self,
        mut connection: HostedConnection,
        idle: &Deadline,
    ) -> Result<Option<(AdmittedExchange, Deadline)>> {
        self.check_open()?;
        let Some((wire, deadline)) = connection.connection.read_after_idle(idle).await? else {
            return Ok(None);
        };
        let exchange = self.admit_request(connection, wire, &deadline).await?;
        Ok(exchange.map(|exchange| (exchange, deadline)))
    }
    async fn admit_request(
        &self,
        connection: HostedConnection,
        wire: crate::IpcEnvelope,
        deadline: &Deadline,
    ) -> Result<Option<AdmittedExchange>> {
        let admitted_at = Instant::now();
        let request_id = wire.request_id;
        self.check_open()?;
        let context = self.context.clone();
        let fenced = std::sync::Arc::clone(&self.fenced);
        let (mut exchange, span) =
            timings::blocking(&self.execution.blocking, Mode::Owned, deadline, move || {
                let call = if fenced.load(std::sync::atomic::Ordering::Acquire) {
                    Err(SeError::invalid(
                        "host admission",
                        "a call admitted before its drain fence",
                    ))
                } else {
                    route(&context, &connection, wire)
                };
                let (call, channels) = match call {
                    Ok(RouteChoice::Channels(input)) => (None, Some(input)),
                    Ok(RouteChoice::Core(call)) => (Some(Ok(*call)), None),
                    Err(error) => (Some(Err(error)), None),
                };
                Ok(Some(AdmittedExchange {
                    connection,
                    request_id,
                    call,
                    channels,
                    admission: None,
                    admitted_at,
                }))
            })
            .await?;
        if let Some(exchange) = &mut exchange {
            exchange.admission = Some(span);
        }
        Ok(exchange)
    }
}
impl AdmittedExchange {
    pub fn take_call(&mut self) -> Result<RoutedCall> {
        let mut call = self
            .call
            .take()
            .ok_or_else(|| SeError::invalid("admitted exchange", "one owned call consumer"))??;
        if let HostedInput::Operation(se_core::ops::AnyOp::AtlasAugment(input)) =
            &mut call.admitted.input
        {
            input.deadline = Some(self.admitted_at + std::time::Duration::from_millis(5));
        }
        Ok(call)
    }
    /// The original id/API/G are taken from the admitted exchange. A complete
    /// response is budgeted and written once; an incomplete write consumes it.
    pub async fn reply(
        self,
        output: Result<ExecutedCall>,
        deadline: &Deadline,
    ) -> Result<HostedConnection> {
        self.reply_with_error(output, deadline, None).await
    }
    pub(crate) async fn reply_draining(
        self,
        output: Result<ExecutedCall>,
        deadline: &Deadline,
    ) -> Result<HostedConnection> {
        match deadline.remaining() {
            Ok(_) => self.reply(output, deadline).await,
            Err(expired) => {
                // Report known finish facts using the existing finite transport
                // cleanup allowance; neither execution nor storage is renewed.
                self.reply_with_error(output, &super::shutdown::cleanup_deadline()?, Some(expired))
                    .await
            }
        }
    }
    async fn reply_with_error(
        self,
        output: Result<ExecutedCall>,
        deadline: &Deadline,
        unavailable: Option<SeError>,
    ) -> Result<HostedConnection> {
        // An execution error already carries its authoritative outcome. Only a
        // completed output needs conversion when the shutdown budget expired.
        let unavailable = output.as_ref().ok().and(unavailable);
        let mut connection = self.connection;
        let committed = output
            .as_ref()
            .ok()
            .and_then(|completed| completed.committed.clone());
        let capture_keys = output
            .as_ref()
            .ok()
            .map(|completed| completed.capture_keys.clone())
            .unwrap_or_default();
        let capture_events: Vec<_> = output
            .as_ref()
            .ok()
            .into_iter()
            .flat_map(|completed| &completed.capture_commits)
            .map(|commit| commit.event_id.clone())
            .collect();
        let result = match output {
            Ok(mut completed) => {
                completed.host_phases.admission = self.admission;
                completed.host_phases.admitted_to_encode_us =
                    Some(timings::micros(self.admitted_at.elapsed()));
                encode_executed(completed).map(|o| IpcResult::Output(Box::new(o)))
            }
            Err(error) => envelope(&error).map(IpcResult::Error),
        };
        let response_error = |error: SeError| {
            let error = committed
                .as_ref()
                .map_or(error.body.clone().into(), |known| {
                    known.response_error(error)
                });
            if !capture_events.is_empty() {
                SeError::new(se_types::Detail::CaptureIncomplete(
                    se_types::details::CaptureIncomplete {
                        committed_events: capture_events.clone(),
                        natural_keys: capture_keys.clone(),
                        reason: error.to_string(),
                    },
                ))
                .with_cause(error)
            } else {
                error
            }
        };
        let result = match (result, unavailable) {
            (_, Some(expired)) => IpcResult::Error(envelope(&response_error(expired))?),
            (Ok(result), None) => result,
            (Err(error), None) => IpcResult::Error(envelope(&response_error(error))?),
        };
        let mut response = IpcResponse {
            version: se_types::API_VERSION,
            request_id: self.request_id,
            generation: connection.connection.negotiated().generation,
            result,
        };
        // Encode/validate before consuming the channel. A known commit whose
        // output exceeds its negotiated budget still receives a typed key error.
        if let Err(error) = crate::client::wire::encode_response(
            &response,
            connection.connection.negotiated().maximum_reply_bytes.get() as usize,
        ) {
            response.result = IpcResult::Error(envelope(&response_error(error))?);
        }
        connection.connection.reply(&response, deadline).await?;
        Ok(connection)
    }
}
enum RouteChoice {
    Core(Box<RoutedCall>),
    Channels(crate::channels::ChannelRequest),
}
fn route(
    context: &AdmissionContext,
    connection: &HostedConnection,
    wire: crate::IpcEnvelope,
) -> Result<RouteChoice> {
    let (raw, hook) = match wire.request {
        IpcRequest::Channels(input) => {
            context.channel_owner(
                connection.connection.peer(),
                connection.connection.connection_authority(),
                wire.authority.as_ref(),
                &connection.grant,
            )?;
            if wire.cli_selections.is_some() {
                return Err(SeError::invalid(
                    "channel scope",
                    "the closed native channel input without CLI selection overrides",
                ));
            }
            input.validate().map_err(|error| error.refusal())?;
            return Ok(RouteChoice::Channels(input));
        }
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
    Ok(RouteChoice::Core(Box::new(RoutedCall { admitted, hook })))
}
/// The one completed-output encoding shared by IPC and loopback MCP replies.
pub(crate) fn encode_executed(completed: ExecutedCall) -> Result<OperationOutput> {
    let output = match completed.write_timings {
        Some(measured) => {
            let timings = se_core::ops::ReceiptWriteTimings::from_store(&measured);
            timings.validate()?;
            completed.output.with_write_timings(timings)
        }
        None => completed.output,
    }
    .with_capture_commits(completed.capture_commits)?
    .with_host_phases(completed.host_phases);
    let schema = output.family().schema();
    let value = serde_json::to_value(output)
        .map_err(|e| se_core::scope::unreadable("core output encoding", &e.to_string()))?;
    let window = value
        .get("window")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| SeError::invalid("core output window", "the canonical complete Window"))?;
    Ok(OperationOutput {
        schema,
        value,
        window,
    })
}
fn envelope(error: &SeError) -> Result<ErrorEnvelope> {
    ErrorEnvelope::new(error.body.clone(), &RenderCx::default())
}
impl HostedRouter {
    /// Loopback MCP: admit on the blocking pool exactly as IPC does, then run
    /// the same executor. A known commit survives a later encoding failure.
    pub(crate) async fn mcp_call(
        &self,
        secret: std::sync::Arc<se_types::Secret>,
        operation: se_core::ops::AnyOp,
        deadline: &Deadline,
    ) -> Result<OperationOutput> {
        let admitted_at = Instant::now();
        self.check_open()?;
        let context = self.context.clone();
        let fenced = std::sync::Arc::clone(&self.fenced);
        let (admitted, admission) =
            timings::blocking(&self.execution.blocking, Mode::Owned, deadline, move || {
                if fenced.load(std::sync::atomic::Ordering::Acquire) {
                    return Err(SeError::invalid(
                        "host admission",
                        "a call admitted before its drain fence",
                    ));
                }
                context.mcp_call(&secret, operation)
            })
            .await?;
        let mut completed = self
            .execute_call(
                RoutedCall {
                    admitted,
                    hook: None,
                },
                deadline,
            )
            .await?;
        completed.host_phases.admission = Some(admission);
        completed.host_phases.admitted_to_encode_us = Some(timings::micros(admitted_at.elapsed()));
        let committed = completed.committed.clone();
        encode_executed(completed).map_err(|error| match committed {
            Some(known) => known.response_error(error),
            None => error,
        })
    }
    pub(crate) async fn mcp_principal(
        &self,
        secret: std::sync::Arc<se_types::Secret>,
        deadline: &Deadline,
    ) -> Result<crate::mcp::McpPrincipal> {
        self.check_open()?;
        let context = self.context.clone();
        self.execution
            .blocking
            .run_owned(deadline, move || context.mcp_principal(&secret))
            .await
    }
    pub(crate) async fn check_session(
        &self,
        secret: std::sync::Arc<se_types::Secret>,
        deadline: &Deadline,
    ) -> Result<()> {
        self.check_open()?;
        let context = self.context.clone();
        self.execution
            .blocking
            .run_owned(deadline, move || context.check_session(&secret))
            .await
    }
    pub(crate) fn response_limit(&self) -> std::num::NonZeroU32 {
        self.response_bytes
    }
    /// The loopback MCP port a launch writes into its provider's MCP config.
    pub fn http_port(&self) -> Option<u16> {
        self.http_port.get().copied()
    }
}
