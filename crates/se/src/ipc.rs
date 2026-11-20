//! One synchronous call through the authenticated native client. Connection loss
//! is returned to the caller with its existing operation key; this layer retries nothing.
use se_core::ops::{AnyOp, AnyOutput, CliSelections};
pub use se_host::client::operation::{decode, operation, uncertain};
use se_host::{
    EndpointRecord, IpcEnvelope, IpcRequest, OperationOutput,
    client::{
        BlockingIpcClient, ClientOptions,
        lease::{ClientCredential, ExchangeProgress},
        presence::OwnerPresence,
        wire::DEFAULT_REPLY_BYTES,
    },
};
use se_types::{Detail, Result, SeError, details};
use sha2::{Digest, Sha256};
use std::{num::NonZeroU32, time::Instant};

pub fn forward(
    endpoint: &EndpointRecord,
    credential: ClientCredential,
    op: AnyOp,
    selections: &CliSelections,
    observation: Option<&se_proc::OwnerObservation>,
    options: &ClientOptions,
) -> Result<AnyOutput> {
    let presence = observation.map(OwnerPresence::from_observation);
    forward_owned(endpoint, credential, op, selections, presence, options)
}

/// The same request from values a thread can own.
///
/// The native observation is read once by the parent and reduced to its
/// `OwnerPresence` before it crosses a thread boundary, so a worker never
/// borrows the caller's process inventory. Everything else here is already
/// owned. Only the owner-authenticated route can carry presence; session and
/// launch credentials never gain human presence from metadata.
pub fn forward_owned(
    endpoint: &EndpointRecord,
    credential: ClientCredential,
    op: AnyOp,
    selections: &CliSelections,
    presence: Option<OwnerPresence>,
    options: &ClientOptions,
) -> Result<AnyOutput> {
    let expected = op.meta().family.schema();
    let mut call = operation(op, selections, endpoint.generation)?;
    if matches!(&credential, ClientCredential::Machine(_)) {
        call.presence = presence;
    }
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
            presence: None,
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
    let keyed = match &call.request {
        IpcRequest::Operation(operation) => operation
            .key
            .as_ref()
            .map(|key| (operation.name.clone(), key.clone())),
        _ => None,
    };
    let output = exchange_output(endpoint, credential, call, options)?;
    decode(output, expected).map_err(|error| uncertain(keyed.as_ref(), error))
}
pub(crate) fn exchange_output(
    endpoint: &EndpointRecord,
    credential: ClientCredential,
    call: IpcEnvelope,
    options: &ClientOptions,
) -> Result<OperationOutput> {
    let keyed = match &call.request {
        IpcRequest::Operation(operation) => operation
            .key
            .as_ref()
            .map(|key| (operation.name.clone(), key.clone())),
        IpcRequest::Hook(_) | IpcRequest::Channels(_) | IpcRequest::Adopt(_) => None,
        #[cfg(feature = "remote")]
        IpcRequest::RemoteOwner(input) => input
            .key()
            .map(|key| ("remote authority control".into(), key.clone())),
    };
    let started = Instant::now();
    let mut connection = BlockingIpcClient::connect_authenticated(
        endpoint,
        credential,
        NonZeroU32::new(DEFAULT_REPLY_BYTES).ok_or_else(|| invalid("nonzero reply budget"))?,
        options,
    )?;
    // Authentication and exchange consume one caller budget after any separate
    // runtime bootstrap. A new connection never renews that request budget.
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
    let mut progress = ExchangeProgress::NotSent;
    let output = connection
        .exchange_with_progress(call, &exchange_options, &mut progress)
        .map_err(|error| {
            if progress == ExchangeProgress::SendAttempted {
                uncertain(keyed.as_ref(), error)
            } else {
                // Definitely unsent and authoritative error replies keep their
                // original classes, including confirmed-but-unreadable commits.
                error
            }
        })?;
    Ok(output)
}

#[cfg(feature = "remote")]
pub(crate) fn forward_owner(
    endpoint: &EndpointRecord,
    credential: ClientCredential,
    input: se_host::remote::OwnerInput,
    observation: &se_proc::OwnerObservation,
    options: &ClientOptions,
) -> Result<OperationOutput> {
    input.validate()?;
    if !matches!(&credential, ClientCredential::Machine(_)) {
        return Err(invalid(
            "native human machine admission for remote authority control",
        ));
    }
    let key = input
        .key()
        .map(|key| ("remote authority control".into(), key.clone()));
    let output = exchange_output(
        endpoint,
        credential,
        IpcEnvelope {
            version: se_types::API_VERSION,
            request_id: 1,
            generation: endpoint.generation,
            authority: None,
            presence: Some(OwnerPresence::from_observation(observation)),
            cli_selections: None,
            request: IpcRequest::RemoteOwner(Box::new(input)),
        },
        options,
    )?;
    if output.schema != "stateengine.remote-control/v1" {
        return Err(uncertain(
            key.as_ref(),
            invalid("the closed remote Owner control response"),
        ));
    }
    Ok(output)
}

fn call_operation(call: &IpcEnvelope) -> &str {
    match &call.request {
        IpcRequest::Operation(op) => &op.name,
        IpcRequest::Hook(_) => "hook.claude",
        IpcRequest::Channels(_) => "native.channels",
        IpcRequest::Adopt(_) => "native.adopt",
        #[cfg(feature = "remote")]
        IpcRequest::RemoteOwner(_) => "remote authority control",
    }
}
fn invalid(expected: &str) -> SeError {
    SeError::invalid("CLI IPC", expected)
}

/// A session-only client with one outstanding request and a pinned host epoch.
/// Every call sends its capability again; the host rechecks revocation and scope.
/// Incomplete exchanges consume the native channel and never trigger a retry.
pub struct SessionForwarder {
    connection: se_host::client::BlockingConnection,
    request_id: u64,
    source_hash: Option<[u8; 32]>,
}
impl SessionForwarder {
    pub fn connect_guest(
        endpoint: &EndpointRecord,
        cwd: se_types::NativePath,
        options: &ClientOptions,
    ) -> Result<Self> {
        let connection = BlockingIpcClient::connect_authenticated(
            endpoint,
            ClientCredential::GuestBootstrap(cwd),
            NonZeroU32::new(DEFAULT_REPLY_BYTES).ok_or_else(|| invalid("nonzero reply budget"))?,
            options,
        )?;
        if connection.negotiated().lease.is_none() {
            return Err(invalid("a host-issued guest ticket"));
        }
        Ok(Self {
            connection,
            request_id: 0,
            source_hash: None,
        })
    }

    pub fn guest_ticket(&self) -> Option<&se_host::ConnectionTicket> {
        self.connection
            .negotiated()
            .lease
            .as_ref()
            .filter(|ticket| ticket.agent.is_none())
    }

    pub fn is_leased(&self) -> bool {
        self.connection.negotiated().lease.is_some()
    }

    pub fn connect_renewed(
        endpoint: &EndpointRecord,
        secret: &se_types::Secret,
        options: &ClientOptions,
    ) -> Result<Self> {
        let connection = BlockingIpcClient::connect_authenticated(
            endpoint,
            ClientCredential::SessionBootstrap(se_types::Secret::new(secret.expose().to_vec())?),
            NonZeroU32::new(DEFAULT_REPLY_BYTES).ok_or_else(|| invalid("nonzero reply budget"))?,
            options,
        )?;
        if connection
            .negotiated()
            .lease
            .as_ref()
            .is_none_or(|ticket| ticket.agent.is_none() || ticket.session.is_none())
        {
            return Err(invalid("a host-issued session ticket"));
        }
        let requested =
            std::env::var("SE_SESSION").map_err(|_| invalid("the launched session handle"))?;
        if connection
            .negotiated()
            .lease
            .as_ref()
            .and_then(|ticket| ticket.session.as_ref())
            .is_none_or(|session| session.as_str() != requested)
        {
            return Err(invalid("the same launched session handle"));
        }
        Ok(Self {
            connection,
            request_id: 0,
            source_hash: Some(Sha256::digest(secret.expose()).into()),
        })
    }

    pub fn connect(
        endpoint: &EndpointRecord,
        secret: &se_types::Secret,
        options: &ClientOptions,
    ) -> Result<Self> {
        let connection = BlockingIpcClient::connect_authenticated(
            endpoint,
            ClientCredential::Session(se_types::Secret::new(secret.expose().to_vec())?),
            NonZeroU32::new(DEFAULT_REPLY_BYTES).ok_or_else(|| invalid("nonzero reply budget"))?,
            options,
        )?;
        Ok(Self {
            connection,
            request_id: 0,
            source_hash: None,
        })
    }
    pub fn forward(
        &mut self,
        secret: &se_types::Secret,
        op: AnyOp,
        options: &ClientOptions,
    ) -> Result<AnyOutput> {
        self.request_id = self
            .request_id
            .checked_add(1)
            .ok_or_else(|| invalid("an unexhausted request sequence"))?;
        let expected = op.meta().family.schema();
        let keyed = op
            .idempotency_key()
            .map(|key| (op.meta().name.to_owned(), key.clone()));
        let mut call = operation(
            op,
            &CliSelections::default(),
            self.connection.negotiated().generation,
        )?;
        call.request_id = self.request_id;
        call.cli_selections = None;
        call.authority = Some(
            if let Some(ticket) = self.connection.negotiated().lease.as_ref() {
                if let Some(hash) = self.source_hash {
                    if <[u8; 32]>::from(Sha256::digest(secret.expose())) != hash {
                        return Err(invalid("the original renewed session credential"));
                    }
                } else if secret.expose() != ticket.secret.expose() {
                    return Err(invalid("the original guest ticket"));
                }
                se_host::PresentedAuthority::Lease(se_types::Secret::new(
                    ticket.secret.expose().to_vec(),
                )?)
            } else {
                se_host::PresentedAuthority::Session(se_types::Secret::new(
                    secret.expose().to_vec(),
                )?)
            },
        );
        let mut progress = ExchangeProgress::NotSent;
        let output = self
            .connection
            .exchange_with_progress(call, options, &mut progress)
            .map_err(|error| {
                if progress == ExchangeProgress::SendAttempted {
                    uncertain(keyed.as_ref(), error)
                } else {
                    error
                }
            })?;
        decode(output, &expected).map_err(|error| uncertain(keyed.as_ref(), error))
    }
}
