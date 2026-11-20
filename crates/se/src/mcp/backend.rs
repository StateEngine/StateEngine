//! Session-only native forwarding for the shared MCP consumer. No store is
//! opened directly and no machine credential or owner fallback exists here.
use se_core::{
    ops::{AnyOp, IdentityWhoami, ProjectStatus},
    scope,
    store_error::store_error,
};
use se_host::{
    client::{ClientOptions, lease::Deadline},
    mcp::McpPrincipal,
};
use se_types::{AgentId, ProjectId, Result, Secret};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Instant};

pub struct Backend {
    home: Option<PathBuf>,
    client: Option<crate::ipc::SessionForwarder>,
    managed_hash: Option<[u8; 32]>,
    /// Bound principal per capability digest. The credential's project and
    /// agent binding is fixed for the credential's life, so one authenticated
    /// identity read serves every later caller-assertion check on the same
    /// capability; a stopped, revoked or restarted session is refused by the
    /// host admission of the real operation that follows.
    principals: HashMap<[u8; 32], McpPrincipal>,
}
impl Backend {
    pub fn new(home: Option<PathBuf>) -> Self {
        Self {
            home,
            client: None,
            managed_hash: None,
            principals: HashMap::new(),
        }
    }

    pub fn capability(
        &mut self,
        metadata: Option<&serde_json::Value>,
        supplied: Option<Arc<Secret>>,
    ) -> Result<Option<Arc<Secret>>> {
        if let Some(metadata) = metadata {
            let object = metadata
                .as_object()
                .ok_or_else(|| invalid_capability("MCP _meta must be an object"))?;
            if let Some(value) = object.get("stateengine.session-capability-v1") {
                let text = value
                    .as_str()
                    .filter(|text| !text.is_empty() && text.len() <= 1024)
                    .ok_or_else(|| {
                        invalid_capability(
                            "explicit session metadata must contain a bounded capability string",
                        )
                    })?;
                let secret = metadata_secret(text)?;
                if self
                    .client
                    .as_ref()
                    .is_some_and(crate::ipc::SessionForwarder::is_leased)
                {
                    self.client = None;
                }
                return Ok(Some(Arc::new(secret)));
            }
        }
        if supplied.is_some() {
            if self
                .client
                .as_ref()
                .is_some_and(crate::ipc::SessionForwarder::is_leased)
            {
                self.client = None;
            }
            return Ok(supplied);
        }
        if std::env::var_os("SE_SESSION").is_none() {
            self.ensure_guest(Instant::now())?;
            return self
                .client
                .as_ref()
                .and_then(crate::ipc::SessionForwarder::guest_ticket)
                .map(|ticket| Some(Arc::clone(&ticket.secret)))
                .ok_or_else(|| invalid_capability("host did not issue a guest ticket"));
        }
        let home = crate::bootstrap::state_home(self.home.clone())?;
        let secret = crate::bootstrap::session_input(&home)?
            .ok_or_else(|| invalid_capability("the launched session handle disappeared"))?;
        let hash: [u8; 32] = Sha256::digest(secret.expose()).into();
        if self.managed_hash.is_some_and(|previous| previous != hash) {
            self.client = None;
            self.principals.clear();
        }
        self.managed_hash = Some(hash);
        Ok(Some(Arc::new(secret)))
    }
    /// A fresh authenticated read on every call: the contract is liveness, so
    /// this deliberately does not read the principal memo.
    pub fn check_session(&mut self, secret: &Secret) -> Result<()> {
        self.call(secret, AnyOp::ProjectStatus(ProjectStatus::default()))
            .map(|_| ())
    }
    /// The capability's bound project and agent, memoized per capability.
    /// Identity is the cheapest operation that authenticates the session and
    /// returns the binding: `project.status` carries both ids too, but it
    /// walks every agent and the runtime for data an assertion check never
    /// reads. The memo is sound because the binding is a property of the
    /// credential; the host rechecks the credential on every real exchange.
    fn principal(&mut self, secret: &Secret) -> Result<McpPrincipal> {
        if let Some(ticket) = self
            .client
            .as_ref()
            .and_then(crate::ipc::SessionForwarder::guest_ticket)
            && ticket.secret.expose() == secret.expose()
        {
            return Ok(McpPrincipal {
                project: ticket.project.clone(),
                agent: None,
            });
        }
        let key: [u8; 32] = Sha256::digest(secret.expose()).into();
        if let Some(principal) = self.principals.get(&key) {
            return Ok(principal.clone());
        }
        // A door serves its launch pin plus at most a few explicit metadata
        // capabilities; bounding keeps this a memo, not a second identity store.
        if self.principals.len() >= 4 {
            self.principals.clear();
        }
        let identity = self.call(secret, AnyOp::IdentityWhoami(IdentityWhoami))?;
        let id = |path: &str| {
            identity
                .pointer(path)
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    scope::unreadable(
                        "MCP bound principal",
                        "authenticated identity did not supply an exact project and agent",
                    )
                })
        };
        let principal = McpPrincipal {
            project: id("/project/id")?.parse::<ProjectId>()?,
            agent: Some(id("/agent/id")?.parse::<AgentId>()?),
        };
        self.principals.insert(key, principal.clone());
        Ok(principal)
    }
    pub fn call(&mut self, secret: &Secret, operation: AnyOp) -> Result<serde_json::Value> {
        let mut options = crate::route::execute::options();
        let started = Instant::now();
        if self.client.is_none() {
            let home = crate::bootstrap::state_home(self.home.clone())?;
            let files =
                crate::route::files::Files::open(&home).map_err(|error| store_error(&error))?;
            let bound = Deadline::from_options(&options)?;
            let endpoint = if std::env::var_os("SE_SESSION").is_some() {
                let cx = crate::bootstrap::Bootstrap::resolve(
                    self.home.clone(),
                    None,
                    false,
                    true,
                    &operation,
                )?;
                crate::route::autostart::endpoint(&cx, &files, &bound, &mut |message| {
                    use std::io::Write;
                    writeln!(std::io::stderr().lock(), "{message}")
                })?
            } else {
                scope::require_present(
                    crate::route::execute::endpoint(&files)?,
                    "live runtime endpoint",
                    "Launch this agent through StateEngine or run se up in this data home; MCP never writes directly or uses owner authority.",
                )?
            };
            se_proc::native_ipc::restore_image_cache(
                &home,
                endpoint.image_sha256,
                &bound.native_bound(),
            )
            .map_err(|error| scope::unreadable("protected executable cache", &error.to_string()))?;
            options.expected_generation = Some(endpoint.generation);
            charge_elapsed(&mut options, started)?;
            let connected = match crate::ipc::SessionForwarder::connect(&endpoint, secret, &options)
            {
                Err(error)
                    if expired_session(&error) && std::env::var_os("SE_SESSION").is_some() =>
                {
                    options.timeout = crate::route::execute::options().timeout;
                    charge_elapsed(&mut options, started)?;
                    crate::ipc::SessionForwarder::connect_renewed(&endpoint, secret, &options)?
                }
                other => other?,
            };
            self.client = Some(connected);
        }
        // Discovery/authentication consume this call's original budget too.
        options.timeout = crate::route::execute::options().timeout;
        charge_elapsed(&mut options, started)?;
        let guest_project = self.client.as_ref().and_then(|client| {
            client.guest_ticket().and_then(|ticket| {
                (ticket.secret.expose() == secret.expose()).then(|| ticket.project.clone())
            })
        });
        let first = self
            .client
            .as_mut()
            .ok_or_else(|| se_types::SeError::invalid("MCP IPC", "the retained session channel"))?
            .forward(secret, operation.clone(), &options);
        let output = match first {
            Err(error)
                if guest_project.is_some()
                    && operation.meta().effect == se_core::registry::Effect::Read
                    && error.code() == se_types::Code::IpcUnavailable =>
            {
                self.reconnect_guest(guest_project.as_ref(), operation, started)?
            }
            Err(error) if expired_session(&error) && std::env::var_os("SE_SESSION").is_some() => {
                self.client = None;
                let home = crate::bootstrap::state_home(self.home.clone())?;
                let files =
                    crate::route::files::Files::open(&home).map_err(|error| store_error(&error))?;
                let endpoint = scope::require_present(
                    crate::route::execute::endpoint(&files)?,
                    "live runtime endpoint",
                    "Start the runtime and retry the same operation.",
                )?;
                options.timeout = crate::route::execute::options().timeout;
                charge_elapsed(&mut options, started)?;
                options.expected_generation = Some(endpoint.generation);
                let mut client =
                    crate::ipc::SessionForwarder::connect_renewed(&endpoint, secret, &options)?;
                options.timeout = crate::route::execute::options().timeout;
                charge_elapsed(&mut options, started)?;
                let output = client.forward(secret, operation, &options)?;
                self.client = Some(client);
                output
            }
            other => other?,
        };
        // A confirmed write is retained if final formatting later fails; this
        // conversion is infallible for the closed core families in normal use.
        serde_json::to_value(output).map_err(|_| {
            se_types::SeError::invalid("MCP result", "the complete registered core output family")
        })
    }

    fn reconnect_guest(
        &mut self,
        project: Option<&ProjectId>,
        operation: AnyOp,
        started: Instant,
    ) -> Result<se_core::ops::AnyOutput> {
        self.client = None;
        self.ensure_guest(started)?;
        let missing = || invalid_capability("host did not issue a replacement guest ticket");
        let client = self.client.as_mut().ok_or_else(missing)?;
        let ticket = client.guest_ticket().ok_or_else(missing)?;
        if Some(&ticket.project) != project {
            return Err(invalid_capability(
                "the registered project changed during reconnect",
            ));
        }
        let replacement = Arc::clone(&ticket.secret);
        let mut options = crate::route::execute::options();
        charge_elapsed(&mut options, started)?;
        client.forward(&replacement, operation, &options)
    }

    fn ensure_guest(&mut self, started: Instant) -> Result<()> {
        if self
            .client
            .as_ref()
            .and_then(crate::ipc::SessionForwarder::guest_ticket)
            .is_some()
        {
            return Ok(());
        }
        let op = AnyOp::ProjectStatus(ProjectStatus::default());
        let cx = crate::bootstrap::Bootstrap::resolve(self.home.clone(), None, false, true, &op)?;
        let files =
            crate::route::files::Files::open(&cx.home).map_err(|error| store_error(&error))?;
        let mut options = crate::route::execute::options();
        charge_elapsed(&mut options, started)?;
        let bound = Deadline::from_options(&options)?;
        let endpoint = crate::route::autostart::endpoint(&cx, &files, &bound, &mut |message| {
            use std::io::Write;
            writeln!(std::io::stderr().lock(), "{message}")
        })?;
        se_proc::native_ipc::restore_image_cache(
            &cx.home,
            endpoint.image_sha256,
            &bound.native_bound(),
        )
        .map_err(|error| scope::unreadable("protected executable cache", &error.to_string()))?;
        options.expected_generation = Some(endpoint.generation);
        options.timeout = crate::route::execute::options().timeout;
        charge_elapsed(&mut options, started)?;
        let cwd = se_types::NativePath::from_local(cx.cwd)?;
        self.client = Some(crate::ipc::SessionForwarder::connect_guest(
            &endpoint, cwd, &options,
        )?);
        Ok(())
    }
}
fn expired_session(error: &se_types::SeError) -> bool {
    matches!(error.body.detail(), se_types::Detail::CapabilityInvalid(detail)
        if detail.subject == "presented" && detail.reason == "expired")
}
fn charge_elapsed(options: &mut ClientOptions, started: Instant) -> Result<()> {
    options.timeout = options
        .timeout
        .checked_sub(started.elapsed())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| {
            se_types::SeError::new(se_types::Detail::DeadlineExceeded(
                se_types::details::DeadlineExceeded {
                    op: "MCP call".into(),
                    deadline_ms: 30_000,
                },
            ))
        })?;
    Ok(())
}

fn metadata_secret(text: &str) -> Result<Secret> {
    let (session, encoded) = text
        .strip_prefix("sec1.")
        .and_then(|rest| rest.rsplit_once('.'))
        .ok_or_else(|| invalid_capability("expected a sec1 session capability"))?;
    let _: se_types::SessionId = session
        .parse()
        .map_err(|_| invalid_capability("capability must name a canonical session"))?;
    if encoded.len() != 43
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(invalid_capability(
            "capability must contain the bounded base64url secret",
        ));
    }
    Secret::new(text.as_bytes().to_vec())
}

fn invalid_capability(reason: &str) -> se_types::SeError {
    se_types::SeError::new(se_types::Detail::CapabilityInvalid(se_types::details::CapabilityInvalid {
        subject: "MCP session identity".into(), reason: reason.into(),
        next_step: "Use the launched session's protected pin or valid per-call metadata; identity never falls back to the owner".into(),
    }))
}
impl se_host::McpBackend for Backend {
    fn capability(
        &mut self,
        metadata: Option<&serde_json::Value>,
        supplied: Option<Arc<Secret>>,
    ) -> Result<Option<Arc<Secret>>> {
        Backend::capability(self, metadata, supplied)
    }
    fn configured_atlas(&mut self) -> Option<Result<bool>> {
        let op = AnyOp::ProjectStatus(ProjectStatus::default());
        let cx = crate::bootstrap::Bootstrap::resolve(self.home.clone(), None, false, true, &op);
        Some(cx.map(|cx| cx.config.value.atlas.enabled))
    }
    async fn check_session(&mut self, capability: Arc<Secret>) -> Result<()> {
        Backend::check_session(self, &capability)
    }
    async fn bound_principal(&mut self, capability: Arc<Secret>) -> Result<McpPrincipal> {
        Backend::principal(self, &capability)
    }
    async fn atlas_available(&mut self, capability: Arc<Secret>) -> Result<bool> {
        let status = Backend::call(
            self,
            &capability,
            AnyOp::ProjectStatus(ProjectStatus::default()),
        )?;
        match status
            .pointer("/atlas/state")
            .and_then(serde_json::Value::as_str)
        {
            Some("unavailable" | "not-built" | "disabled") => Ok(false),
            Some(
                "unknown" | "preparing" | "unreadable" | "dormant" | "absent" | "updating"
                | "current" | "partial" | "suspended" | "draining" | "closed",
            ) => Ok(true),
            _ => Err(scope::unreadable(
                "MCP Atlas discovery",
                "authenticated status did not supply recognized controller availability; preserve the home and check se status",
            )),
        }
    }
    async fn call(
        &mut self,
        capability: Arc<Secret>,
        operation: AnyOp,
    ) -> Result<serde_json::Value> {
        Backend::call(self, &capability, operation)
    }
    fn response_limit(&self) -> usize {
        // The stdio frame keeps one byte for its terminating newline.
        se_host::client::wire::MAX_FRAME_BYTES - 1
    }
}
