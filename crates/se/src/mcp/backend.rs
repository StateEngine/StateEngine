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
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, OnceLock},
    time::Instant,
};

pub struct Backend {
    home: Option<PathBuf>,
    client: Option<crate::ipc::SessionForwarder>,
    managed: OnceLock<Result<Option<Arc<Secret>>>>,
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
            managed: OnceLock::new(),
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
                return metadata_secret(text).map(Arc::new).map(Some);
            }
        }
        if supplied.is_some() {
            return Ok(supplied);
        }
        let resolved = self.managed.get_or_init(|| {
            if std::env::var_os("SE_SESSION").is_none() {
                return Ok(None);
            }
            let home = crate::bootstrap::state_home(self.home.clone())?;
            crate::bootstrap::session_input(&home).map(|secret| secret.map(Arc::new))
        });
        match resolved {
            Ok(secret) => Ok(secret.as_ref().map(Arc::clone)),
            Err(error) => Err(error.body.clone().into()),
        }
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
        let mut digest = Sha256::new();
        digest.update(secret.expose());
        let key: [u8; 32] = digest.finalize().into();
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
            agent: id("/agent/id")?.parse::<AgentId>()?,
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
            let endpoint = scope::require_present(
                crate::route::execute::endpoint(&files)?,
                "live runtime endpoint",
                "Launch this agent through StateEngine or run se up in this data home; MCP never writes directly or uses owner authority.",
            )?;
            let bound = Deadline::from_options(&options)?;
            se_proc::native_ipc::restore_image_cache(
                &home,
                endpoint.image_sha256,
                &bound.native_bound(),
            )
            .map_err(|error| scope::unreadable("protected executable cache", &error.to_string()))?;
            options.expected_generation = Some(endpoint.generation);
            charge_elapsed(&mut options, started)?;
            self.client = Some(crate::ipc::SessionForwarder::connect(
                &endpoint, secret, &options,
            )?);
        }
        // Discovery/authentication consume this call's original budget too.
        options.timeout = crate::route::execute::options().timeout;
        charge_elapsed(&mut options, started)?;
        let output = self
            .client
            .as_mut()
            .ok_or_else(|| se_types::SeError::invalid("MCP IPC", "the retained session channel"))?
            .forward(secret, operation, &options)?;
        // A confirmed write is retained if final formatting later fails; this
        // conversion is infallible for the closed core families in normal use.
        serde_json::to_value(output).map_err(|_| {
            se_types::SeError::invalid("MCP result", "the complete registered core output family")
        })
    }
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
