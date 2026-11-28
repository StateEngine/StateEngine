//! Dedicated stdio MCP bridge for an owner-approved external seat (`se mcp --as <name>`).
//! One immutable seat per bridge connection: no in-band identity switching, no
//! capability in prompts/argv/env/logs/files, and clean fenced disconnect on EOF.
use se_core::ops::{AnyOp, IdentityWhoami};
use se_host::{
    EndpointRecord, IpcEnvelope, IpcRequest,
    client::{
        BlockingIpcClient, ClientOptions, lease::ClientCredential, wire::DEFAULT_REPLY_BYTES,
    },
    external::{
        ExternalClaimApproved, ExternalClaimBootstrap, ExternalClaimOpenOutput, ExternalRequest,
    },
    mcp::{McpBackend, McpPrincipal},
};
use se_types::{AgentId, NativePath, ProjectId, Result, SeError, Secret};
use serde_json::Value;
use std::{
    io::Write as _,
    num::NonZeroU32,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

struct ApprovedSeat {
    project: ProjectId,
    agent: AgentId,
    secret: Arc<Secret>,
}

enum ClaimState {
    Pending { claim_id: String },
    Approved(ApprovedSeat),
    Failed(String),
}

pub struct ExternalBackend {
    endpoint: EndpointRecord,
    state: Arc<Mutex<ClaimState>>,
    /// Kept alive for the bridge's lifetime so host-side connection drop
    /// triggers lease-generation-fenced cleanup on stdio EOF.
    _watcher: Option<std::thread::JoinHandle<()>>,
}

impl ExternalBackend {
    pub fn connect(home: Option<PathBuf>, agent: String, project: Option<String>) -> Result<Self> {
        let state_home = crate::bootstrap::state_home(home)?;
        let files = se_host::state_files::Files::open(&state_home)
            .map_err(|e| se_core::store_error::store_error(&e))?;
        let endpoint = se_core::scope::require_present(
            crate::route::execute::endpoint(&files)?,
            "external seat host",
            "Start the local StateEngine host (`se up`) before connecting an external MCP bridge.",
        )?;
        let cwd = std::env::current_dir()
            .map_err(|e| se_core::scope::unreadable("current directory", &e.to_string()))?;
        let cwd = NativePath::from_local(cwd)?;
        let project = project
            .as_deref()
            .map(|p| crate::route::select::resolve_project_selector(&state_home, p))
            .transpose()?;
        let connection_nonce = se_host::client::auth::fresh_nonce()?;
        let bootstrap = ExternalClaimBootstrap {
            project,
            cwd,
            agent: agent.clone(),
            connection_nonce,
        };
        let options = ClientOptions {
            expected_generation: Some(endpoint.generation),
            timeout: Duration::from_secs(30),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let mut conn = BlockingIpcClient::connect_authenticated(
            &endpoint,
            ClientCredential::ExternalClaim(Box::new(bootstrap)),
            NonZeroU32::new(DEFAULT_REPLY_BYTES)
                .ok_or_else(|| SeError::invalid("reply budget", "positive"))?,
            &options,
        )?;
        let open_env = IpcEnvelope {
            version: se_types::API_VERSION,
            request_id: 1,
            generation: endpoint.generation,
            authority: None,
            presence: None,
            cli_selections: None,
            request: IpcRequest::External(Box::new(ExternalRequest::ClaimOpen)),
        };
        let open_out = conn.exchange(open_env, &options)?;
        let opened: ExternalClaimOpenOutput = serde_json::from_value(open_out.value)
            .map_err(|e| se_core::scope::unreadable("external claim open", &e.to_string()))?;

        let claim_id = opened.claim_id.clone();
        let state = Arc::new(Mutex::new(ClaimState::Pending {
            claim_id: claim_id.clone(),
        }));
        // Start the ClaimWait waiter before printing the actionable claim ID so
        // an immediate Owner approval can be delivered without a race.
        let watcher = spawn_claim_watcher(conn, endpoint.generation, claim_id, Arc::clone(&state));

        // Stderr only — stdout is strictly reserved for MCP JSON-RPC frames.
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "Pending external seat claim {} for {} — approve with: se external approve {}",
            opened.claim_id, opened.agent_name, opened.claim_id
        );
        let _ = stderr.flush();
        drop(stderr);

        Ok(Self {
            endpoint,
            state,
            _watcher: Some(watcher),
        })
    }

    fn call_sync(&self, capability: &Secret, operation: AnyOp) -> Result<Value> {
        let options = ClientOptions {
            expected_generation: Some(self.endpoint.generation),
            timeout: Duration::from_secs(30),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let secret = Secret::new(capability.expose().to_vec())?;
        let output = crate::ipc::forward_owned(
            &self.endpoint,
            ClientCredential::ExternalSession(secret),
            operation,
            &Default::default(),
            None,
            &options,
        )?;
        serde_json::to_value(output).map_err(|_| {
            SeError::invalid("MCP result", "the complete registered core output family")
        })
    }
}

impl McpBackend for ExternalBackend {
    fn is_external_seat(&self) -> bool {
        true
    }

    fn capability(
        &mut self,
        metadata: Option<&Value>,
        supplied: Option<Arc<Secret>>,
    ) -> Result<Option<Arc<Secret>>> {
        if supplied.is_some()
            || metadata.is_some_and(|m| {
                !m.is_object() || m.get("stateengine.session-capability-v1").is_some()
            })
        {
            return Err(SeError::invalid(
                "external seat bridge",
                "one immutable seat per bridge connection; in-band capability switching is refused",
            ));
        }
        let guard = self
            .state
            .lock()
            .map_err(|_| se_core::scope::unreadable("external seat state", "lock poisoned"))?;
        match &*guard {
            ClaimState::Approved(seat) => Ok(Some(Arc::clone(&seat.secret))),
            ClaimState::Pending { claim_id } => Err(SeError::invalid(
                "external seat approval",
                &format!(
                    "out-of-band Owner approval first; run `se external approve {claim_id}` in an Owner terminal"
                ),
            )),
            ClaimState::Failed(reason) => Err(SeError::invalid(
                "external seat claim",
                &format!("a valid approved claim; previous claim failed: {reason}"),
            )),
        }
    }

    async fn check_session(&mut self, capability: Arc<Secret>) -> Result<()> {
        self.call_sync(&capability, AnyOp::IdentityWhoami(IdentityWhoami))
            .map(drop)
    }

    async fn call(&mut self, capability: Arc<Secret>, operation: AnyOp) -> Result<Value> {
        self.call_sync(&capability, operation)
    }

    async fn bound_principal(&mut self, _capability: Arc<Secret>) -> Result<McpPrincipal> {
        let guard = self
            .state
            .lock()
            .map_err(|_| se_core::scope::unreadable("external seat state", "lock poisoned"))?;
        match &*guard {
            ClaimState::Approved(seat) => Ok(McpPrincipal {
                project: seat.project.clone(),
                agent: Some(seat.agent.clone()),
            }),
            _ => Err(SeError::invalid(
                "external seat",
                "an owner-approved external seat",
            )),
        }
    }

    fn response_limit(&self) -> usize {
        se_host::client::wire::DEFAULT_REPLY_BYTES as usize
    }
}

fn spawn_claim_watcher(
    mut conn: se_host::client::BlockingConnection,
    generation: se_types::Generation,
    claim_id: String,
    state_bg: Arc<Mutex<ClaimState>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let wait_opts = ClientOptions {
            expected_generation: Some(generation),
            timeout: Duration::from_secs(se_host::external::CLAIM_TTL_SECS + 10),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let wait_env = IpcEnvelope {
            version: se_types::API_VERSION,
            request_id: 2,
            generation,
            authority: None,
            presence: None,
            cli_selections: None,
            request: IpcRequest::External(Box::new(ExternalRequest::ClaimWait { claim_id })),
        };
        match conn.exchange(wait_env, &wait_opts) {
            Ok(out) => match serde_json::from_value::<ExternalClaimApproved>(out.value) {
                Ok(approved) => match Secret::new(approved.capability.into_bytes()) {
                    Ok(secret) => {
                        if let Ok(mut guard) = state_bg.lock() {
                            *guard = ClaimState::Approved(ApprovedSeat {
                                project: approved.project_id,
                                agent: approved.agent_id,
                                secret: Arc::new(secret),
                            });
                        }
                        loop {
                            std::thread::park();
                        }
                    }
                    Err(err) => {
                        if let Ok(mut guard) = state_bg.lock() {
                            *guard = ClaimState::Failed(err.to_string());
                        }
                    }
                },
                Err(err) => {
                    if let Ok(mut guard) = state_bg.lock() {
                        *guard = ClaimState::Failed(err.to_string());
                    }
                }
            },
            Err(err) => {
                if let Ok(mut guard) = state_bg.lock() {
                    *guard = ClaimState::Failed(err.to_string());
                }
            }
        }
    })
}
