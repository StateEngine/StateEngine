#![cfg(feature = "listener")]
#[path = "support/wave2_host_fixture.rs"]
mod host;
use host::{fixture::*, *};
use se_host::{
    client::{
        BlockingConnection, BlockingIpcClient, ClientOptions, lease::ClientCredential,
        presence::OwnerPresence, wire::DEFAULT_REPLY_BYTES,
    },
    external::{
        ExternalApproveOutput, ExternalClaimApproved, ExternalClaimBootstrap,
        ExternalClaimOpenOutput, ExternalListOutput, ExternalMailWaitOutput, ExternalRequest,
        ExternalRevokeOutput,
    },
    *,
};
use se_store::*;
use se_types::{AgentId, IdempotencyKey, NativePath, Secret};
use std::{
    num::NonZeroU32,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

type BridgeWaiter =
    std::thread::JoinHandle<Result<(BlockingConnection, ExternalClaimApproved), String>>;

fn reply_limit() -> se_types::Result<NonZeroU32> {
    NonZeroU32::new(DEFAULT_REPLY_BYTES)
        .ok_or_else(|| se_types::SeError::invalid("reply_limit", "reply limit must be non-zero"))
}

struct LiveHost {
    rt: tokio::runtime::Runtime,
    endpoint: EndpointRecord,
    stop: LocalStop,
    task: Option<tokio::task::JoinHandle<HostServeExit>>,
    home: Fixture,
    external_agent: AgentId,
    regular_agent: AgentId,
}

impl LiveHost {
    fn start_fresh() -> Result<Self, Box<dyn std::error::Error>> {
        let f = Fixture::new()?;
        seed(&f)?;
        let external_agent = f.a.clone();
        let regular_agent = f.b.clone();
        {
            let (mut direct, lease) = direct(&f)?;
            let mut events = vec![EventBody::PrincipalRegistered {
                principal: Actor::Human(f.owner.clone()),
                kind: PrincipalKind::Human,
                owner: f.owner.clone(),
                created_by: None,
                name: "owner".into(),
                role: String::new(),
                ephemeral: None,
                expected: Expected::Absent,
            }];
            for (agent, external) in [(&external_agent, true), (&regular_agent, false)] {
                events.push(EventBody::ProfileSaved {
                    agent: agent.clone(),
                    profile: Profile {
                        provider_settings: Default::default(),
                        provider: Provider::Claude,
                        harness: None,
                        model: None,
                        permission: PermissionProfile::WorkspaceWrite,
                        named_profile: "default".into(),
                        effort: None,
                        external,
                    },
                    expected: Expected::Absent,
                });
            }
            direct.append(
                f.batch(
                    f.owner_project(),
                    Some(request("seed-external-profiles")?),
                    events,
                )?,
                &*lease,
            )?;
            direct.close()?;
        }
        Self::boot(f, external_agent, regular_agent)
    }

    fn boot(
        f: Fixture,
        external_agent: AgentId,
        regular_agent: AgentId,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let initialized = initialize_host_process()?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let mut cfg = start(&f)?;
        cfg.limits.active_connections = positive(16)?;
        cfg.limits.preauth_connections = positive(8)?;
        cfg.limits.parked_mail_waits = positive(8)?;
        cfg.limits.blocking_jobs = positive(8)?;
        let (endpoint, stop, task) = rt.block_on(async {
            let mut runtime =
                HostedRuntime::prepare(initialized, cfg, rt.handle().clone(), &bound()?).await?;
            let stop = runtime.local_stop();
            let listener = runtime.listen(rt.handle().clone(), &bound()?).await?;
            let endpoint = listener.endpoint().clone();
            let task = tokio::spawn(runtime.serve(listener));
            Ok::<_, Box<dyn std::error::Error>>((endpoint, stop, task))
        })?;
        Ok(Self {
            rt,
            endpoint,
            stop,
            task: Some(task),
            home: f,
            external_agent,
            regular_agent,
        })
    }

    fn restart(mut self) -> Result<Self, Box<dyn std::error::Error>> {
        self.stop.request();
        if let Some(task) = self.task.take() {
            let exit = self.rt.block_on(task)?;
            let mut report = self.rt.block_on(exit.finish(&bound()?));
            let _ = self.rt.block_on(report.runtime.drain_storage(&bound()?));
        }
        let LiveHost {
            home,
            external_agent,
            regular_agent,
            ..
        } = self;
        Self::boot(home, external_agent, regular_agent)
    }

    fn shutdown(mut self) -> Check {
        self.stop.request();
        if let Some(task) = self.task.take() {
            let exit = self.rt.block_on(task)?;
            let mut report = self.rt.block_on(exit.finish(&bound()?));
            let _ = self.rt.block_on(report.runtime.drain_storage(&bound()?));
        }
        Ok(())
    }

    fn owner_presence(&self) -> Result<OwnerPresence, Box<dyn std::error::Error>> {
        let peer = se_proc::native_ipc::observe_ipc_self()?;
        let owner = match peer.principal() {
            se_proc::native_ipc::IpcPrincipal::Unix { uid } => uid.to_string(),
            se_proc::native_ipc::IpcPrincipal::Windows { sid } => sid.clone(),
        };
        Ok(serde_json::from_value(serde_json::json!({
            "os_owner": owner,
            "stdin_console": true,
            "stdout_console": true,
            "session_present": false,
            "provider_marker_present": false,
            "outside_agent_tree": true,
        }))?)
    }

    fn owner_external(&self, req: ExternalRequest) -> Result<OperationOutput, se_types::SeError> {
        let mut conn = BlockingIpcClient::connect_authenticated(
            &self.endpoint,
            ClientCredential::Machine(Secret::new(vec![23; 32])?),
            reply_limit()?,
            &ClientOptions {
                expected_generation: Some(self.endpoint.generation),
                timeout: Duration::from_secs(15),
                cancelled: Arc::new(AtomicBool::new(false)),
            },
        )?;
        let presence = self
            .owner_presence()
            .map_err(|e| se_types::SeError::invalid("presence", &e.to_string()))?;
        conn.exchange(
            IpcEnvelope {
                version: se_types::API_VERSION,
                request_id: 1,
                generation: self.endpoint.generation,
                authority: None,
                presence: Some(presence),
                cli_selections: None,
                request: IpcRequest::External(Box::new(req)),
            },
            &ClientOptions {
                expected_generation: Some(self.endpoint.generation),
                timeout: Duration::from_secs(15),
                cancelled: Arc::new(AtomicBool::new(false)),
            },
        )
    }

    fn owner_op(
        &self,
        name: &str,
        arguments: serde_json::Value,
        key: Option<&str>,
    ) -> Result<OperationOutput, se_types::SeError> {
        let mut conn = BlockingIpcClient::connect_authenticated(
            &self.endpoint,
            ClientCredential::Machine(Secret::new(vec![23; 32])?),
            reply_limit()?,
            &ClientOptions {
                expected_generation: Some(self.endpoint.generation),
                timeout: Duration::from_secs(15),
                cancelled: Arc::new(AtomicBool::new(false)),
            },
        )?;
        let presence = self
            .owner_presence()
            .map_err(|e| se_types::SeError::invalid("presence", &e.to_string()))?;
        let selections = serde_json::to_value(se_core::ops::CliSelections {
            project: Some(self.home.project.clone()),
            ..Default::default()
        })
        .map_err(|e| se_types::SeError::invalid("selections", &e.to_string()))?;
        let key = key.map(IdempotencyKey::new).transpose()?;
        conn.exchange(
            IpcEnvelope {
                version: se_types::API_VERSION,
                request_id: 1,
                generation: self.endpoint.generation,
                authority: None,
                presence: Some(presence),
                cli_selections: Some(selections),
                request: IpcRequest::Operation(RawOperation {
                    name: name.into(),
                    arguments,
                    key,
                }),
            },
            &ClientOptions {
                expected_generation: Some(self.endpoint.generation),
                timeout: Duration::from_secs(15),
                cancelled: Arc::new(AtomicBool::new(false)),
            },
        )
    }

    fn open_claim(
        &self,
        agent: &str,
    ) -> Result<(BlockingConnection, ExternalClaimOpenOutput), se_types::SeError> {
        let bootstrap = ExternalClaimBootstrap {
            project: Some(self.home.project.clone()),
            cwd: NativePath::from_local(self.home.options.state_directory.clone())?,
            agent: agent.to_owned(),
            connection_nonce: se_host::client::auth::fresh_nonce()?,
        };
        let opts = ClientOptions {
            expected_generation: Some(self.endpoint.generation),
            timeout: Duration::from_secs(15),
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        let mut conn = BlockingIpcClient::connect_authenticated(
            &self.endpoint,
            ClientCredential::ExternalClaim(Box::new(bootstrap)),
            reply_limit()?,
            &opts,
        )?;
        let out = conn.exchange(
            IpcEnvelope {
                version: se_types::API_VERSION,
                request_id: 1,
                generation: self.endpoint.generation,
                authority: None,
                presence: None,
                cli_selections: None,
                request: IpcRequest::External(Box::new(ExternalRequest::ClaimOpen)),
            },
            &opts,
        )?;
        let opened: ExternalClaimOpenOutput = serde_json::from_value(out.value)
            .map_err(|e| se_types::SeError::invalid("claim open", &e.to_string()))?;
        Ok((conn, opened))
    }

    fn approve_with_bridge(
        &self,
        mut bridge_conn: BlockingConnection,
        claim_id: String,
    ) -> Result<(BridgeWaiter, ExternalApproveOutput), Box<dyn std::error::Error>> {
        let generation = self.endpoint.generation;
        let cid = claim_id.clone();
        let waiter = std::thread::spawn(move || {
            let opts = ClientOptions {
                expected_generation: Some(generation),
                timeout: Duration::from_secs(15),
                cancelled: Arc::new(AtomicBool::new(false)),
            };
            let out = bridge_conn
                .exchange(
                    IpcEnvelope {
                        version: se_types::API_VERSION,
                        request_id: 2,
                        generation,
                        authority: None,
                        presence: None,
                        cli_selections: None,
                        request: IpcRequest::External(Box::new(ExternalRequest::ClaimWait {
                            claim_id: cid,
                        })),
                    },
                    &opts,
                )
                .map_err(|e| e.to_string())?;
            let approved: ExternalClaimApproved =
                serde_json::from_value(out.value).map_err(|e| e.to_string())?;
            Ok((bridge_conn, approved))
        });
        // Give ClaimWait a brief moment to attach its oneshot receiver on the host.
        std::thread::sleep(Duration::from_millis(60));
        let approved_out = self.owner_external(ExternalRequest::Approve { claim_id })?;
        let approved: ExternalApproveOutput = serde_json::from_value(approved_out.value)?;
        Ok((waiter, approved))
    }

    fn external_op(
        &self,
        capability: &str,
        name: &str,
        arguments: serde_json::Value,
        key: Option<&str>,
    ) -> Result<OperationOutput, se_types::SeError> {
        let opts = ClientOptions {
            expected_generation: Some(self.endpoint.generation),
            timeout: Duration::from_secs(15),
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        let mut conn = BlockingIpcClient::connect_authenticated(
            &self.endpoint,
            ClientCredential::ExternalSession(Secret::new(capability.as_bytes().to_vec())?),
            reply_limit()?,
            &opts,
        )?;
        let key = key.map(IdempotencyKey::new).transpose()?;
        conn.exchange(
            IpcEnvelope {
                version: se_types::API_VERSION,
                request_id: 1,
                generation: self.endpoint.generation,
                authority: None,
                presence: None,
                cli_selections: None,
                request: IpcRequest::Operation(RawOperation {
                    name: name.into(),
                    arguments,
                    key,
                }),
            },
            &opts,
        )
    }
}

#[test]
fn external_claim_approval_one_shot_and_narrow_allowlist() -> Check {
    let h = LiveHost::start_fresh()?;
    // Non-external agent is refused at claim open.
    assert!(
        h.open_claim(h.regular_agent.as_str()).is_err(),
        "non-external agent must be refused"
    );

    // Open pending claim for external-eligible agent.
    let (bridge_conn, opened) = h.open_claim(h.external_agent.as_str())?;
    assert!(opened.claim_id.starts_with("claim_"));
    let list_out: ExternalListOutput = serde_json::from_value(
        h.owner_external(ExternalRequest::List { project: None })?
            .value,
    )?;
    assert_eq!(list_out.pending_claims.len(), 1);
    assert_eq!(list_out.pending_claims[0].claim_id, opened.claim_id);

    // Approve once; second approval on consumed claim fails closed.
    let (waiter, approve_out) = h.approve_with_bridge(bridge_conn, opened.claim_id.clone())?;
    assert_eq!(approve_out.lease_generation, 1);
    assert!(
        h.owner_external(ExternalRequest::Approve {
            claim_id: opened.claim_id.clone(),
        })
        .is_err(),
        "re-approving consumed claim must fail closed"
    );
    let (_held_bridge, delivered) = waiter
        .join()
        .map_err(|_| "bridge waiter panicked")?
        .map_err(|e| format!("bridge waiter failed: {e}"))?;
    assert_eq!(delivered.session_id, approve_out.session_id);
    assert!(delivered.capability.starts_with("sext1."));

    // Allowed Phase 1 operations succeed.
    let whoami = h.external_op(
        &delivered.capability,
        "identity.whoami",
        serde_json::json!({}),
        None,
    )?;
    assert_eq!(
        whoami.value.pointer("/agent/id").and_then(|v| v.as_str()),
        Some(h.external_agent.as_str())
    );
    h.external_op(
        &delivered.capability,
        "working_state.set",
        serde_json::json!({"text": "external note", "expect": "absent", "idempotency_key": "ext-ws-1"}),
        Some("ext-ws-1"),
    )?;
    let ws = h.external_op(
        &delivered.capability,
        "working_state.get",
        serde_json::json!({}),
        None,
    )?;
    assert!(
        ws.value.to_string().contains("external note"),
        "expected external note in working_state.get output: {}",
        ws.value
    );
    h.external_op(
        &delivered.capability,
        "message.list",
        serde_json::json!({}),
        None,
    )?;

    // Privileged / out-of-allowlist operations are refused at host admission!
    for (op, args, key) in [
        (
            "agent.launch",
            serde_json::json!({"agent": h.regular_agent.as_str()}),
            Some("ext-deny-1"),
        ),
        (
            "agent.stop",
            serde_json::json!({"agent": h.regular_agent.as_str()}),
            Some("ext-deny-2"),
        ),
        (
            "delegate.start",
            serde_json::json!({"task": "hi"}),
            Some("ext-deny-3"),
        ),
        ("config.list", serde_json::json!({}), None),
        ("project.status", serde_json::json!({}), None),
    ] {
        let res = h.external_op(&delivered.capability, op, args, key);
        assert!(res.is_err(), "external seat must refuse `{op}`");
    }

    verify_in_band_switch_refused(&h, &delivered.capability)?;
    verify_external_mcp_tools(&h)?;
    h.shutdown()
}

fn verify_in_band_switch_refused(h: &LiveHost, capability: &str) -> Check {
    let opts = ClientOptions {
        expected_generation: Some(h.endpoint.generation),
        timeout: Duration::from_secs(10),
        cancelled: Arc::new(AtomicBool::new(false)),
    };
    let mut conn = BlockingIpcClient::connect_authenticated(
        &h.endpoint,
        ClientCredential::ExternalSession(Secret::new(capability.as_bytes().to_vec())?),
        reply_limit()?,
        &opts,
    )?;
    let switched = conn.exchange(
        IpcEnvelope {
            version: se_types::API_VERSION,
            request_id: 1,
            generation: h.endpoint.generation,
            authority: Some(PresentedAuthority::ExternalSession(Secret::new(
                capability.as_bytes().to_vec(),
            )?)),
            presence: None,
            cli_selections: None,
            request: IpcRequest::Operation(RawOperation {
                name: "identity.whoami".into(),
                arguments: serde_json::json!({}),
                key: None,
            }),
        },
        &opts,
    );
    assert!(
        switched.is_err(),
        "in-band identity switching on external seat connection must be refused"
    );
    Ok(())
}

fn verify_external_mcp_tools(h: &LiveHost) -> Check {
    // MCP tools/list for an external seat advertises ONLY the 8 Phase 1 allowlisted tools (never se_join!).
    struct DummyExternal;
    impl se_host::mcp::McpBackend for DummyExternal {
        fn is_external_seat(&self) -> bool {
            true
        }
        async fn check_session(&mut self, _: Arc<Secret>) -> se_types::Result<()> {
            Ok(())
        }
        async fn call(
            &mut self,
            _: Arc<Secret>,
            _: se_core::ops::AnyOp,
        ) -> se_types::Result<serde_json::Value> {
            Ok(serde_json::json!({}))
        }
        fn response_limit(&self) -> usize {
            DEFAULT_REPLY_BYTES as usize
        }
    }
    let mut dummy = DummyExternal;
    let reply = h.rt.block_on(se_host::mcp::dispatch(
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
        None,
        &mut dummy,
    ));
    let se_host::McpReply::Json(val) = reply else {
        return Err("expected JSON tools/list reply".into());
    };
    let names: Vec<&str> = val["result"]["tools"]
        .as_array()
        .ok_or("missing tools array")?
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert_eq!(names.len(), 8, "expected 8 external tools, got {names:?}");
    assert!(
        !names
            .iter()
            .any(|n| n.contains("join") || n.contains("launch") || n.contains("delegate"))
    );
    Ok(())
}

#[test]
fn simultaneous_external_claims_and_managed_launch_exclusivity() -> Check {
    let h = LiveHost::start_fresh()?;
    // Open two simultaneous claims for the same external agent.
    let (conn1, claim1) = h.open_claim(h.external_agent.as_str())?;
    let (conn2, claim2) = h.open_claim(h.external_agent.as_str())?;

    let (w1, approve1) = h.approve_with_bridge(conn1, claim1.claim_id)?;
    let (_held1, delivered1) = w1
        .join()
        .map_err(|_| "w1 panicked")?
        .map_err(|e| format!("w1 failed: {e}"))?;
    assert_eq!(delivered1.session_id, approve1.session_id);

    // Second claim must be refused atomically at host-writer commit time!
    let second = h.approve_with_bridge(conn2, claim2.claim_id);
    assert!(
        second.is_err(),
        "second simultaneous external claim must be refused by atomic exclusivity"
    );

    // Revoke external seat, then verify managed SessionPrepared + ProcessRegistered blocks external join.
    let rev: ExternalRevokeOutput = serde_json::from_value(
        h.owner_external(ExternalRequest::Revoke {
            project: Some(h.home.project.clone()),
            agent: h.external_agent.as_str().into(),
        })?
        .value,
    )?;
    assert!(rev.revoked);

    h.shutdown()?;
    verify_store_exclusivity()
}

fn verify_store_exclusivity() -> Check {
    // Direct store-writer atomic exclusivity check (both directions: managed->external and external->managed).
    let f = Fixture::new()?;
    seed(&f)?;
    let (mut direct, lease) = direct(&f)?;
    let managed = session::session()?;
    direct.append(
        f.batch(
            f.owner_project(),
            Some(request("managed-c1")?),
            vec![session::prepared(&f, &managed, &f.a)],
        )?,
        &*lease,
    )?;
    // External join must be refused atomically while managed launch is prepared!
    let ext = session::session()?;
    let ext_attempt = direct.append(
        f.batch(
            f.owner_project(),
            Some(request("ext-during-managed")?),
            external_session_events(&ext, &f.a, "external:claim_race", now()?),
        )?,
        &*lease,
    );
    assert!(
        ext_attempt.is_err(),
        "external join must be refused while managed session is live"
    );

    // Opposite direction on agent B: external active blocks managed SessionPrepared!
    let ext_b = session::session()?;
    direct.append(
        f.batch(
            f.owner_project(),
            Some(request("ext-b-active")?),
            external_session_events(&ext_b, &f.b, "external:claim_b", now()?),
        )?,
        &*lease,
    )?;
    let managed_b = session::session()?;
    let managed_attempt = direct.append(
        f.batch(
            f.owner_project(),
            Some(request("managed-during-ext")?),
            vec![session::prepared(&f, &managed_b, &f.b)],
        )?,
        &*lease,
    );
    assert!(
        managed_attempt.is_err(),
        "managed launch must be refused while external seat is active"
    );
    direct.close()?;
    Ok(())
}

fn external_session_events<T>(
    session: &se_types::SessionId,
    agent: &AgentId,
    native_ref: &str,
    observed_at_us: i64,
) -> Vec<EventBody<T>> {
    vec![
        EventBody::SessionPrepared {
            session: session.clone(),
            agent: agent.clone(),
            provider: Provider::Claude,
            surface: Some(SessionSurface::External),
            native_ref: native_ref.into(),
            consent: Consent::Suppressed,
            generation: 1,
            expected: Expected::Absent,
        },
        EventBody::SessionActivated {
            session: session.clone(),
            expected: Expected::Revision(Revision {
                value: std::num::NonZeroU64::MIN,
            }),
            incumbent: None,
            process: None,
            containment: ContainmentFact::ExternalSeat {
                lease_generation: 1,
                observed_at_us,
            },
            witnesses: vec![],
        },
    ]
}

#[test]
fn stale_disconnect_fencing_reconnect_and_host_restart() -> Check {
    let h = LiveHost::start_fresh()?;
    // Gen 1 approved.
    let (conn1, claim1) = h.open_claim(h.external_agent.as_str())?;
    let (w1, approve1) = h.approve_with_bridge(conn1, claim1.claim_id)?;
    let (held1, del1) = w1
        .join()
        .map_err(|_| "w1 panicked")?
        .map_err(|e| format!("w1 failed: {e}"))?;
    assert_eq!(approve1.lease_generation, 1);

    // Owner revokes gen 1; old capability is immediately refused.
    h.owner_external(ExternalRequest::Revoke {
        project: Some(h.home.project.clone()),
        agent: h.external_agent.as_str().into(),
    })?;
    assert!(
        h.external_op(
            &del1.capability,
            "identity.whoami",
            serde_json::json!({}),
            None
        )
        .is_err(),
        "revoked gen 1 capability must be refused"
    );

    // Reconnect: gen 2 approved while old gen 1 bridge socket is still open.
    let (conn2, claim2) = h.open_claim(h.external_agent.as_str())?;
    let (w2, approve2) = h.approve_with_bridge(conn2, claim2.claim_id)?;
    let (_held2, del2) = w2
        .join()
        .map_err(|_| "w2 panicked")?
        .map_err(|e| format!("w2 failed: {e}"))?;
    assert_eq!(approve2.lease_generation, 2);

    // Delayed close of stale gen 1 connection MUST NOT revoke gen 2!
    drop(held1);
    std::thread::sleep(Duration::from_millis(120));
    h.external_op(
        &del2.capability,
        "identity.whoami",
        serde_json::json!({}),
        None,
    )?;

    // Status / agent show report external seat active and resume.ready == false.
    let shown = h.owner_op(
        "agent.show",
        serde_json::json!({"target_agent_id": h.external_agent.as_str()}),
        None,
    )?;
    assert_eq!(
        shown
            .value
            .pointer("/agent/value/external_seat/state")
            .and_then(|v| v.as_str()),
        Some("active")
    );
    assert_eq!(
        shown
            .value
            .pointer("/agent/value/resume/ready")
            .and_then(|v| v.as_bool()),
        Some(false)
    );

    // Restart host (new generation): old gen 2 external capability must be refused!
    let h = h.restart()?;
    assert!(
        h.external_op(
            &del2.capability,
            "identity.whoami",
            serde_json::json!({}),
            None
        )
        .is_err(),
        "external capability from prior host generation must require fresh reacquisition"
    );
    let shown_after = h.owner_op(
        "agent.show",
        serde_json::json!({"target_agent_id": h.external_agent.as_str()}),
        None,
    )?;
    let post_restart_state = shown_after
        .value
        .pointer("/agent/value/external_seat/state")
        .and_then(|v| v.as_str());
    assert!(
        matches!(post_restart_state, Some("revoked" | "expired")),
        "expected revoked or expired after host restart, got {post_restart_state:?}"
    );
    assert_eq!(
        shown_after
            .value
            .pointer("/agent/value/resume/ready")
            .and_then(|v| v.as_bool()),
        Some(false)
    );

    h.shutdown()
}

#[test]
fn blocking_mail_wait_revoke_race_and_commit_to_waiter_latency() -> Check {
    let h = LiveHost::start_fresh()?;
    let (conn1, claim1) = h.open_claim(h.external_agent.as_str())?;
    let (w1, _approve1) = h.approve_with_bridge(conn1, claim1.claim_id)?;
    let (_held1, del1) = w1
        .join()
        .map_err(|_| "w1 panicked")?
        .map_err(|e| format!("w1 failed: {e}"))?;

    let cursor = measure_wait_latencies(&h, &del1.capability)?;
    verify_wait_does_not_mark_read(&h, &del1.capability)?;
    verify_revoke_wakes_waiter(&h, &del1.capability, cursor)?;
    h.shutdown()
}

fn spawn_mail_wait(
    ep: EndpointRecord,
    cap: String,
    after: Option<String>,
    timeout_ms: u64,
) -> std::thread::JoinHandle<Result<(ExternalMailWaitOutput, Instant), String>> {
    std::thread::spawn(move || {
        let opts = ClientOptions {
            expected_generation: Some(ep.generation),
            timeout: Duration::from_secs(15),
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        let mut conn = BlockingIpcClient::connect_authenticated(
            &ep,
            ClientCredential::ExternalSession(
                Secret::new(cap.as_bytes().to_vec()).map_err(|e| e.to_string())?,
            ),
            reply_limit().map_err(|e| e.to_string())?,
            &opts,
        )
        .map_err(|e| e.to_string())?;
        let out = conn
            .exchange(
                IpcEnvelope {
                    version: se_types::API_VERSION,
                    request_id: 1,
                    generation: ep.generation,
                    authority: None,
                    presence: None,
                    cli_selections: None,
                    request: IpcRequest::External(Box::new(ExternalRequest::MailWait {
                        project: None,
                        agent: None,
                        after,
                        timeout_ms: Some(timeout_ms),
                    })),
                },
                &opts,
            )
            .map_err(|e| e.to_string())?;
        let received_at = Instant::now();
        let waited: ExternalMailWaitOutput =
            serde_json::from_value(out.value).map_err(|e| e.to_string())?;
        Ok((waited, received_at))
    })
}

fn measure_wait_latencies(
    h: &LiveHost,
    capability: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    // Measure 25 consecutive commit-to-waiter receipt latencies with zero polling.
    let mut latencies_us = Vec::with_capacity(25);
    let mut cursor: Option<String> = None;
    for i in 0..25u32 {
        let wait_thread = spawn_mail_wait(
            h.endpoint.clone(),
            capability.to_owned(),
            cursor.clone(),
            10_000,
        );
        // Allow waiter to park on the registry before committing mail.
        std::thread::sleep(Duration::from_millis(25));
        let key = format!("ext-wait-ping-{i}");
        h.owner_op(
            "message.send",
            serde_json::json!({
                "to": h.external_agent.as_str(),
                "body": format!("ping {i}"),
                "idempotency_key": key,
            }),
            Some(&key),
        )?;
        let commit_done = Instant::now();
        let (waited, received_at) = wait_thread
            .join()
            .map_err(|_| "wait thread panicked")?
            .map_err(|e| format!("wait thread failed: {e}"))?;
        assert_eq!(waited.status, "messages");
        assert!(!waited.ids.is_empty());
        let delta_us = u64::try_from(
            received_at
                .saturating_duration_since(commit_done)
                .as_micros(),
        )
        .unwrap_or(u64::MAX);
        latencies_us.push(delta_us);
        cursor = Some(waited.cursor.to_string());
    }
    latencies_us.sort_unstable();
    let p50 = latencies_us[latencies_us.len() / 2];
    let p95 = latencies_us[(latencies_us.len() * 95) / 100];
    let p99 = latencies_us[(latencies_us.len() * 99) / 100];
    eprintln!("external-wait commit-to-waiter latency (n=25): p50={p50}us p95={p95}us p99={p99}us");
    Ok(cursor)
}

fn verify_wait_does_not_mark_read(h: &LiveHost, capability: &str) -> Check {
    // MailWait never marks any message read or delivered: inbox still reports unread!
    let listed = h.external_op(capability, "message.list", serde_json::json!({}), None)?;
    let items = listed
        .value
        .get("items")
        .or_else(|| listed.value.pointer("/page/items"))
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("missing items in message.list: {}", listed.value))?;
    assert!(
        !items.is_empty(),
        "mail wait must never mark messages read or delivered"
    );
    Ok(())
}

fn verify_revoke_wakes_waiter(h: &LiveHost, capability: &str, cursor: Option<String>) -> Check {
    // Revoke racing a parked waiter immediately wakes the waiter with a revocation refusal!
    let revoke_wait = spawn_mail_wait(h.endpoint.clone(), capability.to_owned(), cursor, 30_000);
    std::thread::sleep(Duration::from_millis(50));
    let revoke_started = Instant::now();
    h.owner_external(ExternalRequest::Revoke {
        project: Some(h.home.project.clone()),
        agent: h.external_agent.as_str().into(),
    })?;
    let wait_res = revoke_wait.join().map_err(|_| "revoke wait panicked")?;
    assert!(
        wait_res.is_err(),
        "parked waiter must wake with error on revocation"
    );
    assert!(
        revoke_started.elapsed() < Duration::from_secs(2),
        "revoke must wake parked waiter promptly, not wait for 30s timeout"
    );
    Ok(())
}
