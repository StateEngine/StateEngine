#![cfg(feature = "listener")]
#[path = "support/wave2_host_fixture.rs"]
mod host;
use host::{fixture::*, *};
use se_host::{
    client::{
        BlockingConnection, BlockingIpcClient, ClientOptions, lease::ClientCredential,
        presence::OwnerPresence, wire::DEFAULT_REPLY_BYTES,
    },
    events::{ControlFrame, EventStreamKind, SubscribeFrame, SubscribeRequest},
    external::{
        ExternalApproveOutput, ExternalClaimApproved, ExternalClaimBootstrap,
        ExternalClaimOpenOutput, ExternalRequest,
    },
    *,
};
use se_store::*;
use se_types::{AgentId, IdempotencyKey, NativePath, Secret};
use std::{
    num::NonZeroU32,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

fn reply_limit() -> se_types::Result<NonZeroU32> {
    NonZeroU32::new(DEFAULT_REPLY_BYTES)
        .ok_or_else(|| se_types::SeError::invalid("reply_limit", "positive"))
}

struct LiveHost {
    rt: tokio::runtime::Runtime,
    endpoint: EndpointRecord,
    stop: LocalStop,
    task: Option<tokio::task::JoinHandle<HostServeExit>>,
    home: Fixture,
    agent_a: AgentId,
    agent_b: AgentId,
}

impl LiveHost {
    fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let f = Fixture::new()?;
        seed(&f)?;
        let agent_a = f.a.clone();
        let agent_b = f.b.clone();
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
            for (agent, external) in [(&agent_a, true), (&agent_b, false)] {
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
                    Some(request("seed-events-sub-profiles")?),
                    events,
                )?,
                &*lease,
            )?;
            direct.close()?;
        }
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
            agent_a,
            agent_b,
        })
    }

    fn owner_opts(&self, timeout: Duration) -> ClientOptions {
        ClientOptions {
            expected_generation: Some(self.endpoint.generation),
            timeout,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    fn owner_conn(&self, timeout: Duration) -> se_types::Result<BlockingConnection> {
        let key = Secret::new(vec![23; 32])?;
        BlockingIpcClient::connect_authenticated(
            &self.endpoint,
            ClientCredential::Machine(key),
            reply_limit()?,
            &self.owner_opts(timeout),
        )
    }

    fn owner_presence(&self) -> Result<OwnerPresence, Box<dyn std::error::Error>> {
        let self_peer = se_proc::native_ipc::observe_ipc_self()?;
        let owner = match self_peer.principal() {
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

    fn send_mail(
        &self,
        to: &AgentId,
        body: &str,
        key: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.owner_conn(Duration::from_secs(10))?;
        let env = IpcEnvelope {
            version: se_types::API_VERSION,
            request_id: 1,
            generation: self.endpoint.generation,
            authority: None,
            presence: None,
            cli_selections: Some(serde_json::json!({
                "project": self.home.project.as_str(),
            })),
            request: IpcRequest::Operation(RawOperation {
                name: "message.send".into(),
                key: Some(key.parse::<IdempotencyKey>()?),
                arguments: serde_json::json!({
                    "to": to.as_str(),
                    "body": body,
                    "idempotency_key": key,
                }),
            }),
        };
        let _ = conn.exchange(env, &self.owner_opts(Duration::from_secs(10)))?;
        Ok(())
    }

    fn approve_external_seat_a(
        &self,
    ) -> Result<(BlockingConnection, ExternalClaimApproved), Box<dyn std::error::Error>> {
        let opts = self.owner_opts(Duration::from_secs(10));
        let bootstrap = ExternalClaimBootstrap {
            project: Some(self.home.project.clone()),
            cwd: NativePath::from_local(self.home.home.clone())?,
            agent: self.agent_a.as_str().to_owned(),
            connection_nonce: se_host::client::auth::fresh_nonce()?,
        };
        let mut bridge = BlockingIpcClient::connect_authenticated(
            &self.endpoint,
            ClientCredential::ExternalClaim(Box::new(bootstrap)),
            reply_limit()?,
            &opts,
        )?;
        let open = bridge.exchange(
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
        let opened: ExternalClaimOpenOutput = serde_json::from_value(open.value)?;
        let claim_id = opened.claim_id.clone();
        let generation = self.endpoint.generation;
        let wait_opts = self.owner_opts(Duration::from_secs(15));
        let waiter = std::thread::spawn(move || {
            let out = bridge
                .exchange(
                    IpcEnvelope {
                        version: se_types::API_VERSION,
                        request_id: 2,
                        generation,
                        authority: None,
                        presence: None,
                        cli_selections: None,
                        request: IpcRequest::External(Box::new(ExternalRequest::ClaimWait {
                            claim_id,
                        })),
                    },
                    &wait_opts,
                )
                .map_err(|e| e.to_string())?;
            let approved: ExternalClaimApproved =
                serde_json::from_value(out.value).map_err(|e| e.to_string())?;
            Ok::<_, String>((bridge, approved))
        });

        let mut owner = self.owner_conn(Duration::from_secs(10))?;
        let presence = self.owner_presence()?;
        let out = owner.exchange(
            IpcEnvelope {
                version: se_types::API_VERSION,
                request_id: 1,
                generation: self.endpoint.generation,
                authority: None,
                presence: Some(presence),
                cli_selections: None,
                request: IpcRequest::External(Box::new(ExternalRequest::Approve {
                    claim_id: opened.claim_id,
                })),
            },
            &opts,
        )?;
        let _: ExternalApproveOutput = serde_json::from_value(out.value)?;
        let (bridge, approved) = waiter.join().map_err(|_| "waiter panicked")??;
        Ok((bridge, approved))
    }

    fn revoke_external_seat_a(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut owner = self.owner_conn(Duration::from_secs(10))?;
        let presence = self.owner_presence()?;
        let opts = self.owner_opts(Duration::from_secs(10));
        let _ = owner.exchange(
            IpcEnvelope {
                version: se_types::API_VERSION,
                request_id: 1,
                generation: self.endpoint.generation,
                authority: None,
                presence: Some(presence),
                cli_selections: None,
                request: IpcRequest::External(Box::new(ExternalRequest::Revoke {
                    project: Some(self.home.project.clone()),
                    agent: self.agent_a.as_str().to_owned(),
                })),
            },
            &opts,
        )?;
        Ok(())
    }
}

impl Drop for LiveHost {
    fn drop(&mut self) {
        self.stop.request();
        if let Some(task) = self.task.take() {
            let _ = self.rt.block_on(task);
        }
    }
}

#[test]
fn owner_subscribe_pushes_body_free_mail_notice_and_resumes_from_cursor()
-> Result<(), Box<dyn std::error::Error>> {
    let host = LiveHost::start()?;
    let mut sub_conn = host.owner_conn(Duration::from_secs(10))?;
    let call = IpcEnvelope {
        version: se_types::API_VERSION,
        request_id: 1,
        generation: host.endpoint.generation,
        authority: None,
        presence: None,
        cli_selections: None,
        request: IpcRequest::Subscribe(Box::new(SubscribeRequest {
            project_id: Some(host.home.project.clone()),
            filter: Some(vec![EventStreamKind::MailNotice]),
            ..Default::default()
        })),
    };
    let opts = host.owner_opts(Duration::from_secs(10));
    let mut seen_heartbeat = false;
    let mut first_cursor = None;

    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut frames = Vec::new();
        let res = sub_conn.subscribe_events(call, &opts, |frame| {
            let is_hb = matches!(
                frame,
                SubscribeFrame::Control(ControlFrame::Heartbeat { .. })
            );
            frames.push(frame);
            if is_hb {
                let _ = ready_tx.send(());
                return Ok(true);
            }
            Ok(false)
        });
        (res, frames)
    });

    ready_rx.recv_timeout(Duration::from_secs(5))?;
    host.send_mail(&host.agent_a, "TOP-SECRET-BODY-DO-NOT-PUSH", "sub-msg-1")?;

    let (res, frames) = reader.join().map_err(|_| "reader panicked")?;
    res.map_err(|e| format!("stage 1 initial subscribe failed: {e}"))?;
    for f in frames {
        match f {
            SubscribeFrame::Control(ControlFrame::Heartbeat { head_cursor }) => {
                assert!(head_cursor.starts_with("evcur_v1_"));
                seen_heartbeat = true;
            }
            SubscribeFrame::Event(ev) => {
                assert_eq!(ev.kind, EventStreamKind::MailNotice);
                let serialized = serde_json::to_string(&ev.payload)?;
                assert!(
                    !serialized.contains("TOP-SECRET-BODY-DO-NOT-PUSH"),
                    "mail.notice leaked message body: {serialized}"
                );
                assert!(ev.payload.get("message_id").is_some());
                assert!(ev.payload.get("dedupe_digest").is_some());
                first_cursor = Some(ev.cursor);
            }
            other => return Err(format!("unexpected frame: {other:?}").into()),
        }
    }
    assert!(seen_heartbeat);
    let resume_cursor = first_cursor.ok_or("missing first mail.notice")?;

    // Send a second message while disconnected, then resume from first_cursor.
    host.send_mail(&host.agent_a, "SECOND-SECRET-BODY", "sub-msg-2")?;
    let mut resume_conn = host.owner_conn(Duration::from_secs(10))?;
    let mut resumed = Vec::new();
    resume_conn
        .subscribe_events(
            IpcEnvelope {
                version: se_types::API_VERSION,
                request_id: 1,
                generation: host.endpoint.generation,
                authority: None,
                presence: None,
                cli_selections: None,
                request: IpcRequest::Subscribe(Box::new(SubscribeRequest {
                    project_id: Some(host.home.project.clone()),
                    after_cursor: Some(resume_cursor),
                    filter: Some(vec![EventStreamKind::MailNotice]),
                    ..Default::default()
                })),
            },
            &host.owner_opts(Duration::from_secs(10)),
            |frame| {
                resumed.push(frame);
                Ok(false)
            },
        )
        .map_err(|e| format!("stage 2 resume subscribe failed: {e}"))?;
    assert_eq!(resumed.len(), 1);
    let SubscribeFrame::Event(ev2) = &resumed[0] else {
        return Err(format!("expected resumed event, got {:?}", resumed[0]).into());
    };
    assert_eq!(ev2.kind, EventStreamKind::MailNotice);
    assert!(!serde_json::to_string(&ev2.payload)?.contains("SECOND-SECRET-BODY"));
    assert_stale_cursor_refused(&host)?;
    Ok(())
}

fn assert_stale_cursor_refused(host: &LiveHost) -> Result<(), Box<dyn std::error::Error>> {
    let mut bad_conn = host.owner_conn(Duration::from_secs(10))?;
    let err = bad_conn
        .subscribe_events(
            IpcEnvelope {
                version: se_types::API_VERSION,
                request_id: 1,
                generation: host.endpoint.generation,
                authority: None,
                presence: None,
                cli_selections: None,
                request: IpcRequest::Subscribe(Box::new(SubscribeRequest {
                    project_id: Some(host.home.project.clone()),
                    after_cursor: Some("bad-cursor".into()),
                    ..Default::default()
                })),
            },
            &host.owner_opts(Duration::from_secs(10)),
            |_| Ok(false),
        )
        .err()
        .ok_or("expected stale_cursor refusal")?;
    assert_eq!(err.code(), se_types::Code::CursorInvalid, "{err}");
    Ok(())
}

#[test]
fn external_session_subscribe_enforces_scope_and_closes_on_revoke()
-> Result<(), Box<dyn std::error::Error>> {
    let host = LiveHost::start()?;
    let (_bridge, approved) = host.approve_external_seat_a()?;
    let cap = Secret::new(approved.capability.clone().into_bytes())?;

    // Cross-agent subscription is strictly refused.
    let mut cross_conn = BlockingIpcClient::connect_authenticated(
        &host.endpoint,
        ClientCredential::ExternalSession(Secret::new(cap.expose().to_vec())?),
        reply_limit()?,
        &host.owner_opts(Duration::from_secs(10)),
    )?;
    let err = cross_conn
        .subscribe_events(
            IpcEnvelope {
                version: se_types::API_VERSION,
                request_id: 1,
                generation: host.endpoint.generation,
                authority: None,
                presence: None,
                cli_selections: None,
                request: IpcRequest::Subscribe(Box::new(SubscribeRequest {
                    project_id: Some(host.home.project.clone()),
                    agent_id: Some(host.agent_b.clone()),
                    ..Default::default()
                })),
            },
            &host.owner_opts(Duration::from_secs(10)),
            |_| Ok(false),
        )
        .err()
        .ok_or("cross-agent subscribe must be refused")?;
    assert!(err.to_string().contains("agent_id"), "{err}");

    // Own-scope subscription terminates cleanly when Owner revokes the seat.
    let mut own_conn = BlockingIpcClient::connect_authenticated(
        &host.endpoint,
        ClientCredential::ExternalSession(cap),
        reply_limit()?,
        &host.owner_opts(Duration::from_secs(10)),
    )?;
    let call = IpcEnvelope {
        version: se_types::API_VERSION,
        request_id: 1,
        generation: host.endpoint.generation,
        authority: None,
        presence: None,
        cli_selections: None,
        request: IpcRequest::Subscribe(Box::new(SubscribeRequest {
            filter: Some(vec![EventStreamKind::MailNotice]),
            ..Default::default()
        })),
    };
    let opts = host.owner_opts(Duration::from_secs(10));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        own_conn.subscribe_events(call, &opts, |frame| {
            if matches!(
                frame,
                SubscribeFrame::Control(ControlFrame::Heartbeat { .. })
            ) {
                let _ = ready_tx.send(());
            }
            Ok(true)
        })
    });
    ready_rx.recv_timeout(Duration::from_secs(5))?;
    host.revoke_external_seat_a()?;
    let end = reader.join().map_err(|_| "reader panicked")?;
    let err = end
        .err()
        .ok_or("expected revoked stream to terminate with error")?;
    assert_eq!(err.code(), se_types::Code::CapabilityInvalid, "{err}");
    Ok(())
}
