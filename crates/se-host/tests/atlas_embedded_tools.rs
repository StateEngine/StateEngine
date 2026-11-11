//! Native linked catalogue/binding checks; provider search adoption is separate.
#![cfg(all(feature = "secode", target_os = "linux"))]
#[path = "support/shutdown_linked_fixture.rs"]
mod linked;
#[path = "support/wave2_host_fixture.rs"]
mod transport;
use fixture::*;
use linked::*;
use se_host::{
    IpcEnvelope, IpcRequest, RawOperation,
    client::{
        BlockingIpcClient, ClientOptions, endpoint::decode_endpoint, lease::ClientCredential,
    },
};
use se_store::{DirectStore, EventBody, Expected, PermissionProfile, Profile};
use secode_stateengine_api as api;
use std::{
    fs,
    io::Write,
    num::NonZeroU32,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
use transport::fixture;
fn protected(f: &Fixture, name: &str, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let files = se_proc::NativeStateFiles::open(&f.options.state_directory)?;
    let mut staged = files.create_staging(&f.options.state_directory)?;
    staged.file.write_all(bytes)?;
    staged.file.sync_all()?;
    drop(staged.file);
    files.publish_no_replace(&staged.path, &f.options.state_directory.join(name))?;
    Ok(())
}
fn hosted_status(
    home: &std::path::Path,
    project: se_types::ProjectId,
) -> Result<serde_json::Value, String> {
    let read = || -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let endpoint = decode_endpoint(&fs::read(home.join("endpoint.json"))?)?;
        let options = ClientOptions {
            expected_generation: Some(endpoint.generation),
            timeout: Duration::from_secs(30),
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        let mut connection = BlockingIpcClient::connect_authenticated(
            &endpoint,
            ClientCredential::Machine(se_types::Secret::new(fs::read(home.join("credential"))?)?),
            NonZeroU32::new(1_048_576).ok_or("zero reply budget")?,
            &options,
        )?;
        let response = connection.exchange(
            IpcEnvelope {
                version: connection.negotiated().version,
                request_id: 1,
                generation: endpoint.generation,
                authority: None,
                presence: None,
                cli_selections: Some(serde_json::json!({"project":project})),
                request: IpcRequest::Operation(RawOperation {
                    name: "project.status".into(),
                    arguments: serde_json::json!({}),
                    key: None,
                }),
            },
            &options,
        )?;
        if response.schema != "se.status/v1" {
            return Err("wrong hosted status family".into());
        }
        Ok(response.value)
    };
    read().map_err(|e| e.to_string())
}
#[test]
/// Bug: c322dd33 — an unsupported embedded host activated Atlas and advertised unavailable tools.
fn unsupported_embedded_atlas_stays_unavailable_and_bound_to_the_live_session() -> Check {
    check(None)
}

#[test]
#[ignore = "requires an exact native CLI in SE_ATLAS_JUDGE_SE"]
/// Bug: c322dd33 — HTTP and stdio advertised Atlas without a controller.
fn unsupported_atlas_discovery_agrees_over_http_and_stdio() -> Check {
    let image = std::path::PathBuf::from(
        std::env::var_os("SE_ATLAS_JUDGE_SE")
            .ok_or("SE_ATLAS_JUDGE_SE must pin the candidate CLI")?,
    );
    if !image.is_absolute() || !image.is_file() {
        return Err("SE_ATLAS_JUDGE_SE must name an existing absolute CLI path".into());
    }
    check(Some(image))
}

#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn check(image: Option<std::path::PathBuf>) -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    for agent in [&f.a, &f.b] {
        store.append(
            f.batch(
                f.owner_project(),
                Some(request(&format!("catalogue-profile-{agent}"))?),
                vec![EventBody::ProfileSaved {
                    agent: agent.clone(),
                    profile: Profile {
                        provider: se_store::Provider::Codex,
                        model: None,
                        permission: PermissionProfile::WorkspaceWrite,
                        named_profile: "default".into(),
                        effort: None,
                    },
                    expected: Expected::Absent,
                }],
            )?,
            &*lease,
        )?;
    }
    let discovery_session = transport::session::session()?;
    let native_capability = format!("sec1.{}.{}", discovery_session.as_str(), "A".repeat(43));
    if image.is_some() {
        let files = se_proc::NativeStateFiles::open(&f.options.state_directory)?;
        se_proc::publish_session_pin(
            &files,
            &discovery_session,
            &se_types::Secret::new(native_capability.as_bytes().to_vec())?,
        )?;
        let now = transport::now()?;
        let mut events = vec![se_store::EventBody::SessionPrepared {
            session: discovery_session.clone(),
            agent: f.b.clone(),
            provider: se_store::Provider::Claude,
            surface: None,
            native_ref: "catalogue-protocol-fixture".into(),
            consent: se_store::Consent::Suppressed,
            generation: 1,
            expected: Expected::Absent,
        }];
        let mut credentials = Vec::new();
        for (purpose, secret) in [
            ("http", "atlas-http-discovery"),
            ("session", native_capability.as_str()),
        ] {
            let event = transport::credential(
                &discovery_session,
                purpose,
                secret,
                now + 300_000_000,
                now + 60_000_000,
            )?;
            let EventBody::CredentialIssued { credential, .. } = &event else {
                return Err("credential setup".into());
            };
            credentials.push(*credential);
            events.push(event);
        }
        events.push(transport::session::activated(&discovery_session)?);
        for credential in credentials {
            events.push(EventBody::CredentialActivated {
                credential,
                session: discovery_session.clone(),
                expected: revision(1)?,
                first_request: transport::session::record()?,
            });
        }
        store.append(
            f.batch(
                f.owner_project(),
                Some(request("catalogue-discovery-credentials")?),
                events,
            )?,
            &*lease,
        )?;
    }
    store.close()?;
    drop(lease);
    protected(
        &f,
        "machine.json",
        br#"{"schema":"stateengine-machine/v1","machine_id":"atlas-native-catalogue"}"#,
    )?;
    protected(&f, "credential", &[29; 32])?;
    // ConfigFile defaults are product defaults; the test does not opt into
    // launching a provider, capture services or a substitute query controller.
    let mut config = se_core::config_policy::ConfigFile::default();
    let listener = (20000..30000)
        .find_map(|port| std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).ok())
        .ok_or("no available configured listener port")?;
    let listener_port = listener.local_addr()?.port();
    config.runtime.listen_port = Some(listener_port);
    drop(listener);
    fs::write(
        f.options.state_directory.join("config.toml"),
        toml::to_string(&config)?,
    )?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let factory = se_host::embedded_factory(runtime.handle().clone());
        let positive = |n| NonZeroU32::new(n).ok_or("zero bound");
        let config = api::HostConfig {
            state_home: f.options.state_directory.clone(),
            helper_executable: std::env::current_exe()?,
            linux_delegation: api::LinuxDelegation::CurrentScope,
            api: api::API_VERSION,
            kind: api::HostKind::EmbeddedSecode,
            features: vec![api::Feature::LocalListener],
            limits: api::Limits {
                page_items: positive(100)?,
                payload_bytes: positive(262144)?,
                notice_ids: positive(100)?,
            },
        };
        let opened = factory
            .open(
                config,
                api::OpenOptions {
                    expected_generation: None,
                    timeout: Duration::from_secs(30),
                    cancellation: Arc::new(NoopCancellation),
                },
            )
            .await
            .map_err(|e| format!("open: {e:?}"))?;
        let api::Read::Present { value: opened } = opened else {
            return Err("store not present".into());
        };
        let options = call_options(opened.negotiated.generation, Duration::from_secs(30));
        let epoch = build_epoch(opened.negotiated.generation.0, &f.options.state_directory)?;
        let ready = opened
            .host
            .activate(
                api::HostIntegration::Secode {
                    epoch,
                    services: Arc::new(SilentServices),
                },
                options.clone(),
            )
            .await
            .map_err(|e| format!("activate: {e:?}"))?;
        let cache_after_activation = f.options.state_directory.join("atlas").try_exists()?;
        let outcome = async {
            let request = api::BindingRequest {
                project: api::ProjectId(f.project.as_str().into()),
                agent: api::AgentId(f.a.as_str().into()),
                harness: api::Harness::Secode,
                model: api::ModelIdentity {
                    provider: "deterministic".into(),
                    model: "catalogue-consumer".into(),
                },
                conversation: api::ProviderSessionId("atlas-native-catalogue".into()),
                target: None,
                expected_binding_revision: None,
                capture_consent: false,
                idempotency_key: api::IdempotencyKey("atlas-catalogue-bind".into()),
            };
            let bound = opened
                .host
                .bind_session(
                    &api::BindingAuthority::Owner(api::OwnerAuthority),
                    request,
                    options.clone(),
                )
                .await
                .map_err(|e| format!("bind: {e:?}"))?
                .session;
            let page = opened
                .host
                .tools(
                    &bound,
                    api::PageRequest {
                        after: None,
                        limit: 1,
                        max_bytes: 65536,
                    },
                    options.clone(),
                )
                .await
                .map_err(|e| format!("tools: {e:?}"))?;
            let context = opened
                .host
                .continuity(
                    &bound,
                    api::ContinuityRequest {
                        page: api::PageRequest {
                            after: None,
                            limit: 20,
                            max_bytes: 4096,
                        },
                        acknowledge_packet: None,
                    },
                    options.clone(),
                )
                .await
                .map_err(|e| format!("continuity: {e:?}"))?;
            let model: serde_json::Value = serde_json::from_str(&context.model_input.text)?;
            let mut foreign = api::BoundSession {
                grant: bound.grant.clone(),
                identity: bound.identity.clone(),
                generation: bound.generation,
                binding_revision: bound.binding_revision,
            };
            foreign.identity.agent = api::AgentId(f.b.as_str().into());
            let foreign_refused = opened
                .host
                .tools(
                    &foreign,
                    api::PageRequest {
                        after: None,
                        limit: 5,
                        max_bytes: 65536,
                    },
                    options.clone(),
                )
                .await
                .is_err();
            let mutation_refused = opened
                .host
                .call_tool(
                    &bound,
                    api::ToolCall {
                        name: "stateengine_atlas_find".into(),
                        arguments: serde_json::json!({"query":"alpha"}),
                        identity: api::RequestIdentity::Mutation(api::IdempotencyKey(
                            "forbidden-query-write".into(),
                        )),
                    },
                    options.clone(),
                )
                .await
                .is_err();
            let home = f.options.state_directory.clone();
            let project = f.project.clone();
            let status =
                tokio::task::spawn_blocking(move || hosted_status(&home, project)).await??;
            let discovery = if let Some(image) = image {
                let http = transport::rpc(listener_port, "atlas-http-discovery", "tools/list", serde_json::json!({})).await?;
                let home = f.options.state_directory.clone();
                let session_handle = discovery_session.to_string();
                let stdio = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, String> {
                    let mut child = std::process::Command::new(image)
                        .args(["--home", home.to_str().ok_or("non-UTF8 fixture")?, "mcp", "--stdio"])
                        .env_clear().env("PATH", "/usr/bin:/bin").env("HOME", home.parent().ok_or("fixture owner absent")?)
                        .env("SE_SESSION", session_handle)
                        .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
                        .spawn().map_err(|e| e.to_string())?;
                    child.stdin.take().ok_or("stdio input absent")?.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n").map_err(|e| e.to_string())?;
                    let output = child.wait_with_output().map_err(|e| e.to_string())?;
                    if !output.status.success() { return Err(format!("stdio discovery failed: {}", String::from_utf8_lossy(&output.stderr))); }
                    serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())
                }).await??;
                Some((http, stdio))
            } else { None };
            let cache_after_reads = f.options.state_directory.join("atlas").try_exists()?;
            Ok::<_, Box<dyn std::error::Error>>((
                bound,
                page,
                context,
                model,
                foreign_refused,
                mutation_refused,
                status,
                cache_after_reads,
                discovery,
            ))
        }
        .await;
        let receipt = opened
            .host
            .drain(options.clone())
            .await
            .map_err(|e| format!("drain: {e:?}"))?;
        let drained = receipt.writer_flushed && receipt.unresolved_effects == 0;
        opened
            .host
            .close(receipt, options)
            .await
            .map_err(|e| format!("close: {e:?}"))?;
        // All assertions follow ordinary drain/close, including the old-candidate
        // regression failure, so a failed expectation cannot strand this host.
        let (
            bound,
            page,
            context,
            model,
            foreign_refused,
            mutation_refused,
            status,
            cache_after_reads,
            discovery,
        ) = outcome?;
        assert_eq!(ready, api::Readiness::Ready);
        assert!(drained);
        assert!(
            !f.options
                .state_directory
                .join("endpoint.json")
                .try_exists()?
        );
        let lock = fs::File::open(f.options.state_directory.join("runtime.lock"))?;
        lock.try_lock()?;
        if let Some((http, stdio)) = discovery {
            let mut unsupported = Vec::new();
            for (door, reply) in [("HTTP", http), ("stdio", stdio)] {
                let tools = reply["result"]["tools"].as_array().ok_or(format!("{door} tools absent: {reply}"))?;
                assert!(tools.iter().any(|tool| tool["name"] == "stateengine_status"), "{door} lost ordinary tools");
                if tools.iter().any(|tool| tool["name"].as_str().is_some_and(|name| name.starts_with("stateengine_atlas_"))) {
                    unsupported.push(door);
                }
                assert!(reply["result"]["nextCursor"].is_null(), "{door} discovery was not exhausted");
            }
            assert!(unsupported.is_empty(), "{unsupported:?} advertised unsupported Atlas tools");
        }
        assert!(
            !cache_after_activation && !cache_after_reads,
            "unsupported embedded host created an Atlas cache"
        );
        assert!(!f.options.state_directory.join("atlas").try_exists()?);
        assert!(
            page.items.is_empty(),
            "unsupported embedded host advertised Atlas tools"
        );
        assert_eq!(page.window.returned, 0);
        assert_eq!(page.window.bytes, 0);
        assert!(page.window.complete && page.next.is_none());
        assert_eq!(page.window.stop_reason, api::StopReason::Exhausted);
        assert_eq!(page.window.omitted_after, api::Omission::None);
        assert_eq!(page.window.unreadable, 0);
        assert!(page.window.bytes <= 65536);
        assert!(model["code_changes"].is_array());
        // Continuity's existing wire enum represents an unavailable optional
        // source as Unreadable; public status must distinguish absent controller.
        assert_eq!(model["code_status"]["state"], "Unreadable");
        assert_eq!(model["agent"], bound.identity.agent.0);
        assert!(context.model_input.utf8_bytes <= 4096);
        assert_eq!(status["atlas"]["state"], "unavailable");
        assert_eq!(status["atlas"]["history"], "unavailable");
        assert!(status["atlas"]["summary"].is_null());
        assert!(
            status["atlas"]["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("No Atlas controller"))
        );
        assert!(foreign_refused && mutation_refused);
        Ok(())
    })
}
