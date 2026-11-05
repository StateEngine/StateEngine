//! Native linked catalogue/binding checks; provider search adoption is separate.
#![cfg(all(feature = "secode", target_os = "linux"))]
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
#[path = "support/shutdown_linked_fixture.rs"]
mod linked;
use fixture::*;
use linked::*;
use se_store::DirectStore;
use secode_stateengine_api as api;
use std::{fs, io::Write, num::NonZeroU32, sync::Arc, time::Duration};
fn protected(f: &Fixture, name: &str, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let files = se_proc::NativeStateFiles::open(&f.options.state_directory)?;
    let mut staged = files.create_staging(&f.options.state_directory)?;
    staged.file.write_all(bytes)?;
    staged.file.sync_all()?;
    drop(staged.file);
    files.publish_no_replace(&staged.path, &f.options.state_directory.join(name))?;
    Ok(())
}
#[test]
fn native_tool_catalogue_is_paged_and_bound_to_the_live_session() -> Check {
    let f = Fixture::new()?;
    let (store, lease) = f.direct()?;
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
    fs::write(
        f.options.state_directory.join("config.toml"),
        toml::to_string(&se_core::config_policy::ConfigFile::default())?,
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
        assert_eq!(ready, api::Readiness::Ready);
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
            let mut names = Vec::new();
            let mut next = None;
            loop {
                let page = opened
                    .host
                    .tools(
                        &bound,
                        api::PageRequest {
                            after: next.clone(),
                            limit: 1,
                            max_bytes: 65536,
                        },
                        options.clone(),
                    )
                    .await
                    .map_err(|e| format!("tools: {e:?}"))?;
                assert_eq!(page.items.len(), 1);
                assert!(page.window.bytes <= 65536);
                let tool = &page.items[0];
                names.push(tool.name.clone());
                assert!(tool.input_schema.is_object() && tool.output_schema["oneOf"].is_array());
                assert!(!page.window.complete || page.next.is_none());
                match page.next {
                    Some(cursor) => {
                        assert_ne!(Some(&cursor), next.as_ref());
                        next = Some(cursor);
                    }
                    None => break,
                }
            }
            assert_eq!(names.len(), 5);
            assert!(names.contains(&"stateengine_atlas_find".into()));
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
            assert!(model["code_changes"].is_array());
            assert_eq!(model["code_status"]["state"], "Unreadable");
            assert_eq!(model["agent"], bound.identity.agent.0);
            assert!(context.model_input.utf8_bytes <= 4096);
            let mut foreign = api::BoundSession {
                grant: bound.grant.clone(),
                identity: bound.identity.clone(),
                generation: bound.generation,
                binding_revision: bound.binding_revision,
            };
            foreign.identity.agent = api::AgentId(f.b.as_str().into());
            assert!(
                opened
                    .host
                    .tools(
                        &foreign,
                        api::PageRequest {
                            after: None,
                            limit: 5,
                            max_bytes: 65536
                        },
                        options.clone()
                    )
                    .await
                    .is_err()
            );
            assert!(
                opened
                    .host
                    .call_tool(
                        &bound,
                        api::ToolCall {
                            name: "stateengine_atlas_find".into(),
                            arguments: serde_json::json!({"query":"alpha"}),
                            identity: api::RequestIdentity::Mutation(api::IdempotencyKey(
                                "forbidden-query-write".into()
                            ))
                        },
                        options.clone()
                    )
                    .await
                    .is_err()
            );
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let receipt = opened
            .host
            .drain(options.clone())
            .await
            .map_err(|e| format!("drain: {e:?}"))?;
        assert!(receipt.writer_flushed && receipt.unresolved_effects == 0);
        opened
            .host
            .close(receipt, options)
            .await
            .map_err(|e| format!("close: {e:?}"))?;
        outcome
    })
}
