//! Public Host consumers over real SQLite and native IPC. Typed session fixtures
//! establish authority only; these tests do not claim a real provider or phone.
#![cfg(all(feature = "listener", any(target_os = "linux", windows)))]
#[path = "support/wave2_host_fixture.rs"]
mod support;
use se_host::{
    channels::*,
    client::{BlockingIpcClient, lease::ClientCredential},
    *,
};
use se_store::*;
use support::*;

/// Protects: 49 — expose exact Rust selections and opaque credentials only through an open native Host.
#[test]
fn native_abi_lists_exact_rust_selections_and_protected_credential_references() -> Check {
    let f = Fixture::new()?;
    seed(&f)?;
    let (mut writer, lease) = direct(&f)?;
    for (agent, key) in [(&f.a, "profile-a"), (&f.b, "profile-b")] {
        writer.append(
            f.batch(
                f.owner_project(),
                Some(fixture::request(key)?),
                vec![EventBody::ProfileSaved {
                    agent: agent.clone(),
                    profile: Profile {
                        provider: Provider::Codex,
                        model: None,
                        permission: PermissionProfile::WorkspaceWrite,
                        named_profile: "codex".into(),
                        effort: None,
                    },
                    expected: Expected::Absent,
                }],
            )?,
            &*lease,
        )?;
    }
    writer.close()?;
    drop(lease);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let initialized = initialize_host_process()?;
        let mut host =
            HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        configure_private_listener(&mut host)?;
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let channels = host.channels()?;
        let vault = NativeChannelCredentials::open(
            &f.options.state_directory,
            f.store.clone(),
            f.owner.clone(),
        )?;
        let reference = vault.provision(&mut &b"123456:dummy_invalid_provider_token_123456"[..])?;
        let catalog = channels.credential_catalog(&bound()?).await?;
        assert_eq!(catalog.credentials, vec![reference]);
        let choices = channels
            .targets(
                ChannelTargets {
                    project: f.project.clone(),
                    after: None,
                },
                &bound()?,
            )
            .await?;
        assert_eq!(choices.items().len(), 2);
        for choice in choices.items() {
            assert_eq!(choice.target.selection_revision, 1);
            assert_eq!(choice.profile_revision, 1);
            assert_eq!(choice.saved.role.as_deref(), Some("builder"));
        }
        let page = channels
            .inspect(
                InspectChannels {
                    connection: None,
                    receipt: None,
                    cursor: None,
                    wait_until_us: None,
                },
                &bound()?,
            )
            .await?;
        assert!(page.complete && page.connections.is_empty() && page.receipts.is_empty());

        let stop = host.local_stop();
        let client = async {
            stop.request();
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let (exit, result) = join(host.serve(listener), client).await;
        let report = exit.finish(&bound()?).await;
        result?;
        assert!(report.transport_closed && report.endpoint_retired);
        let refused = channels.credential_catalog(&bound()?).await;
        assert!(refused.is_err());
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}
/// Protects: 49 — deny native Channels control to a valid agent session over actual IPC.
#[test]
fn current_agent_session_cannot_enter_native_owner_channel_frames() -> Check {
    let f = Fixture::new()?;
    seed(&f)?;
    let (mut writer, lease) = direct(&f)?;
    let s = session::session()?;
    let at = now()?;
    let issued = credential(
        &s,
        "session",
        "channel-agent-fixture",
        at + 300000000,
        at + 60000000,
    )?;
    let EventBody::CredentialIssued {
        credential: credential_id,
        ..
    } = &issued
    else {
        return Err("credential kind".into());
    };
    let credential_id = *credential_id;
    writer.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("active-channel-agent")?),
            vec![
                session::prepared(&f, &s, &f.a),
                issued,
                session::activated(&s)?,
                EventBody::CredentialActivated {
                    credential: credential_id,
                    session: s,
                    expected: revision(1)?,
                    first_request: session::record()?,
                },
            ],
        )?,
        &*lease,
    )?;
    writer.close()?;
    drop(lease);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let initialized = initialize_host_process()?;
        let mut host =
            HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        configure_private_listener(&mut host)?;
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let endpoint = listener.endpoint().clone();
        let stop = host.local_stop();
        let client = async move {
            let result = tokio::task::spawn_blocking(move || {
                let work = || -> Check {
                    let mut connection = BlockingIpcClient::connect_authenticated(
                        &endpoint,
                        ClientCredential::Session(se_types::Secret::new(
                            b"channel-agent-fixture".to_vec(),
                        )?),
                        positive(256 * 1024)?,
                        &options(),
                    )?;
                    for (index, request) in [
                        ChannelRequest::Capabilities,
                        ChannelRequest::CredentialCatalog,
                        ChannelRequest::Inspect(InspectChannels {
                            connection: None,
                            receipt: None,
                            cursor: None,
                            wait_until_us: None,
                        }),
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        let error = connection
                            .exchange(
                                IpcEnvelope {
                                    version: se_types::API_VERSION,
                                    request_id: index as u64 + 1,
                                    generation: endpoint.generation,
                                    authority: None,
                                    presence: None,
                                    cli_selections: None,
                                    request: IpcRequest::Channels(request),
                                },
                                &options(),
                            )
                            .err()
                            .ok_or("session entered native Owner frame")?;
                        assert_eq!(error.code(), se_types::Code::OwnerRequired);
                    }
                    Ok(())
                };
                work().map_err(|error| error.to_string())
            })
            .await;
            stop.request();
            result
                .map_err(|_| "native IPC client task failed")?
                .map_err(|error| -> Box<dyn std::error::Error> { error.into() })
        };
        let (exit, result) = join(host.serve(listener), client).await;
        let report = exit.finish(&bound()?).await;
        assert!(report.transport_closed && report.endpoint_retired);
        result
    })
}
