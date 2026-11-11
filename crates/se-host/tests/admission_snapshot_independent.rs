//! Real native requests cannot combine old authority with post-fence data.
#![cfg(all(feature = "listener", any(target_os = "linux", windows)))]
use se_host::{
    client::{BlockingIpcClient, lease::ClientCredential},
    *,
};
use se_store::*;
use se_types::{API_VERSION, Secret};
use serde_json::{Value, json};
#[path = "support/wave2_host_fixture.rs"]
mod support;
use support::*;

const TOKEN: &str = "snapshot:synthetic-session-credential";
type NativeClient = std::thread::JoinHandle<Result<Value, String>>;

fn seed_session(f: &Fixture) -> Result<se_store::RecordId, Box<dyn std::error::Error>> {
    seed(f)?;
    let s = session::session()?;
    let issued = credential(
        &s,
        "session",
        TOKEN,
        now()? + 300_000_000,
        now()? + 60_000_000,
    )?;
    let EventBody::CredentialIssued { credential: id, .. } = &issued else {
        return Err("credential fixture".into());
    };
    let id = *id;
    let (mut d, lease) = direct(f)?;
    d.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("snapshot-seed")?),
            vec![
                session::prepared(f, &s, &f.a),
                issued,
                session::activated(&s)?,
                EventBody::CredentialActivated {
                    credential: id,
                    session: s,
                    expected: revision(1)?,
                    first_request: session::record()?,
                },
                EventBody::WorkingStateSet {
                    agent: f.a.clone(),
                    text: InputText::Inline("before-fence".into()),
                    expected: Expected::Absent,
                },
            ],
        )?,
        &*lease,
    )?;
    d.close()?;
    Ok(id)
}

fn call(generation: se_types::Generation, request_id: u64) -> IpcEnvelope {
    IpcEnvelope {
        version: API_VERSION,
        request_id,
        generation,
        authority: None,
        presence: None,
        cli_selections: None,
        request: IpcRequest::Operation(RawOperation {
            name: "working_state.get".into(),
            arguments: json!({}),
            key: None,
        }),
    }
}

async fn exchange(
    listener: &mut HostedListener,
    router: &HostedRouter,
) -> Result<(AdmittedExchange, NativeClient), Box<dyn std::error::Error>> {
    let endpoint = listener.endpoint().clone();
    let client = std::thread::spawn(move || -> Result<Value, String> {
        let mut connection = BlockingIpcClient::connect_authenticated(
            &endpoint,
            ClientCredential::Session(
                Secret::new(TOKEN.as_bytes().to_vec()).map_err(|e| e.to_string())?,
            ),
            positive(65536).map_err(|e| e.to_string())?,
            &options(),
        )
        .map_err(|e| e.to_string())?;
        let value = connection
            .exchange(call(endpoint.generation, 1), &options())
            .map_err(|e| e.to_string())?;
        Ok(value.value)
    });
    let accepted = listener.accept(options().cancelled).await?;
    let AcceptedPeer::Operation(connection) =
        router.authenticate_stream(accepted, &bound()?).await?
    else {
        return Err("session operation connection required".into());
    };
    let admitted = router
        .read_call(*connection, &bound()?)
        .await?
        .ok_or("missing native request")?;
    Ok((admitted, client))
}

async fn exercise(
    f: &Fixture,
    credential: se_store::RecordId,
    stop_unproved: bool,
    host: &HostedRuntime,
    listener: &mut HostedListener,
) -> Check {
    let router = host.router()?;
    let writer = host.execution_context().writer;
    let (mut admitted, client) = exchange(listener, &router).await?;
    // The actual production admission has returned. The writer's completed
    // receipt establishes the intervening fence before execution is resumed.
    if stop_unproved {
        old_stop_unproved(f, &writer).await?;
    } else {
        writer
            .submit(f.batch(
                f.owner_project(),
                Some(fixture::request("snapshot-revoke")?),
                vec![EventBody::CredentialRevoked {
                    credential,
                    expected: revision(2)?,
                    reason: InputText::Inline("synthetic revocation".into()),
                }],
            )?)?
            .await?;
    }
    writer
        .submit(f.batch(
            f.owner_project(),
            Some(fixture::request("snapshot-after-fence")?),
            vec![EventBody::WorkingStateSet {
                agent: f.a.clone(),
                text: InputText::Inline("after-fence-private".into()),
                expected: revision(1)?,
            }],
        )?)?
        .await?;
    let output = router.execute_call(admitted.take_call()?, &bound()?).await;
    let connection = admitted.reply(output, &bound()?).await?;
    drop(connection);
    let result = client
        .join()
        .map_err(|_| "native client panicked")?
        .map_err(std::io::Error::other)?;
    println!(
        "fence={} actual native reply={result}",
        if stop_unproved {
            "stop-unproved"
        } else {
            "revoked"
        }
    );
    require(
        result.to_string().contains("before-fence")
            && !result.to_string().contains("after-fence-private"),
        "an earlier admitted read exposed data written after its authority was fenced",
    )?;

    // A new transport with the same secret must fail authentication, without
    // requiring another process launch or an owner fallback.
    let endpoint = listener.endpoint().clone();
    let client = std::thread::spawn(move || -> Result<bool, String> {
        let response = BlockingIpcClient::connect_authenticated(
            &endpoint,
            ClientCredential::Session(
                Secret::new(TOKEN.as_bytes().to_vec()).map_err(|e| e.to_string())?,
            ),
            positive(65536).map_err(|e| e.to_string())?,
            &options(),
        );
        Ok(
            matches!(response, Err(error) if matches!(error.body.detail(), se_types::Detail::CapabilityInvalid(_))),
        )
    });
    let accepted = listener.accept(options().cancelled).await?;
    let response = router.authenticate_stream(accepted, &bound()?).await;
    let refused = matches!(response, Err(error) if matches!(error.body.detail(), se_types::Detail::CapabilityInvalid(_)));
    let client_refused = client
        .join()
        .map_err(|_| "native client panicked")?
        .map_err(std::io::Error::other)?;
    require(
        refused && client_refused,
        "new request bypassed the committed session fence",
    )
}

fn scenario(stop_unproved: bool) -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    let credential = seed_session(&f)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut host =
            HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        let mut listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let result = exercise(&f, credential, stop_unproved, &host, &mut listener).await;
        host.local_stop().request();
        let mut closed = host.serve(listener).await.finish(&bound()?).await;
        require(
            closed.transport_closed && closed.endpoint_retired,
            "native fixture transport cleanup failed",
        )?;
        // StopUnproved above is store-only setup, not a claimed native child.
        // Join the fixture writer even when its typed unresolved row remains.
        let storage = closed.runtime.drain_storage(&bound()?).await?;
        require(
            storage.writer_joined && storage.pending.is_empty(),
            "fixture writer did not join",
        )?;
        result
    })
}

#[test]
fn admitted_read_cannot_observe_data_after_revocation() -> Check {
    scenario(false)
}

#[test]
fn admitted_read_cannot_observe_data_after_stop_unproved() -> Check {
    scenario(true)
}
