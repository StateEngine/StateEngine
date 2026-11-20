//! An active session row is insufficient to renew without witnessed native custody.
#![cfg(any(target_os = "linux", windows))]
use se_host::client::{BlockingIpcClient, lease::ClientCredential};
use se_host::{EndpointRecord, HostedRuntime, initialize_host_process};
use se_store::{DirectStore, EventBody, Expected};
use se_types::{Detail, Secret};
use sha2::{Digest, Sha256};
#[path = "../../se-host/tests/support/wave2_host_fixture.rs"]
mod support;
use support::*;

#[test]
fn renewal_refuses_active_sessions_without_matching_native_custody() -> Check {
    let initialized = initialize_host_process()?;
    let fixture = Fixture::new()?;
    seed(&fixture)?;
    let capabilities = provision(&fixture)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(4)
        .build()?;
    runtime.block_on(async {
        let mut host = HostedRuntime::prepare(
            initialized,
            start(&fixture)?,
            runtime.handle().clone(),
            &bound()?,
        )
        .await?;
        host.configure(se_config::config_policy::ConfigFile::default())?;
        let listener = host.listen(runtime.handle().clone(), &bound()?).await?;
        let endpoint = listener.endpoint().clone();
        let stop = host.local_stop();
        let probe = async {
            let result = tokio::task::spawn_blocking(move || {
                refuse_without_custody(&endpoint, capabilities).map_err(|error| error.to_string())
            })
            .await;
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), probe).await;
        let report = exit.finish(&bound()?).await;
        result??;
        require(
            report.transport_closed && report.endpoint_retired && report.errors.is_empty(),
            format!("runtime custody not cleanly released: {:?}", report.errors),
        )
    })
}

fn provision(fixture: &Fixture) -> Result<Vec<Secret>, Box<dyn std::error::Error>> {
    let (mut writer, lease) = direct(fixture)?;
    let now = now()?;
    let mut capabilities = Vec::new();
    for (agent, symbol) in [(&fixture.a, 'A'), (&fixture.b, 'B')] {
        let session = session::session()?;
        let body = symbol.to_string().repeat(43);
        let secret = Secret::new(format!("sec1.{session}.{body}").into_bytes())?;
        let credential = se_core::ops::process_commit::session_credential_id(&session, "session")?;
        let events = vec![
            session::prepared(fixture, &session, agent),
            session::activated(&session)?,
            EventBody::CredentialIssued {
                credential,
                session: session.clone(),
                purpose: "session".into(),
                secret_sha256: Sha256::digest(secret.expose()).into(),
                expires_at_us: now + 120_000_000,
                activation_deadline_us: now + 60_000_000,
                expected: Expected::Absent,
            },
            EventBody::CredentialActivated {
                credential,
                session: session.clone(),
                expected: revision(1)?,
                first_request: session::record()?,
            },
        ];
        writer.append(
            fixture.batch(
                fixture.owner_project(),
                Some(fixture::request(&format!("renewal-fixture-{symbol}"))?),
                events,
            )?,
            &*lease,
        )?;
        capabilities.push(secret);
    }
    writer.close()?;
    drop(lease);
    Ok(capabilities)
}

fn refuse_without_custody(endpoint: &EndpointRecord, capabilities: Vec<Secret>) -> Check {
    for secret in capabilities {
        // Ordinary admission is the control that proves each synthetic session
        // row is active and usable before the stricter renewal check.
        let live = Secret::new(secret.expose().to_vec())?;
        let limit = positive(65_536)?;
        let connection = BlockingIpcClient::connect_authenticated(
            endpoint,
            ClientCredential::Session(live),
            limit,
            &options(),
        )?;
        require(
            connection.negotiated().lease.is_none(),
            "ordinary session returned a lease",
        )?;
        drop(connection);

        let refused = BlockingIpcClient::connect_authenticated(
            endpoint,
            ClientCredential::SessionBootstrap(secret),
            limit,
            &options(),
        );
        let error = refused
            .err()
            .ok_or("renewal granted without native custody")?;
        require(
            matches!(error.body.detail(), Detail::UsageInvalidValue(value)
                if value.argument == "session renewal"
                    && value.expected.contains("live native process tree")),
            format!("renewal did not reach the native custody check: {error}"),
        )?;
    }
    Ok(())
}
