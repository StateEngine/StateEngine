//! Bug: one paired machine claiming many source agents must not lock another machine's agents out of the destination.
#![cfg(all(feature = "remote", target_os = "linux"))]
use se_host::remote::auth::Security;
use se_host::remote::*;
use se_host::*;
use se_store::*;
use sha2::{Digest, Sha256};
use std::sync::Arc;
#[path = "support/wave2_host_fixture.rs"]
mod support;
use support::*;

const BUDGET: u64 = 4096;
type R<T> = Result<T, Box<dyn std::error::Error>>;

struct Identity;
impl CredentialSource for Identity {
    fn credential_sha256(&self) -> [u8; 32] {
        [31; 32]
    }
    fn credential(&self) -> se_types::Result<se_types::remote::LinkSecret> {
        Ok(se_types::remote::LinkSecret::new([31; 32]))
    }
}

fn grant(f: &Fixture, n: u8, machine: u8) -> R<se_store::remote::GrantRecord> {
    use se_store::remote::*;
    let at = now()?;
    let rev = Revision {
        value: std::num::NonZeroU64::new(1).ok_or("revision")?,
    };
    Ok(GrantRecord {
        grant: RemoteGrantId::from_parts(1_700_000_000_000, [n; 10])?,
        principal: RemotePrincipalId::from_parts(1_700_000_000_000, [n + 1; 10])?,
        device: RemoteDeviceId::from_parts(1_700_000_000_000, [n + 2; 10])?,
        credential_sha256: CredentialDigest(Sha256::digest([machine; 32]).into()),
        host: RemoteHostId(se_types::Sha256::from_bytes([31; 32])),
        store: f.store.clone(),
        subject: RemoteSubject::Machine {
            host: RemoteHostId(se_types::Sha256::from_bytes([machine; 32])),
        },
        scope: RemoteScope {
            targets: vec![RemoteTarget {
                project: f.project.clone(),
                agent: f.a.clone(),
            }],
            verbs: vec![RemoteVerb::List],
        },
        issued_at_us: at,
        last_use_at_us: at,
        expires_at_us: at + GRANT_INACTIVITY_US,
        authority_revision: rev,
        lease_revision: rev,
        state: GrantState::Active,
    })
}

fn invocation(
    f: &Fixture,
    machine: u8,
    n: u64,
    agent: &se_types::AgentId,
    target: &se_types::AgentId,
) -> R<RemoteInvocation> {
    Ok(RemoteInvocation {
        source: Some(RemoteSourceSession {
            host: RemoteHostId(se_types::Sha256::from_bytes([machine; 32])),
            project: f.project.clone(),
            agent: agent.clone(),
            session: se_types::SessionId::from_parts(1_700_000_000_000 + n, [7; 10])?,
            generation: se_types::Generation::new(1)?,
        }),
        request: RemoteRequest::List(RemoteList {
            targets: vec![RemoteTarget {
                project: f.project.clone(),
                agent: target.clone(),
            }],
            cursor: None,
            limit: 20,
            budget: 32768,
        }),
    })
}
fn connect_grants(f: &Fixture) -> Check {
    let (mut direct, lease) = direct(f)?;
    for (n, machine) in [(40u8, 28u8), (50, 29)] {
        direct.append(
            f.batch(
                f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
                Some(fixture::request(&format!("connect-{n}"))?),
                vec![EventBody::RemoteSecurity {
                    transition: se_store::remote::SecurityTransition::Connect {
                        grant: Box::new(grant(f, n, machine)?),
                    },
                }],
            )?,
            &*lease,
        )?;
    }
    direct.close()?;
    drop(lease);
    Ok(())
}

/// One authenticated session per machine: machine A, then machine B.
async fn machine_sessions(security: &Security, f: &Fixture) -> R<Vec<auth::AuthenticatedDevice>> {
    let mut devices = Vec::new();
    for (n, machine) in [(40u8, 28u8), (50, 29)] {
        let g = grant(f, n, machine)?;
        let hello = RemoteHello {
            protocol: se_types::ApiVersion {
                major: se_types::remote::CLIENT_PROTOCOL_MAJOR,
                minor: se_types::remote::CLIENT_PROTOCOL_MINOR,
            },
            host: security.host(),
            grant: g.grant.clone(),
            device: g.device.clone(),
            authority_revision: 1,
        };
        let connection = security.accepted_connection()?;
        devices.push(
            security
                .authenticate_session(
                    connection,
                    hello,
                    se_types::remote::LinkSecret::new([machine; 32]),
                )
                .await?,
        );
    }
    Ok(devices)
}

fn agent(i: u64) -> R<se_types::AgentId> {
    Ok(se_types::AgentId::from_parts(
        1_700_000_100_000 + i,
        [i as u8; 10],
    )?)
}

/// Machine A floods with sources aimed outside its granted target.
/// Those requests are refused before any source record exists.
fn flood_out_of_scope(
    security: &Security,
    devices: &[auth::AuthenticatedDevice],
    f: &Fixture,
) -> Check {
    for i in 0..BUDGET + 8 {
        let refused = security.authorize_invocation(
            &devices[0],
            invocation(f, 28, i, &agent(1_000_000 + i)?, &f.b)?,
        );
        require(refused.is_err(), "out-of-scope request was authorized")?;
    }
    Ok(())
}

fn check_budgets(security: &Security, devices: &[auth::AuthenticatedDevice], f: &Fixture) -> Check {
    flood_out_of_scope(security, devices, f)?;
    // Machine A can still admit a full budget of in-scope sources.
    for i in 0..BUDGET {
        security
            .authorize_invocation(&devices[0], invocation(f, 28, i, &agent(i)?, &f.a)?)
            .map_err(|e| format!("source {i} on machine A refused: {e}"))?;
    }
    // Its budget is now full; a new source on A is refused.
    require(
        security
            .authorize_invocation(
                &devices[0],
                invocation(f, 28, BUDGET, &agent(BUDGET)?, &f.a)?,
            )
            .is_err(),
        "machine A exceeded its source budget",
    )?;
    // Machine B is unaffected, and so are A's already admitted sources.
    security
        .authorize_invocation(&devices[1], invocation(f, 29, 0, &agent(0)?, &f.a)?)
        .map_err(|e| format!("machine B was locked out by machine A: {e}"))?;
    security
        .authorize_invocation(&devices[0], invocation(f, 28, 0, &agent(0)?, &f.a)?)
        .map_err(|e| format!("an already admitted source was refused: {e}"))?;
    Ok(())
}

#[test]
fn one_machine_cannot_exhaust_another_machines_source_budget() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    connect_grants(&f)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut runtime =
            HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        configure_private_listener(&mut runtime)?;
        let listener = runtime.listen(rt.handle().clone(), &bound()?).await?;
        let execution = runtime.execution_context();
        let store = Arc::new(se_host::remote::session::SecurityStore::new(
            execution.reader.as_ref().clone(),
            execution.writer.clone(),
            execution.generation.get(),
            f.owner.clone(),
        )?);
        let security = Security::new(
            store,
            &Identity,
            execution.generation,
            execution.blocking.clone(),
        )?;
        let devices = machine_sessions(&security, &f).await?;
        let result = check_budgets(&security, &devices, &f);
        runtime.local_stop().request();
        let exit = runtime.serve(listener).await;
        let report = exit.finish(&bound()?).await;
        require(
            report.transport_closed && report.endpoint_retired,
            "runtime did not retire",
        )?;
        result
    })
}
