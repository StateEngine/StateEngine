//! Shared target authorization over a real native store/writer on Windows.
//! SSH possession and socket closure are exercised by separate transport controls.
#![cfg(all(windows, feature = "remote"))]
use se_host::remote::{
    auth::{Security, VerifiedLocalOwner},
    keys::ProtectedCredential,
    session::{RevokeGrant, SecurityStore},
    *,
};
use se_host::*;
use se_store::{remote::*, *};
use se_types::{IdempotencyKey, Read};
use sha2::{Digest, Sha256};
use std::sync::Arc;
#[path = "support/wave2_host_fixture.rs"]
mod support;
use support::*;

fn seed_grant(f: &Fixture) -> Result<GrantRecord, Box<dyn std::error::Error>> {
    let at = now()?;
    let grant = GrantRecord {
        grant: RemoteGrantId::from_parts(1_700_000_000_000, [61; 10])?,
        principal: RemotePrincipalId::from_parts(1_700_000_000_000, [62; 10])?,
        device: RemoteDeviceId::from_parts(1_700_000_000_000, [63; 10])?,
        credential_sha256: CredentialDigest(Sha256::digest([44; 32]).into()),
        host: RemoteHostId(se_types::Sha256::from_bytes(
            Sha256::digest([23; 32]).into(),
        )),
        store: f.store.clone(),
        subject: RemoteSubject::Machine {
            host: RemoteHostId(se_types::Sha256::from_bytes([64; 32])),
        },
        scope: RemoteScope {
            targets: vec![RemoteTarget {
                project: f.project.clone(),
                agent: f.a.clone(),
            }],
            verbs: vec![RemoteVerb::List, RemoteVerb::Watch],
        },
        issued_at_us: at,
        last_use_at_us: at,
        expires_at_us: at + GRANT_INACTIVITY_US,
        authority_revision: revision_value(1)?,
        lease_revision: revision_value(1)?,
        state: GrantState::Active,
    };
    let (mut store, lease) = direct(f)?;
    store.append(
        f.batch(
            f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
            Some(fixture::request("native-remote-grant")?),
            vec![EventBody::RemoteSecurity {
                transition: SecurityTransition::Connect {
                    grant: Box::new(grant.clone()),
                },
            }],
        )?,
        &*lease,
    )?;
    store.close()?;
    Ok(grant)
}
fn revision_value(n: u64) -> Result<Revision, Box<dyn std::error::Error>> {
    Ok(Revision {
        value: std::num::NonZeroU64::new(n).ok_or("zero revision")?,
    })
}
fn hello(g: &GrantRecord) -> RemoteHello {
    RemoteHello {
        protocol: se_types::ApiVersion {
            major: CLIENT_PROTOCOL_MAJOR,
            minor: CLIENT_PROTOCOL_MINOR,
        },
        host: g.host,
        grant: g.grant.clone(),
        device: g.device.clone(),
        authority_revision: g.authority_revision.value.get(),
    }
}
fn invocation(source: Option<RemoteSourceSession>, targets: Vec<RemoteTarget>) -> RemoteInvocation {
    RemoteInvocation {
        source,
        request: RemoteRequest::List(RemoteList {
            targets,
            cursor: None,
            limit: 20,
            budget: 32768,
        }),
    }
}

#[test]
fn native_windows_target_refuses_wrong_secret_subject_scope_and_revoked_device() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let grant = seed_grant(&f)?;
    let owner = VerifiedLocalOwner::from_native(
        &f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
        &se_core::admission::HumanTerminal::OutsideAgentTree,
    )?;
    let files = Arc::new(se_host::state_files::Files::open(
        &f.options.state_directory,
    )?);
    let key = ProtectedCredential::open(files, f.options.state_directory.join("credential"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut runtime =
            HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        let listener = runtime.listen(rt.handle().clone(), &bound()?).await?;
        let execution = runtime.execution_context();
        let reader = present(SqliteFactory::open_reader(&f.options)?)?;
        let store = Arc::new(SecurityStore::new(
            reader,
            execution.writer.clone(),
            runtime.generation().get(),
            f.owner.clone(),
        )?);
        let security = Security::new(
            store,
            &key,
            runtime.generation(),
            execution.blocking.clone(),
        )?;
        let stop = runtime.local_stop();
        let consumer = async {
            let result = check_authority(&security, &grant, &f, owner).await;
            stop.request();
            result
        };
        let (exit, result) = join(runtime.serve(listener), consumer).await;
        let report = exit.finish(&bound()?).await;
        require(
            report.transport_closed && report.endpoint_retired,
            "native target transport did not close",
        )?;
        require(
            matches!(report.storage,Read::Present {ref value} if value.writer_joined),
            "native target writer did not join",
        )?;
        result
    })
}

async fn check_authority(
    security: &Security,
    g: &GrantRecord,
    f: &Fixture,
    owner: VerifiedLocalOwner,
) -> Check {
    require(
        security
            .authenticate_session(
                security.accepted_connection()?,
                hello(g),
                LinkSecret::new([45; 32]),
            )
            .await
            .is_err(),
        "wrong machine secret admitted",
    )?;
    let device = security
        .authenticate_session(
            security.accepted_connection()?,
            hello(g),
            LinkSecret::new([44; 32]),
        )
        .await?;
    let source = RemoteSourceSession {
        host: match g.subject {
            RemoteSubject::Machine { host } => host,
            _ => return Err("machine subject absent".into()),
        },
        project: f.project.clone(),
        agent: f.b.clone(),
        session: support::session::session()?,
        generation: se_types::Generation::new(1)?,
    };
    require(
        security
            .authorize_invocation(&device, invocation(None, vec![]))
            .is_err(),
        "machine grant acquired human fallback",
    )?;
    let mut wrong = source.clone();
    wrong.host = RemoteHostId(se_types::Sha256::from_bytes([65; 32]));
    require(
        security
            .authorize_invocation(&device, invocation(Some(wrong), vec![]))
            .is_err(),
        "wrong source host admitted",
    )?;
    require(
        security
            .authorize_invocation(
                &device,
                invocation(
                    Some(source.clone()),
                    vec![RemoteTarget {
                        project: f.project.clone(),
                        agent: f.b.clone(),
                    }],
                ),
            )
            .is_err(),
        "ungranted target admitted",
    )?;
    let request = invocation(Some(source.clone()), vec![]);
    let admitted = security.authorize_invocation(&device, request)?;
    assert_eq!(admitted.admission().targets(), g.scope.targets);
    let mut watch = RemoteWatch {
        targets: vec![],
        visible: Some(RemoteTarget {
            project: f.project.clone(),
            agent: f.b.clone(),
        }),
        cursors: vec![],
        budget: 32768,
        measure: false,
    };
    require(
        security
            .authorize_invocation(
                &device,
                RemoteInvocation {
                    source: Some(source.clone()),
                    request: RemoteRequest::Watch(watch.clone()),
                },
            )
            .is_err(),
        "watch visible selector widened scope",
    )?;
    watch.visible = None;
    security.authorize_invocation(
        &device,
        RemoteInvocation {
            source: Some(source.clone()),
            request: RemoteRequest::Watch(watch),
        },
    )?;
    drop(security.output_fence(&device, &g.scope)?);
    let revoked = security
        .revoke(
            owner,
            RevokeGrant {
                grant: g.grant.clone(),
                expected_revision: g.authority_revision,
                key: IdempotencyKey::new("native-revoke-control")?,
            },
        )
        .await?;
    require(
        !revoked.sockets_pending,
        "store-only authorization fixture claimed unresolved sockets",
    )?;
    require(
        security
            .authorize_invocation(&device, invocation(Some(source), vec![]))
            .is_err(),
        "retained revoked device admitted",
    )?;
    require(
        security.output_fence(&device, &g.scope).is_err(),
        "revoked output fence reopened",
    )?;
    require(
        security
            .authenticate_session(
                security.accepted_connection()?,
                hello(g),
                LinkSecret::new([44; 32]),
            )
            .await
            .is_err(),
        "fresh revoked device admitted",
    )
}
