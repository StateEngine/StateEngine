//! C3 credential activation over a real protected store and FULL writer,
//! including the event schema version that guards older readers.
//! Process identities are typed store fixtures, not native launch witnesses.
#![cfg(any(target_os = "linux", windows))]
use se_config::config_policy::ConfigFile;
use se_core::{
    commit::Cx,
    dispatch::{CallFacts, Kernel},
    ops::{
        agent_launch::{AgentLaunch, LaunchPlan},
        process_commit::{self, Activation, CaptureActivation, CredentialActivation},
        process_plan,
    },
};
use se_store::*;
use se_types::{AgentId, EventId, LifecycleId, NativePath};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "../../se-store/tests/support/host_fixture.rs"]
mod native_host;
use native_host::*;
#[path = "support/process_barrier_fixture.rs"]
#[allow(dead_code, reason = "only owner-actor launch helpers are used")]
mod barrier;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
#[allow(dead_code, reason = "only typed session helpers are used")]
mod capture;
#[path = "../../se-store/tests/support/wave2_control_fixture.rs"]
#[allow(dead_code, reason = "only typed process and control helpers are used")]
mod control;
use barrier::*;

const HASHES: [[u8; 32]; 2] = [[31; 32], [32; 32]];

/// A typed process identity with a published root for `executable`.
fn identified(
    h: &Harness,
    plan: &LaunchPlan,
    executable: &str,
) -> Result<ProcessIdentityRecord, Box<dyn std::error::Error>> {
    let mut identity = h.identity(plan)?;
    let mut fields = epoch()?.owner.fields().clone();
    fields.executable = NativePath::from_local(h.f.home.join(executable))?;
    identity.root_identity = RootIdentityState::Identified;
    identity.instance =
        RecordedIdentity::Present(se_types::ProcessInstance::from_observation(fields)?);
    Ok(identity)
}

/// C1, C2 and the root checkpoint; returns the identified Starting head.
fn starting(
    h: &Harness,
    kernel: &Kernel,
    plan: &LaunchPlan,
) -> Result<ProjectionRecord, Box<dyn std::error::Error>> {
    let reserved = h.commit(h.reserve(kernel, plan, h.owner(), HASHES)??)?;
    let mut prepared = h.identity(plan)?;
    prepared.root_identity = RootIdentityState::Unpublished;
    prepared.instance = RecordedIdentity::Absent {
        reason: "prepared scope has not published its root".into(),
    };
    h.write(vec![control::transition(
        &prepared,
        1,
        ProcessState::Reserved,
        ProcessState::Starting,
        reserved.primary_event.clone(),
    )?])?;
    h.write(vec![control::transition(
        &identified(h, plan, "synthetic-helper")?,
        2,
        ProcessState::Starting,
        ProcessState::Starting,
        reserved.primary_event,
    )?])?;
    present(h.snapshot(&h.owner())?.process(plan.lifecycle.clone())?)
}

/// Each C3 attempt gets a fresh kernel, as each real host commit does.
fn activate(
    h: &Harness,
    plan: &LaunchPlan,
    previous: &ProjectionRecord,
    credentials: CredentialActivation,
) -> Result<se_types::Result<AtomicBatch>, Box<dyn std::error::Error>> {
    let admission =
        h.f.admission(Scope::Project(h.f.project.clone()), h.owner());
    let mut read = h.snapshot(&h.owner())?;
    Ok(process_commit::activate(
        &kernel()?,
        plan,
        previous,
        identified(h, plan, "synthetic-helper")?,
        Activation {
            capture: Some(CaptureActivation {
                source: process_commit::credential_id(plan, "capture-source")?,
                native_ref: "synthetic-conversation".into(),
                incarnation: b"synthetic incarnation".to_vec(),
            }),
            credentials,
        },
        &Cx {
            read: &mut read,
            admission: &admission,
        },
    ))
}

/// One stored credential activation: its decoded witness and the schema
/// version the writer recorded for it.
#[derive(Debug, PartialEq)]
struct Stored {
    event: EventId,
    first_request: Option<RecordId>,
    schema_version: i64,
}

fn database(h: &Harness) -> rusqlite::Result<rusqlite::Connection> {
    rusqlite::Connection::open(h.f.options.state_directory.join("state.db"))
}

fn event_key(event: &EventId) -> Result<[u8; 16], Box<dyn std::error::Error>> {
    Ok(event.canonical_bytes()?.ok_or("canonical event id")?)
}

/// Commits the batch and reads each stored credential activation back through
/// the store codec, in batch order (session, then http).
fn committed(h: &Harness, batch: AtomicBatch) -> Result<Vec<Stored>, Box<dyn std::error::Error>> {
    let activated: Vec<_> = batch
        .events
        .iter()
        .filter(|e| matches!(e.body, EventBody::CredentialActivated { .. }))
        .map(|e| e.header.event.clone())
        .collect();
    h.commit(batch)?;
    let mut read = h.snapshot(&h.owner())?;
    let database = database(h)?;
    let mut stored = Vec::new();
    for event in activated {
        let EventBody::CredentialActivated { first_request, .. } =
            present(read.event(event.clone())?)?.body
        else {
            return Err("stored event is not a credential activation".into());
        };
        let schema_version = database.query_row(
            "SELECT schema_version FROM events WHERE event_id=?",
            [event_key(&event)?.as_slice()],
            |row| row.get(0),
        )?;
        stored.push(Stored {
            event,
            first_request,
            schema_version,
        });
    }
    Ok(stored)
}

/// Rewrites one stored row's schema version in this test's private database
/// and returns the code the real decoder refuses it with. Only the immutable
/// event trigger is removed, so the decoder sees damage an append cannot make.
fn tampered(
    h: &Harness,
    event: &EventId,
    schema_version: i64,
) -> Result<StoreErrorCode, Box<dyn std::error::Error>> {
    let database = database(h)?;
    let triggers: Vec<String> = database
        .prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='events' AND upper(sql) LIKE '%BEFORE UPDATE%'")?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    for name in triggers {
        assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
        database.execute_batch(&format!("DROP TRIGGER {name}"))?;
    }
    assert_eq!(
        database.execute(
            "UPDATE events SET schema_version=? WHERE event_id=?",
            rusqlite::params![schema_version, event_key(event)?.as_slice()],
        )?,
        1
    );
    drop(database);
    let mut read = h.snapshot(&h.owner())?;
    Ok(read
        .event(event.clone())
        .err()
        .ok_or("tampered credential activation decoded as success")?
        .code)
}

fn witness(n: u8) -> Result<RecordId, Box<dyn std::error::Error>> {
    Ok(RecordId::from_parts(
        1_700_000_000_000 + u64::from(n),
        [n; 10],
    )?)
}

/// Protects: a non-ACP launch never activates a credential without a verified
/// first-use request for each purpose; with both it stores them exactly.
#[test]
fn non_acp_activation_requires_both_verified_first_requests() -> Check {
    let h = Harness::new()?;
    let (kernel, plan) = h.plan(h.owner())?;
    assert_eq!(plan.profile.provider, Provider::Claude);
    let previous = starting(&h, &kernel, &plan)?;
    for (session_request, http_request) in [
        (None, None),
        (Some(witness(1)?), None),
        (None, Some(witness(2)?)),
    ] {
        let refused = activate(
            &h,
            &plan,
            &previous,
            CredentialActivation {
                session_request,
                http_request,
            },
        )?;
        assert!(
            refused.is_err(),
            "non-ACP activation accepted an absent first-use request"
        );
    }
    let batch = activate(
        &h,
        &plan,
        &previous,
        CredentialActivation {
            session_request: Some(witness(1)?),
            http_request: Some(witness(2)?),
        },
    )??;
    let stored = committed(&h, batch)?;
    assert_eq!(
        stored
            .iter()
            .map(|s| (s.first_request, s.schema_version))
            .collect::<Vec<_>>(),
        vec![(Some(witness(1)?), 1), (Some(witness(2)?), 1)]
    );
    for hash in HASHES {
        assert_eq!(h.credential(hash)?.state, CredentialState::Active);
    }
    // A version 2 row must not carry a first request.
    assert_ne!(
        tampered(&h, &stored[0].event, 2)?,
        StoreErrorCode::VersionUnsupported
    );
    h.finish()
}

/// Protects: an ACP launch whose MCP transport connected lazily or over stdio
/// records the absent witness as absent, and the store round-trips it beside
/// an observed one.
#[test]
fn acp_activation_stores_absent_first_requests_honestly() -> Check {
    let h = Harness::new()?;
    h.write(vec![EventBody::ProfileSaved {
        agent: h.target.clone(),
        profile: Profile {
            provider_settings: Default::default(),
            provider: Provider::Acp,
            model: None,
            permission: PermissionProfile::WorkspaceWrite,
            harness: None,
            named_profile: "default".into(),
            effort: None,
            external: false,
        },
        expected: revision(1)?,
    }])?;
    let (kernel, plan) = h.plan(h.owner())?;
    assert_eq!(plan.profile.provider, Provider::Acp);
    let previous = starting(&h, &kernel, &plan)?;
    let batch = activate(
        &h,
        &plan,
        &previous,
        CredentialActivation {
            session_request: Some(witness(3)?),
            http_request: None,
        },
    )??;
    let stored = committed(&h, batch)?;
    assert_eq!(
        stored
            .iter()
            .map(|s| (s.first_request, s.schema_version))
            .collect::<Vec<_>>(),
        vec![(Some(witness(3)?), 1), (None, 2)],
        "an absent first request must refuse older readers with schema version 2"
    );
    for hash in HASHES {
        assert_eq!(h.credential(hash)?.state, CredentialState::Active);
    }
    // A version 1 row must carry a first request; version 3 is unknown.
    assert_ne!(
        tampered(&h, &stored[1].event, 1)?,
        StoreErrorCode::VersionUnsupported
    );
    assert_eq!(
        tampered(&h, &stored[1].event, 3)?,
        StoreErrorCode::VersionUnsupported
    );
    h.finish()
}
