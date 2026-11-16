//! Selection parity through public planners and the real grant-filtered store.
//! Typed ended sessions are metadata fixtures, not native process witnesses.
#![cfg(all(feature = "remote", any(target_os = "linux", windows)))]
use se_config::config_policy::ConfigFile;
use se_core::{
    commit::Cx,
    dispatch::{CallFacts, Kernel},
    ops::{
        agent_launch::{AgentLaunch, LaunchPlan},
        process_commit, process_plan,
    },
};
use se_store::remote::*;
use se_store::*;
use se_types::remote::*;
use se_types::{AgentId, LifecycleId, NativePath, Read, ResumeSelection, SessionId};
use std::time::Duration;
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "../../se-store/tests/support/host_fixture.rs"]
mod native_host;
use native_host::*;
#[path = "support/process_barrier_fixture.rs"]
#[allow(
    dead_code,
    reason = "only owner planning and fixture lifecycle helpers are used"
)]
mod barrier;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
#[allow(dead_code, reason = "only typed saved-session helpers are used")]
mod capture;
#[path = "../../se-store/tests/support/wave2_control_fixture.rs"]
#[allow(dead_code, reason = "shared fixture imports the typed control helpers")]
mod control;
use barrier::*;

fn ended(h: &Harness, id: &SessionId, reference: &str) -> Check {
    let mut first = capture::prepared(&h.f, id, &h.target);
    if let EventBody::SessionPrepared { native_ref, .. } = &mut first {
        *native_ref = reference.into();
    }
    h.write(vec![
        first,
        capture::activated(id)?,
        EventBody::SessionEnded {
            session: id.clone(),
            expected: revision(2)?,
            reason: InputText::Inline("fixture ended".into()),
            final_turn: None,
            final_cursor: None,
        },
    ])?;
    Ok(())
}

fn local(
    h: &Harness,
    resume: Option<ResumeSelection>,
) -> Result<LaunchPlan, Box<dyn std::error::Error>> {
    let admission = h.f.owner_project();
    let mut read = h.snapshot(&h.owner())?;
    let mut input: AgentLaunch = serde_json::from_value(serde_json::json!({
        "target_agent_id":h.target, "task":null, "detach":true,
        "idempotency_key":format!("local-{}", serial())
    }))?;
    input.resume = resume;
    let planned = process_plan::launch(
        &kernel()?,
        input,
        &ConfigFile::default(),
        &mut Cx {
            read: &mut read,
            admission: &admission,
        },
    );
    read.close()?;
    Ok(planned?)
}

fn grant(h: &Harness) -> Result<GrantRecord, Box<dyn std::error::Error>> {
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros(),
    )?;
    let target = RemoteTarget {
        project: h.f.project.clone(),
        agent: h.target.clone(),
    };
    let g = GrantRecord {
        grant: se_types::RemoteGrantId::from_parts(1_700_000_000_000, [31; 10])?,
        principal: se_types::RemotePrincipalId::from_parts(1_700_000_000_000, [32; 10])?,
        device: se_types::RemoteDeviceId::from_parts(1_700_000_000_000, [33; 10])?,
        credential_sha256: CredentialDigest([34; 32]),
        host: RemoteHostId(se_types::Sha256::from_bytes([35; 32])),
        store: h.f.store.clone(),
        subject: RemoteSubject::Machine {
            host: RemoteHostId(se_types::Sha256::from_bytes([36; 32])),
        },
        scope: RemoteScope {
            targets: vec![target.clone()],
            verbs: vec![RemoteVerb::List, RemoteVerb::Watch, RemoteVerb::Send],
        },
        issued_at_us: now,
        last_use_at_us: now,
        expires_at_us: now + GRANT_INACTIVITY_US,
        authority_revision: Revision {
            value: std::num::NonZeroU64::MIN,
        },
        lease_revision: Revision {
            value: std::num::NonZeroU64::MIN,
        },
        state: GrantState::Active,
    };
    let admission =
        h.f.admission(Scope::Registry, Actor::Human(h.f.owner.clone()));
    h.commit(h.f.batch(
        admission,
        Some(request("selection-grant")?),
        vec![
            EventBody::RemoteSecurity {
                transition: SecurityTransition::Connect {
                    grant: Box::new(g.clone()),
                },
            },
            EventBody::RemoteSecurity {
                transition: SecurityTransition::LaunchPermission {
                    change: LaunchPermissionChange {
                        grant: g.grant.clone(),
                        target,
                        allowed: true,
                        expected: None,
                    },
                },
            },
        ],
    )?)?;
    Ok(g)
}

fn remote(
    h: &Harness,
    g: &GrantRecord,
    resume: Option<ResumeSelection>,
) -> Result<LaunchPlan, Box<dyn std::error::Error>> {
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros(),
    )?;
    let target = RemoteTarget {
        project: h.f.project.clone(),
        agent: h.target.clone(),
    };
    let permission = LaunchPermission {
        grant: g.grant.clone(),
        target: target.clone(),
        allowed: true,
        revision: Revision {
            value: std::num::NonZeroU64::MIN,
        },
    };
    let admitted = se_core::remote::authorize_launch(g.clone(), &target, permission, now)?;
    let admission = h.f.admission(
        Scope::Project(h.f.project.clone()),
        Actor::Remote(g.principal.clone()),
    );
    let reader = present(SqliteFactory::open_reader(&h.f.options)?)?;
    let mut read = reader
        .read_phase()?
        .into_remote_launch_snapshot(admission.clone())?;
    let input = RemoteLaunch {
        target,
        resume,
        idempotency_key: se_types::IdempotencyKey::new(format!("remote-{}", serial()))?,
    };
    let origin = RemoteAttribution {
        host: g.host,
        store: g.store.clone(),
        principal: g.principal.clone(),
        grant: g.grant.clone(),
        device: g.device.clone(),
        authority_revision: 1,
        source: None,
    };
    let planned = se_core::remote::plan_launch(
        admitted,
        input,
        origin,
        &kernel()?,
        &ConfigFile::default(),
        &mut Cx {
            read: &mut read,
            admission: &admission,
        },
    );
    read.close()?;
    Ok(planned?)
}

#[test]
fn local_and_granted_remote_choose_fresh_latest_and_exact_historical_session() -> Check {
    let h = Harness::new()?;
    let first = capture::session()?;
    let second = capture::session()?;
    ended(&h, &first, "saved-first-conversation")?;
    ended(&h, &second, "saved-second-conversation")?;
    let g = grant(&h)?;
    for remote_door in [false, true] {
        let plan = |selection| {
            if remote_door {
                remote(&h, &g, selection)
            } else {
                local(&h, selection)
            }
        };
        assert!(matches!(plan(None)?.conversation, Read::Absent { .. }));
        assert!(matches!(
            plan(Some(ResumeSelection::Latest(false)))?.conversation,
            Read::Absent { .. }
        ));
        let latest = present(plan(Some(ResumeSelection::Latest(true)))?.conversation)?;
        assert_eq!(latest.as_str(), "saved-second-conversation");
        let named = present(plan(Some(ResumeSelection::Session(first.clone())))?.conversation)?;
        assert_eq!(named.as_str(), "saved-first-conversation");
        assert!(plan(Some(ResumeSelection::Session(capture::session()?))).is_err());
    }
    h.finish()
}

#[test]
fn exact_session_lookup_keeps_agent_and_remote_grant_boundaries() -> Check {
    let h = Harness::new()?;
    let foreign = capture::session()?;
    h.write(vec![
        capture::prepared(&h.f, &foreign, &h.f.a),
        capture::activated(&foreign)?,
        EventBody::SessionEnded {
            session: foreign.clone(),
            expected: revision(2)?,
            reason: InputText::Inline("fixture ended".into()),
            final_turn: None,
            final_cursor: None,
        },
    ])?;
    let g = grant(&h)?;
    assert!(local(&h, Some(ResumeSelection::Session(foreign.clone()))).is_err());
    assert!(remote(&h, &g, Some(ResumeSelection::Session(foreign))).is_err());
    h.finish()
}
