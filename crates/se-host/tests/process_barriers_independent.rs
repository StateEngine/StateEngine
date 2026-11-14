//! Independent public core barriers over a real protected store and FULL writer.
//! Process identities below are typed store fixtures, not native launch witnesses.
#![cfg(any(target_os = "linux", windows))]
use se_config::config_policy::ConfigFile;
use se_core::{
    commit::Cx,
    dispatch::{CallFacts, Kernel},
    ops::{
        agent_launch::{AgentLaunch, LaunchPlan},
        process_commit, process_plan,
    },
};
use se_store::*;
use se_types::{AgentId, LifecycleId, NativePath};
use std::time::Duration;
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "../../se-store/tests/support/host_fixture.rs"]
mod native_host;
use native_host::*;
#[path = "support/process_barrier_fixture.rs"]
mod barrier;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
#[allow(dead_code, reason = "only typed session helpers are used")]
mod capture;
#[path = "../../se-store/tests/support/wave2_control_fixture.rs"]
#[allow(dead_code, reason = "only typed process and control helpers are used")]
mod control;
use barrier::*;

const OLD: [[u8; 32]; 2] = [[11; 32], [12; 32]];
const NEW: [[u8; 32]; 2] = [[21; 32], [22; 32]];
/// Protects: C1 replaces an older managed preparation in one FULL transaction,
/// revoking both purposes and the old session before any new native execution.
#[test]
fn replacement_c1_revokes_old_preparation_atomically() -> Check {
    let h = Harness::new()?;
    let (old_kernel, old) = h.plan(h.owner())?;
    let initial = h.commit(h.reserve(&old_kernel, &old, h.owner(), OLD)??)?;
    h.release_no_child(&old, &initial)?;
    for hash in OLD {
        assert_eq!(h.credential(hash)?.state, CredentialState::Prepared);
    }
    let mut before = h.snapshot(&h.owner())?;
    let (new_kernel, new) = h.plan(h.owner())?;
    let outcome = h.commit(h.reserve(&new_kernel, &new, h.owner(), NEW)??);
    assert!(
        outcome.is_ok(),
        "replacement C1 lost a required old credential revocation: {outcome:?}"
    );
    outcome?;
    assert!(
        matches!(
            present(before.session(old.session.clone())?)?.current.body,
            EventBody::SessionPrepared { .. }
        ),
        "outside prior snapshot changed across FULL commit"
    );
    drop(before);
    let mut outside = h.snapshot(&h.owner())?;
    assert!(matches!(
        present(outside.session(old.session)?)?.current.body,
        EventBody::SessionRevoked { .. }
    ));
    assert!(matches!(
        present(outside.session(new.session.clone())?)?.current.body,
        EventBody::SessionPrepared { .. }
    ));
    assert_eq!(
        present(outside.control_target(h.target.clone())?)?
            .processes
            .len(),
        1
    );
    drop(outside);
    for hash in OLD {
        assert_eq!(h.credential(hash)?.state, CredentialState::Revoked);
    }
    for hash in NEW {
        let credential = h.credential(hash)?;
        assert_eq!(credential.state, CredentialState::Prepared);
        assert_eq!(credential.session, new.session);
    }
    h.finish()
}

/// Protects: a failed supersession CAS rolls back every new session, process and
/// credential and preserves the other old capability's state.
#[test]
fn replacement_c1_never_partially_commits_after_credential_drift() -> Check {
    let h = Harness::new()?;
    let (old_kernel, old) = h.plan(h.owner())?;
    let initial = h.commit(h.reserve(&old_kernel, &old, h.owner(), OLD)??)?;
    h.release_no_child(&old, &initial)?;
    h.write(vec![EventBody::CredentialRevoked {
        credential: process_commit::credential_id(&old, "http")?,
        expected: revision(1)?,
        reason: InputText::Inline("independent revocation".into()),
    }])?;
    let (new_kernel, new) = h.plan(h.owner())?;
    let before = h.snapshot(&h.owner())?.info().head;
    let batch = h.reserve(&new_kernel, &new, h.owner(), NEW)??;
    assert!(
        wait(h.client.submit(batch)?)?.is_err(),
        "drifted C1 committed"
    );
    let mut outside = h.snapshot(&h.owner())?;
    assert_eq!(outside.info().head, before);
    assert!(matches!(
        outside.session(new.session)?,
        se_types::Read::Absent { .. }
    ));
    assert!(matches!(
        outside.process(new.lifecycle)?,
        se_types::Read::Absent { .. }
    ));
    assert!(matches!(
        present(outside.session(old.session)?)?.current.body,
        EventBody::SessionPrepared { .. }
    ));
    drop(outside);
    assert_eq!(h.credential(OLD[0])?.state, CredentialState::Prepared);
    assert_eq!(h.credential(OLD[1])?.state, CredentialState::Revoked);
    let reader = present(SqliteFactory::open_reader(&h.f.options)?)?;
    for hash in NEW {
        assert!(matches!(
            reader.credential(hash)?,
            se_types::Read::Absent { .. }
        ));
    }
    h.finish()
}

/// Protects: C1 rereads creator permission and live obligations rather than
/// trusting an earlier authorized plan; refusal produces no new durable facts.
#[test]
fn reservation_rechecks_authorization_and_live_control_barriers() -> Check {
    for case in [
        "revoked-grant",
        "foreign-creator",
        "live-process",
        "active-session",
    ] {
        let h = Harness::new()?;
        let (kernel, plan) = h.plan(h.creator())?;
        let mut actor = h.creator();
        match case {
            "revoked-grant" => {
                h.write(vec![control::grant(&h.f.a, false, revision(1)?)])?;
            }
            "foreign-creator" => actor = Actor::Agent(h.f.b.clone()),
            "live-process" => {
                h.write(vec![control::registration(
                    &control::identity(&h.target)?,
                    ProcessState::Starting,
                )])?;
            }
            _ => {
                let session = capture::session()?;
                h.write(vec![
                    capture::prepared(&h.f, &session, &h.target),
                    capture::activated(&session)?,
                ])?;
            }
        }
        let before = h.snapshot(&h.owner())?.info().head;
        assert!(
            h.reserve(&kernel, &plan, actor, NEW)?.is_err(),
            "{case} crossed C1"
        );
        assert_eq!(h.snapshot(&h.owner())?.info().head, before);
        h.finish()?;
    }
    Ok(())
}

/// Protects: failed readiness retires both credentials and the prepared session
/// in the real writer before any later native cleanup is claimed.
#[test]
fn failed_preparation_retirement_revokes_both_purposes_and_session() -> Check {
    let h = Harness::new()?;
    let (kernel, plan) = h.plan(h.owner())?;
    h.commit(h.reserve(&kernel, &plan, h.owner(), OLD)??)?;
    let admission = h.f.owner_project();
    let mut read = h.snapshot(&h.owner())?;
    let batch = process_commit::retire_session(
        &barrier::kernel()?,
        &plan,
        false,
        "provider readiness failed".into(),
        &Cx {
            read: &mut read,
            admission: &admission,
        },
    )?;
    drop(read);
    h.commit(batch)?;
    for hash in OLD {
        assert_eq!(h.credential(hash)?.state, CredentialState::Revoked);
    }
    let mut outside = h.snapshot(&h.owner())?;
    assert!(matches!(
        present(outside.session(plan.session)?)?.current.body,
        EventBody::SessionRevoked { .. }
    ));
    assert!(
        matches!(
            present(outside.process(plan.lifecycle)?)?.current.body,
            EventBody::ProcessRegistered {
                initial: ProcessState::Reserved,
                ..
            }
        ),
        "credential retirement fabricated native process cleanup"
    );
    drop(outside);
    h.finish()
}

/// Protects: the embedded bind uses the same prepare/activate events in one FULL
/// commit, with no native process or credential issuance, and rejects incompatible facts.
#[test]
fn embedded_session_bind_is_atomic_and_credential_free() -> Check {
    use se_core::ops::session_commit::{self, SessionActivation, SessionPreparation};
    let h = Harness::new()?;
    h.write(vec![EventBody::ProfileSaved {
        agent: h.target.clone(),
        profile: Profile {
            provider: Provider::SeCode,
            model: None,
            permission: PermissionProfile::WorkspaceWrite,
            harness: None,
            named_profile: "default".into(),
            effort: None,
        },
        expected: revision(1)?,
    }])?;
    let session = capture::session()?;
    let admission = h.f.owner_project();
    let build = |case: &str| -> Result<(SessionPreparation, SessionActivation), Box<dyn std::error::Error>> {
        Ok((SessionPreparation { session: session.clone(), agent: h.target.clone(),
            provider: if case == "provider" { Provider::Claude } else { Provider::SeCode },
            surface: None,
            native_ref: "real-embedded-session-fixture".into(), consent: Consent::Capture,
            generation: if case == "generation" { 2 } else { 1 }, expected: Expected::Absent },
            SessionActivation { session: if case == "session" { capture::session()? } else { session.clone() },
                expected: revision(1)?, incumbent: None,
                process: if case == "process" { Some(control::identity(&h.target)?.record) } else { None },
                containment: if case == "containment" { ContainmentFact::Unknown { reason: "native custody absent".into() } }
                    else { ContainmentFact::NotLaunched }, witnesses: vec![] }))
    };
    let before = h.snapshot(&h.owner())?.info().head;
    for case in [
        "provider",
        "generation",
        "session",
        "process",
        "containment",
    ] {
        let mut read = h.snapshot(&h.owner())?;
        let (prepared, activated) = build(case)?;
        assert!(
            session_commit::bind(
                &barrier::kernel()?,
                se_types::IdempotencyKey::new(format!("bad-bind-{case}"))?,
                prepared,
                activated,
                &Cx {
                    read: &mut read,
                    admission: &admission
                }
            )
            .is_err(),
            "invalid embedded {case} produced a commit batch"
        );
    }
    assert_eq!(h.snapshot(&h.owner())?.info().head, before);
    let mut read = h.snapshot(&h.owner())?;
    let (prepared, activated) = build("valid")?;
    let batch = session_commit::bind(
        &barrier::kernel()?,
        se_types::IdempotencyKey::new("embedded-bind")?,
        prepared,
        activated,
        &Cx {
            read: &mut read,
            admission: &admission,
        },
    )?;
    drop(read);
    assert_eq!(batch.events.len(), 2);
    assert!(matches!(
        batch.events[0].body,
        EventBody::SessionPrepared {
            provider: Provider::SeCode,
            ..
        }
    ));
    assert!(matches!(
        batch.events[1].body,
        EventBody::SessionActivated { process: None, .. }
    ));
    let committed = h.commit(batch)?;
    let mut outside = h.snapshot(&h.owner())?;
    assert_eq!(committed.events.len(), 2);
    assert!(
        matches!(present(outside.event(committed.events[0].clone())?)?.body,
        EventBody::SessionPrepared { session: id, provider: Provider::SeCode, .. } if id == session)
    );
    assert!(matches!(
        present(outside.session(session)?)?.current.body,
        EventBody::SessionActivated { process: None, .. }
    ));
    assert!(
        present(outside.control_target(h.target.clone())?)?
            .processes
            .is_empty()
    );
    drop(outside);
    h.finish()
}

/// Protects: a creator's valid C1 succeeds, but a grant revoked after planning
/// refuses inside the real FULL writer and rolls back both capabilities and native facts.
#[test]
fn commit_rechecks_creator_authority_after_the_planning_snapshot() -> Check {
    for revoked in [false, true] {
        let h = Harness::new()?;
        let (kernel, plan) = h.plan(h.creator())?;
        let batch = h.reserve(&kernel, &plan, h.creator(), NEW)??;
        if revoked {
            h.write(vec![control::grant(&h.f.a, false, revision(1)?)])?;
        }
        let before = h.snapshot(&h.owner())?.info().head;
        let outcome = wait(h.client.submit(batch)?)?;
        let mut outside = h.snapshot(&h.owner())?;
        if revoked {
            assert!(
                outcome.is_err(),
                "revoked creator committed its already-planned C1"
            );
            assert_eq!(outside.info().head, before);
            assert!(matches!(
                outside.session(plan.session)?,
                se_types::Read::Absent { .. }
            ));
            assert!(matches!(
                outside.process(plan.lifecycle)?,
                se_types::Read::Absent { .. }
            ));
        } else {
            assert_eq!(outcome?.durability, CommitDurability::Full);
            assert!(matches!(
                outside.session(plan.session)?,
                se_types::Read::Present { .. }
            ));
        }
        drop(outside);
        let reader = present(SqliteFactory::open_reader(&h.f.options)?)?;
        for hash in NEW {
            let observed = reader.credential(hash)?;
            if revoked {
                assert!(matches!(observed, se_types::Read::Absent { .. }));
            } else {
                assert_eq!(present(observed)?.state, CredentialState::Prepared);
            }
        }
        h.finish()?;
    }
    Ok(())
}
