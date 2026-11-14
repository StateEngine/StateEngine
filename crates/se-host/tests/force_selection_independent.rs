//! Force-selection barriers over real FULL commits; native custody is not simulated as proof.
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
#[allow(
    dead_code,
    reason = "shared fixture methods serve separate control roots"
)]
mod barrier;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
#[allow(dead_code, reason = "only typed session helpers are used")]
mod capture;
#[path = "../../se-store/tests/support/wave2_control_fixture.rs"]
#[allow(dead_code, reason = "only typed process and control helpers are used")]
mod control;
use barrier::*;

/// Protects: all old lifecycle and session heads reach the launch coordinator,
/// while a new reservation cannot jump over even one unresolved old lifecycle.
#[test]
fn multiple_originals_are_selected_and_each_blocks_the_successor() -> Check {
    let h = Harness::new()?;
    let (_, first) = h.plan(h.owner())?;
    let (_, second) = h.plan(h.owner())?;
    let a = h.identity(&first)?;
    let b = h.identity(&second)?;
    let registered = h.write(vec![
        capture::prepared(&h.f, &first.session, &h.target),
        capture::prepared(&h.f, &second.session, &h.target),
        control::registration(&a, ProcessState::Starting),
        control::registration(&b, ProcessState::Starting),
    ])?;
    let (kernel, plan) = h.plan(h.owner())?;
    assert_eq!(plan.control.processes.len(), 2);
    assert_eq!(plan.control.sessions.len(), 2);
    let ids = plan
        .control
        .processes
        .iter()
        .map(|p| match &p.current.body {
            EventBody::ProcessRegistered { identity, .. } => identity.record.clone(),
            _ => panic!("unexpected fixture process kind"),
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        ids,
        [first.lifecycle.clone(), second.lifecycle.clone()].into()
    );
    assert!(
        h.reserve(&kernel, &plan, h.owner(), [[31; 32], [32; 32]])?
            .is_err()
    );
    let observation = registered.primary_event;
    h.write(vec![
        control::transition(
            &a,
            1,
            ProcessState::Starting,
            ProcessState::StopRequested,
            observation.clone(),
        )?,
        control::transition(
            &a,
            2,
            ProcessState::StopRequested,
            ProcessState::StopUnproved,
            observation,
        )?,
    ])?;
    let (kernel, next) = h.plan(h.owner())?;
    assert_eq!(next.control.processes.len(), 2, "unproved is not retired");
    assert!(
        h.reserve(&kernel, &next, h.owner(), [[41; 32], [42; 32]])?
            .is_err()
    );
    h.finish()
}

/// Protects: retiring an embedded binding commits only revocation, preserves its
/// captured history and never fabricates native process exit or service closure.
#[test]
fn embedded_binding_retirement_is_not_a_native_stop() -> Check {
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
    let mut read = h.snapshot(&h.owner())?;
    let batch = session_commit::bind(
        &barrier::kernel()?,
        se_types::IdempotencyKey::new("external-binding")?,
        SessionPreparation {
            session: session.clone(),
            agent: h.target.clone(),
            provider: Provider::SeCode,
            surface: Some(SessionSurface::SeCode),
            native_ref: "external-conversation".into(),
            consent: Consent::Capture,
            generation: 1,
            expected: Expected::Absent,
        },
        SessionActivation {
            session: session.clone(),
            expected: revision(1)?,
            incumbent: None,
            process: None,
            containment: ContainmentFact::NotLaunched,
            witnesses: vec![],
        },
        &Cx {
            read: &mut read,
            admission: &admission,
        },
    )?;
    drop(read);
    h.commit(batch)?;
    let mut read = h.snapshot(&h.owner())?;
    let selected = present(read.session(session.clone())?)?;
    assert!(process_commit::embedded_session(&selected).is_some());
    let batch = process_commit::retire_embedded(
        &barrier::kernel()?,
        h.target.clone(),
        selected,
        se_types::IdempotencyKey::new("retire-external")?,
        "external jobs were not stopped".into(),
        &mut Cx {
            read: &mut read,
            admission: &admission,
        },
    )?;
    drop(read);
    assert_eq!(batch.events.len(), 1);
    assert!(matches!(
        batch.events[0].body,
        EventBody::SessionRevoked { .. }
    ));
    h.commit(batch)?;
    let mut outside = h.snapshot(&h.owner())?;
    let record = present(outside.session(session)?)?;
    assert!(matches!(
        record.current.body,
        EventBody::SessionRevoked { .. }
    ));
    assert!(
        matches!(&record.original.as_ref().ok_or("missing preparation")?.body,
        EventBody::SessionPrepared { native_ref, .. } if native_ref.as_str() == "external-conversation")
    );
    assert!(
        present(outside.control_target(h.target.clone())?)?
            .processes
            .is_empty()
    );
    drop(outside);
    h.finish()
}

/// Protects: a bare launch over live protocol work reaches confirmation inventory
/// instead of rejecting the requested display mode before the jobs are shown.
#[test]
fn busy_protocol_launch_reaches_confirmation_before_detach_validation() -> Check {
    let mut failures = Vec::new();
    for provider in [Provider::SeCode, Provider::Acp] {
        let h = Harness::new()?;
        h.write(vec![EventBody::ProfileSaved {
            agent: h.target.clone(),
            profile: Profile {
                provider,
                model: None,
                permission: PermissionProfile::WorkspaceWrite,
                harness: None,
                named_profile: "default".into(),
                effort: None,
            },
            expected: revision(1)?,
        }])?;
        let (_, original) = h.plan(h.owner())?;
        let mut preparation = capture::prepared(&h.f, &original.session, &h.target);
        if let EventBody::SessionPrepared {
            provider: saved, ..
        } = &mut preparation
        {
            *saved = provider;
        }
        h.write(vec![
            preparation,
            control::registration(&h.identity(&original)?, ProcessState::Starting),
        ])?;
        let admission = h.f.owner_project();
        let mut input = original.input;
        input.detach = false;
        input.idempotency_key = se_types::IdempotencyKey::new(format!("plain-busy-{}", serial()))?;
        let mut read = h.snapshot(&h.owner())?;
        let planned = process_plan::launch(
            &barrier::kernel()?,
            input,
            &ConfigFile::default(),
            &mut Cx {
                read: &mut read,
                admission: &admission,
            },
        );
        drop(read);
        let failure = planned.err().map(|e| e.to_string());
        h.finish()?;
        if let Some(failure) = failure {
            failures.push(format!("{provider:?}: {failure}"));
        }
    }
    assert!(
        failures.is_empty(),
        "busy protocol mode hid inventory: {failures:?}"
    );
    Ok(())
}

/// Protects: deferring a busy-target refusal never makes an unattended protocol
/// launch implicit when there is no original session or native work to display.
#[test]
fn fresh_protocol_launch_still_requires_an_explicit_headless_mode() -> Check {
    for provider in [Provider::SeCode, Provider::Acp] {
        let h = Harness::new()?;
        h.write(vec![EventBody::ProfileSaved {
            agent: h.target.clone(),
            profile: Profile {
                provider,
                model: None,
                permission: PermissionProfile::WorkspaceWrite,
                harness: None,
                named_profile: "default".into(),
                effort: None,
            },
            expected: revision(1)?,
        }])?;
        let (_, original) = h.plan(h.owner())?;
        let mut input = original.input;
        input.detach = false;
        let admission = h.f.owner_project();
        let mut read = h.snapshot(&h.owner())?;
        let result = process_plan::launch(
            &barrier::kernel()?,
            input,
            &ConfigFile::default(),
            &mut Cx {
                read: &mut read,
                admission: &admission,
            },
        );
        assert!(
            result
                .err()
                .is_some_and(|e| e.to_string().contains("protocol launch mode"))
        );
        let control = present(read.control_target(h.target.clone())?)?;
        assert!(control.sessions.is_empty() && control.processes.is_empty());
        drop(read);
        h.finish()?;
    }
    Ok(())
}
