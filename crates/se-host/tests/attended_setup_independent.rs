//! Independent core consumers over a protected store and FULL writer.
//! These typed fixtures establish projection/planning rules, not native expiry.
#![cfg(any(target_os = "linux", windows))]
use se_core::{
    commit::Cx,
    config_policy::ConfigFile,
    dispatch::{CallFacts, Kernel},
    ops::{
        agent_launch::{AgentLaunch, LaunchPlan},
        process_commit, process_plan,
    },
};
use se_store::*;
use se_types::{AgentId, LifecycleId, NativePath, Read};
use std::time::Duration;
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "../../se-store/tests/support/host_fixture.rs"]
mod native_host;
use native_host::*;
#[path = "support/process_barrier_fixture.rs"]
#[allow(dead_code, reason = "only owner planning and session helpers are used")]
mod barrier;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
#[allow(
    dead_code,
    reason = "typed session helpers shared by the store fixture"
)]
mod capture;
#[path = "../../se-store/tests/support/wave2_control_fixture.rs"]
#[allow(
    dead_code,
    reason = "typed process helpers shared by the store fixture"
)]
mod control;

const EXPIRED: &str = "attended setup exceeded its activation deadline";
const FAILED: &str = "expired attended setup replacement failed before activation";

fn retired(
    reason: &str,
    window: bool,
    activated: bool,
) -> Result<(barrier::Harness, se_core::ops::agent_launch::LaunchPlan), Box<dyn std::error::Error>>
{
    let h = barrier::Harness::new()?;
    let (kernel, mut plan) = h.plan(h.owner())?;
    plan.input.detach = !window;
    let committed = h.commit(h.reserve(&kernel, &plan, h.owner(), [[81; 32], [82; 32]])??)?;
    h.release_no_child(&plan, &committed)?;
    if activated {
        h.write(vec![capture::activated(&plan.session)?])?;
    }
    h.write(
        ["session", "http"]
            .into_iter()
            .map(|purpose| {
                Ok(EventBody::CredentialRevoked {
                    credential: process_commit::credential_id(&plan, purpose)?,
                    expected: revision(1)?,
                    reason: InputText::Inline("independent fixture retirement".into()),
                })
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?,
    )?;
    h.write(vec![EventBody::SessionRevoked {
        session: plan.session.clone(),
        expected: revision(if activated { 2 } else { 1 })?,
        reason: InputText::Inline(reason.into()),
    }])?;
    Ok((h, plan))
}

#[test]
fn ordinary_launch_retries_expired_and_failed_unactivated_window_setup() -> Check {
    for reason in [EXPIRED, FAILED] {
        let (h, old) = retired(reason, true, false)?;
        let admission = h.f.owner_project();
        let mut snapshot = h.snapshot(&h.owner())?;
        let mut input = old.input.clone();
        input.fresh = false;
        input.idempotency_key = se_types::IdempotencyKey::new(format!("retry-{}", serial()))?;
        let next = process_plan::launch(
            &barrier::kernel()?,
            input,
            &ConfigFile::default(),
            &mut Cx {
                read: &mut snapshot,
                admission: &admission,
            },
        )?;
        assert!(matches!(next.conversation, Read::Absent { .. }));
        assert!(!next.input.fresh && !next.input.override_live && !next.input.detach);
        assert_ne!(next.session, old.session);
        drop(snapshot);
        h.finish()?;
    }
    Ok(())
}

#[test]
fn retry_exception_never_includes_activated_headless_or_other_revocations() -> Check {
    for (reason, window, activated) in [
        (EXPIRED, true, true),
        (FAILED, true, true),
        (EXPIRED, false, false),
        (FAILED, false, false),
        ("launch preparation failed", true, false),
        ("human stop", true, false),
    ] {
        let (h, plan) = retired(reason, window, activated)?;
        let mut snapshot = h.snapshot(&h.owner())?;
        let head = present(snapshot.session(plan.session)?)?;
        assert!(
            !se_core::ops::agent_launch::retryable_attended_setup(&head),
            "invalid retry exception: reason={reason}, window={window}, activated={activated}"
        );
        drop(snapshot);
        h.finish()?;
    }
    Ok(())
}

#[test]
fn replacement_failure_remains_distinct_from_elapsed_credential_expiry() -> Check {
    let (h, plan) = retired(FAILED, true, false)?;
    let mut snapshot = h.snapshot(&h.owner())?;
    let head = present(snapshot.session(plan.session)?)?;
    assert!(se_core::ops::agent_launch::retryable_attended_setup(&head));
    assert!(!se_core::ops::agent_launch::expired_attended_setup(&head));
    drop(snapshot);
    h.finish()
}
