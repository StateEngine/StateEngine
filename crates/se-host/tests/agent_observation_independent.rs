//! Status must survive an older process and a newer process-free session.
//! Real store readers and FULL writer are used; process facts are typed store
//! fixtures because the failure precedes any native process observation.
#![cfg(all(feature = "runtime", any(target_os = "linux", windows)))]
use se_core::{
    commit::Cx,
    config_policy::ConfigFile,
    dispatch::{CallFacts, Kernel},
    ops::{
        AgentShow,
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
#[allow(
    dead_code,
    reason = "shared harness also serves launch authorization judges"
)]
mod barrier;
use barrier::*;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
#[allow(dead_code, reason = "only session helpers are needed")]
mod capture;
#[path = "../../se-store/tests/support/wave2_control_fixture.rs"]
#[allow(
    dead_code,
    reason = "shared typed process helpers support the real writer"
)]
mod control;

fn newer_session(state: &str) -> Check {
    let h = Harness::new()?;
    let (kernel, old) = h.plan(h.owner())?;
    let receipt = h.commit(h.reserve(&kernel, &old, h.owner(), [[31; 32], [32; 32]])??)?;
    h.release_no_child(&old, &receipt)?;
    let mut retired = Vec::new();
    for purpose in ["session", "http"] {
        retired.push(EventBody::CredentialRevoked {
            credential: process_commit::credential_id(&old, purpose)?,
            expected: revision(1)?,
            reason: InputText::Inline("old provider session ended".into()),
        });
    }
    retired.push(EventBody::SessionRevoked {
        session: old.session.clone(),
        expected: revision(1)?,
        reason: InputText::Inline("old provider session ended".into()),
    });
    h.write(retired)?;
    let newest = capture::session()?;
    let mut prepared = capture::prepared(&h.f, &newest, &h.target);
    if let EventBody::SessionPrepared {
        provider,
        native_ref,
        ..
    } = &mut prepared
    {
        *provider = Provider::SeCode;
        *native_ref = "newest-process-free-secode-conversation".into();
    }
    let mut events = vec![prepared];
    if state == "activated" {
        events.push(capture::activated(&newest)?);
    } else if state == "revoked" {
        events.push(EventBody::SessionRevoked {
            session: newest.clone(),
            expected: revision(1)?,
            reason: InputText::Inline("process-free preparation was cancelled".into()),
        });
    }
    h.write(events)?;
    let mut read = h.snapshot(&h.owner())?;
    let target = present(read.control_target(h.target.clone())?)?;
    let old_process = present(target.latest_process)?;
    let mut cx = Cx {
        read: &mut read,
        admission: &h.f.owner_project(),
    };
    let row = present(
        se_core::ops::agent_status::show(
            AgentShow {
                target_agent_id: Some(h.target.clone()),
            },
            &mut cx,
        )?
        .agent,
    )?;
    assert_eq!(row.session.session_id.as_ref(), Some(&newest));
    assert!(matches!(&row.session.process_state, Read::Absent { .. }));
    assert!(matches!(&old_process.current.body,
        EventBody::ProcessTransition { identity, .. } if identity.session.as_ref() == Some(&old.session)));
    let observed = se_host::prepare_agent_observation(&h.f.project, &row, &mut read);
    read.close()?;
    h.finish()?;
    assert!(
        observed.is_ok(),
        "{state} newest session must not substitute an older process or fail the whole status response: {:?}",
        observed.err()
    );
    Ok(())
}

#[test]
fn prepared_session_does_not_inherit_the_previous_process() -> Check {
    newer_session("prepared")
}
#[test]
fn process_free_activated_session_does_not_inherit_the_previous_process() -> Check {
    newer_session("activated")
}
#[test]
fn revoked_preparation_does_not_inherit_the_previous_process() -> Check {
    newer_session("revoked")
}
