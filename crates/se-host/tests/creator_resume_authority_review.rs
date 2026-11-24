//! Reviewer acceptance for child resume authority through the public launch
//! planner and the real grant-filtered store. A create grant lets a creator
//! launch its direct child fresh; only the project Owner or the child itself
//! may reopen the child's saved conversation, with or without `force: true`.
//! Saved sessions are typed metadata fixtures, not native process witnesses.
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
use se_types::{AgentId, Detail, LifecycleId, NativePath, ResumeSelection, SessionId};
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
    reason = "only the rooted creator/child harness and planner kernel are used"
)]
mod barrier;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
#[allow(dead_code, reason = "only typed saved-session helpers are used")]
mod capture;
#[path = "../../se-store/tests/support/wave2_control_fixture.rs"]
#[allow(dead_code, reason = "the shared harness registers helpers and grants")]
mod control;
use barrier::*;

const CLAUDE_REFERENCE: &str = "saved-claude-conversation";
const CODEX_THREAD: &str = "transcript.jsonl";

/// Switch the child's saved profile to Codex so resume needs its private
/// committed capture-source binding, exactly as a real Codex child does.
fn use_codex(h: &Harness) -> Check {
    h.write(vec![EventBody::ProfileSaved {
        agent: h.target.clone(),
        profile: Profile {
            provider_settings: Default::default(),
            provider: Provider::Codex,
            model: None,
            permission: PermissionProfile::WorkspaceWrite,
            harness: None,
            named_profile: "default".into(),
            effort: None,
        },
        expected: revision(1)?,
    }])?;
    Ok(())
}

/// One ended, resumable saved conversation for the child on `provider`.
fn saved(h: &Harness, provider: Provider) -> Result<SessionId, Box<dyn std::error::Error>> {
    let session = capture::session()?;
    let mut prepared = capture::prepared(&h.f, &session, &h.target);
    if let EventBody::SessionPrepared {
        provider: recorded,
        native_ref,
        ..
    } = &mut prepared
    {
        *recorded = provider;
        *native_ref = match provider {
            Provider::Codex => format!(
                "{}{}",
                se_core::ops::session_reference::CODEX_PENDING,
                session.as_str()
            ),
            _ => CLAUDE_REFERENCE.into(),
        };
    }
    let mut bodies = vec![prepared, capture::activated(&session)?];
    if provider == Provider::Codex {
        bodies.push(capture::source(
            process_commit::session_credential_id(&session, "capture-source")?,
            &session,
            b"review-incarnation",
            Expected::Absent,
        ));
    }
    bodies.push(EventBody::SessionEnded {
        session: session.clone(),
        expected: revision(2)?,
        reason: InputText::Inline("fixture ended".into()),
        final_turn: None,
        final_cursor: None,
    });
    h.write(bodies)?;
    Ok(session)
}

type Planned = Result<LaunchPlan, se_types::SeError>;

/// Plans one launch of the child as `actor`; the outer error is fixture setup.
fn launch(
    h: &Harness,
    actor: &Actor,
    resume: Option<ResumeSelection>,
    force: bool,
) -> Result<Planned, Box<dyn std::error::Error>> {
    let admission =
        h.f.admission(Scope::Project(h.f.project.clone()), actor.clone());
    let mut read = h.snapshot(actor)?;
    // Self launch omits the target, exactly as a bound agent launching itself does.
    let target_agent_id = (actor != &Actor::Agent(h.target.clone())).then(|| h.target.clone());
    let planned = process_plan::launch(
        &kernel()?,
        AgentLaunch {
            target_agent_id,
            resume,
            model: None,
            task: Some("resume authority review".into()),
            detach: true,
            override_live: force,
            force_selection: None,
            idempotency_key: se_types::IdempotencyKey::new(format!("review-{}", serial()))?,
            owner_agent: None,
            owner_provider: None,
        },
        &ConfigFile::default(),
        &mut Cx {
            read: &mut read,
            admission: &admission,
        },
    );
    read.close()?;
    Ok(planned)
}

fn selections(session: &SessionId) -> [ResumeSelection; 2] {
    [
        ResumeSelection::Latest(true),
        ResumeSelection::Session(session.clone()),
    ]
}

/// A creator's resume is refused with a typed capability refusal that names a
/// working step (fresh launch) instead of falling back or reading the source.
fn assert_creator_refused(h: &Harness, session: &SessionId, provider: &str) -> Check {
    for resume in selections(session) {
        for force in [false, true] {
            let refused = match launch(h, &h.creator(), Some(resume.clone()), force)? {
                Ok(plan) => {
                    return Err(format!(
                        "{provider}: creator resume {resume:?} force={force} planned {:?}",
                        plan.conversation
                    )
                    .into());
                }
                Err(error) => error,
            };
            let Detail::CapabilityInvalid(detail) = refused.body.detail() else {
                return Err(format!(
                    "{provider}: creator resume {resume:?} force={force} refused as {refused}"
                )
                .into());
            };
            assert!(
                detail.next_step.contains("Omit resume"),
                "{provider}: refusal must name the fresh-launch step: {}",
                detail.next_step
            );
        }
    }
    Ok(())
}

fn assert_resumes(h: &Harness, actor: &Actor, session: &SessionId, expected: &str) -> Check {
    for resume in selections(session) {
        let plan = launch(h, actor, Some(resume.clone()), false)?
            .map_err(|e| format!("{actor:?} resume {resume:?}: {e}"))?;
        let conversation = present(plan.conversation)?;
        assert_eq!(conversation.as_str(), expected, "{resume:?}");
    }
    Ok(())
}

/// Protects #478: a create grant never reopens a Claude child's saved
/// conversation, for the latest or an exact session, with or without force.
#[test]
fn creator_cannot_resume_a_claude_child() -> Check {
    let h = Harness::new()?;
    let session = saved(&h, Provider::Claude)?;
    assert_creator_refused(&h, &session, "claude")?;
    h.finish()
}

/// Protects #478 on Codex, whose resume would read the child's private capture
/// source; force must not turn that refusal into a silent fresh conversation.
#[test]
fn creator_cannot_resume_a_codex_child() -> Check {
    let h = Harness::new()?;
    use_codex(&h)?;
    let session = saved(&h, Provider::Codex)?;
    assert_creator_refused(&h, &session, "codex")?;
    h.finish()
}

/// Creator control still launches the direct child fresh, with or without force.
#[test]
fn creator_launches_a_child_fresh() -> Check {
    for codex in [false, true] {
        let h = Harness::new()?;
        let provider = if codex {
            use_codex(&h)?;
            Provider::Codex
        } else {
            Provider::Claude
        };
        saved(&h, provider)?;
        for force in [false, true] {
            for resume in [None, Some(ResumeSelection::Latest(false))] {
                let plan = launch(&h, &h.creator(), resume, force)??;
                assert!(
                    matches!(plan.conversation, se_types::Read::Absent { .. }),
                    "codex={codex} force={force}: {:?}",
                    plan.conversation
                );
            }
        }
        h.finish()?;
    }
    Ok(())
}

/// The project Owner reopens the child's latest or exact saved conversation.
#[test]
fn owner_resumes_a_child() -> Check {
    let h = Harness::new()?;
    let session = saved(&h, Provider::Claude)?;
    assert_resumes(&h, &h.owner(), &session, CLAUDE_REFERENCE)?;
    h.finish()?;
    let h = Harness::new()?;
    use_codex(&h)?;
    let session = saved(&h, Provider::Codex)?;
    assert_resumes(&h, &h.owner(), &session, CODEX_THREAD)?;
    h.finish()
}

/// The child itself reopens its own latest or exact saved conversation.
#[test]
fn child_resumes_itself() -> Check {
    for codex in [false, true] {
        let h = Harness::new()?;
        let (provider, expected) = if codex {
            use_codex(&h)?;
            (Provider::Codex, CODEX_THREAD)
        } else {
            (Provider::Claude, CLAUDE_REFERENCE)
        };
        let session = saved(&h, provider)?;
        assert_resumes(&h, &Actor::Agent(h.target.clone()), &session, expected)?;
        h.finish()?;
    }
    Ok(())
}
