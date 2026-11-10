//! Independent receipt checks through a real store, observation adapter and CLI parser.
#![allow(
    dead_code,
    reason = "The unchanged executable parser imports shared compatibility helpers."
)]
#[path = "../src/compat.rs"]
mod compat;
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
#[path = "../src/grammar.rs"]
mod grammar;
#[path = "../src/render/mod.rs"]
mod render;
use fixture::*;
use se_core::{
    commit::Cx,
    ops::{AgentShow, AnyOp, agent_status},
};
use se_store::*;
use std::{
    path::Path,
    time::{Duration, Instant},
};

fn observe(
    home: &Path,
) -> Result<(se_core::ops::AgentRow, se_types::ProjectId), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    store.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request(&format!(
                "fixture-resume_command_independent-31-{}",
                serial()
            ))?),
            vec![EventBody::ProfileSaved {
                agent: f.a.clone(),
                profile: Profile {
                    provider: Provider::Claude,
                    model: None,
                    permission: PermissionProfile::WorkspaceWrite,
                    named_profile: "default".into(),
                    effort: None,
                },
                expected: Expected::Absent,
            }],
        )?,
        &*lease,
    )?;
    let admission = f.owner_project();
    let mut read = store.snapshot(f.scoped(Visibility::Owner))?;
    let mut row = present(
        agent_status::show(
            AgentShow {
                target_agent_id: Some(f.a.clone()),
            },
            &mut Cx {
                read: &mut read,
                admission: &admission,
            },
        )?
        .agent,
    )?;
    let plan = se_host::prepare_agent_observation(&f.project, &row, &mut read)?;
    read.close()?;
    se_host::observe_agent(
        plan.with_command_home(home),
        Instant::now() + Duration::from_secs(2),
    )?
    .apply(&mut row)?;
    Ok((row, f.project.clone()))
}

#[test]
fn observed_saved_agent_command_parses_without_losing_home_project_or_target() -> Check {
    let home = Path::new("/private/state with 'quotes'/日本語/$keep;literal");
    let (row, project) = observe(home)?;
    let argv = row.resume.argv.ok_or("missing fresh command")?;
    let invocation = grammar::parse(argv.iter().map(Into::into).collect())
        .map_err(|failure| failure.error.to_string())?;
    assert_eq!(invocation.common.home.as_deref(), Some(home));
    assert_eq!(invocation.common.project.as_deref(), Some(project.as_str()));
    assert_eq!(
        invocation.common.selections.agent.as_deref(),
        Some(row.id.as_str())
    );
    assert!(
        matches!(invocation.operation, AnyOp::AgentLaunch(input) if input.detach && input.fresh)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn non_utf8_configured_home_never_becomes_a_different_receipt_home() -> Check {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt, path::PathBuf};
    let home = PathBuf::from(OsString::from_vec(b"/private/state-\xff".to_vec()));
    let (row, _) = observe(&home)?;
    assert!(
        row.resume.command.is_none() && row.resume.argv.is_none(),
        "unrepresentable home emitted a command for different bytes: {:?}",
        row.resume.argv
    );
    assert!(
        row.resume.reason.is_some(),
        "unavailable command has no reason"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn human_launch_stop_hint_preserves_the_receipt_home_project_and_agent() -> Check {
    use se_core::{
        config_policy::{ConfigFile, Provider},
        ops::{AgentCommand, LaunchResult, ProcessView, ResumeCommand},
    };
    use se_types::{LaunchId, LifecycleId, Named, ProviderSessionId, SessionId};
    let f = Fixture::new()?;
    let home = Path::new("/private/Selected home");
    let resume = AgentCommand::launch_in_home(&f.a, home, &f.project, false).ok_or("command")?;
    let value = LaunchResult {
        secode_binding: None,
        takeover: None,
        idempotency_key: request("render-launch")?.key,
        event_id: event()?,
        launch_id: LaunchId::from_parts(1_700_000_000_000, [1; 10])?,
        lifecycle_id: LifecycleId::from_parts(1_700_000_000_000, [2; 10])?,
        project: Named {
            id: f.project.clone(),
            name: "Project".into(),
        },
        agent: Named {
            id: f.a.clone(),
            name: "Same".into(),
        },
        session_id: SessionId::from_parts(1_700_000_000_000, [3; 10])?,
        provider: Provider::Claude,
        model: None,
        permission_profile: ConfigFile::default().resolve_profile(
            "default",
            Provider::Claude,
            false,
        )?,
        conversation_id: ProviderSessionId::new("render-conversation")?,
        resumed: false,
        saved_conversation_age: se_types::Read::Absent {
            checked: "new conversation".into(),
        },
        state: "running".into(),
        surface: "headless".into(),
        process: ProcessView {
            pid: 42,
            started_at: "2026-01-01T00:00:00Z".into(),
            exe: "provider".into(),
            machine_id: "fixture".into(),
        },
        containment: "contained".into(),
        containment_cause: None,
        replies: AgentCommand::history_in_home(&f.a, home, &f.project),
        resume: ResumeCommand {
            ready: true,
            mode: "resume".into(),
            reason: None,
            command: Some(resume.command),
            argv: Some(resume.argv),
        },
    };
    let mut bytes = Vec::new();
    render::output(&value.into(), false, false, &mut bytes)?;
    let text = String::from_utf8(bytes)?;
    if let Some(stop) = text.lines().find_map(|line| line.strip_prefix("Stop: ")) {
        // Execute shell builtins only, to recover exactly the displayed words.
        let output = std::process::Command::new("sh")
            .args(["-c", &format!("set -- {stop}; printf '%s\\0' \"$@\"")])
            .output()?;
        assert!(output.status.success());
        let words = output
            .stdout
            .strip_suffix(&[0])
            .ok_or("word terminator")?
            .split(|byte| *byte == 0)
            .map(|word| String::from_utf8(word.to_vec()).map(Into::into))
            .collect::<Result<Vec<_>, _>>()?;
        let parsed = grammar::parse(words).map_err(|failure| failure.error.to_string())?;
        assert_eq!(
            parsed.common.home.as_deref(),
            Some(home),
            "human Stop hint lost the selected home: {stop}"
        );
        assert_eq!(parsed.common.project.as_deref(), Some(f.project.as_str()));
        assert_eq!(
            parsed.common.selections.agent.as_deref(),
            Some(f.a.as_str())
        );
        assert!(matches!(parsed.operation, AnyOp::AgentStop(_)));
    }
    Ok(())
}
