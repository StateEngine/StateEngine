//! Receipt argv must be accepted by the executable's unchanged real parser.
#![allow(
    dead_code,
    reason = "Compile the same parser and compatibility adapter as se."
)]
#[path = "../src/compat.rs"]
mod compat;
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
#[path = "../src/grammar.rs"]
mod grammar;

use se_core::ops::{AgentCommand, AnyOp};
use se_types::{AgentId, ProjectId};
use std::path::PathBuf;

type Check = Result<(), Box<dyn std::error::Error>>;

fn parse(command: &AgentCommand) -> grammar::Invocation {
    grammar::parse(command.argv.iter().map(Into::into).collect())
        .unwrap_or_else(|failure| panic!("receipt argv {:?}: {}", command.argv, failure.error))
}

#[test]
fn every_resume_variant_parses_as_the_exact_agent_launch() -> Check {
    let agent = AgentId::from_parts(1_700_000_000_000, [13; 10])?;
    let project = ProjectId::from_parts(1_700_000_000_000, [17; 10])?;
    for home in [None, Some("/private/Pat's State Engine/日本語")] {
        for project in [None, Some(&project)] {
            for fresh in [false, true] {
                let command = AgentCommand::launch(&agent, home, project, fresh);
                let parsed = parse(&command);
                assert_eq!(parsed.common.home, home.map(PathBuf::from));
                assert_eq!(parsed.common.project, project.map(ToString::to_string));
                assert_eq!(parsed.common.selections.agent, Some(agent.to_string()));
                let AnyOp::AgentLaunch(input) = parsed.operation else {
                    panic!("resume argv selected another operation");
                };
                assert!(input.detach);
                assert_eq!(input.fresh, fresh);
                assert!(input.target_agent_id.is_none());
                assert!(!command.argv.iter().any(|arg| arg == "--agent"));
            }
        }
    }
    Ok(())
}

#[test]
fn removal_retry_parses_as_the_exact_agent_stop() -> Check {
    let agent = AgentId::from_parts(1_700_000_000_000, [19; 10])?;
    let project = ProjectId::from_parts(1_700_000_000_000, [23; 10])?;
    let home = "C:\\Users\\Pat's Home\\State Engine";
    let command = AgentCommand::stop(&agent, Some(home), Some(&project));
    let parsed = parse(&command);
    assert_eq!(parsed.common.home, Some(PathBuf::from(home)));
    assert_eq!(parsed.common.project, Some(project.to_string()));
    assert_eq!(parsed.common.selections.agent, Some(agent.to_string()));
    assert!(matches!(parsed.operation, AnyOp::AgentStop(_)));
    assert!(!parsed.common.selections.control_all);
    assert!(!parsed.common.selections.stop_release);
    Ok(())
}

#[test]
fn public_status_list_and_show_keep_the_selected_installation() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let fixture = fixture::Fixture::new()?;
    let home = fixture.home.join("Pat's State Engine");
    let root = fixture.home.join("repository");
    std::fs::create_dir(&root)?;
    let call = |args: &[&str]| -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_se"));
        command
            .args(["--json", "--home"])
            .arg(&home)
            .args(args)
            .current_dir(&root);
        for name in [
            "SE_HOME",
            "SE_PROJECT",
            "SE_CONFIG",
            "SE_LOG",
            "SE_SESSION",
            "CLAUDECODE",
            "CODEX_THREAD_ID",
            "CODEX_CI",
        ] {
            command.env_remove(name);
        }
        let output = command.output()?;
        assert!(
            output.status.success(),
            "CLI: {}; {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(serde_json::from_slice(&output.stdout)?)
    };
    let initialized = call(&["init", "--name", "receipt-commands"])?;
    let project = initialized["project"]["id"].as_str().ok_or("project")?;
    let added = call(&["--project", project, "agent", "add", "receipt-agent"])?;
    let agent = added["agent"]["id"].as_str().ok_or("agent")?;
    for args in [
        vec!["--project", project, "status"],
        vec!["--project", project, "agent", "list"],
        vec!["--project", project, "agent", "show", agent],
    ] {
        let output = call(&args)?;
        let resume =
            find_resume(&output, agent).ok_or_else(|| format!("missing agent resume: {output}"))?;
        let argv: Vec<String> = serde_json::from_value(resume["argv"].clone())?;
        let parsed = grammar::parse(argv.iter().map(Into::into).collect())
            .unwrap_or_else(|failure| panic!("returned argv: {}", failure.error));
        assert_eq!(parsed.common.home, Some(home.clone()));
        assert_eq!(parsed.common.project.as_deref(), Some(project));
        assert_eq!(parsed.common.selections.agent.as_deref(), Some(agent));
        assert!(
            matches!(parsed.operation, AnyOp::AgentLaunch(input) if input.detach && input.fresh)
        );
    }
    Ok(())
}

fn find_resume<'a>(value: &'a serde_json::Value, agent: &str) -> Option<&'a serde_json::Value> {
    match value {
        serde_json::Value::Object(fields) => {
            if value["id"].as_str() == Some(agent) && fields.contains_key("resume") {
                return fields.get("resume");
            }
            fields.values().find_map(|value| find_resume(value, agent))
        }
        serde_json::Value::Array(values) => {
            values.iter().find_map(|value| find_resume(value, agent))
        }
        _ => None,
    }
}

#[cfg(unix)]
#[test]
fn displayed_command_preserves_the_same_words_through_the_shell() -> Check {
    let agent = AgentId::from_parts(1_700_000_000_000, [29; 10])?;
    let project = ProjectId::from_parts(1_700_000_000_000, [31; 10])?;
    let home = "/private/Pat's State Engine/$unchanged; 日本語";
    for command in [
        AgentCommand::launch(&agent, Some(home), Some(&project), false),
        AgentCommand::launch(&agent, Some(home), Some(&project), true),
        AgentCommand::stop(&agent, Some(home), Some(&project)),
    ] {
        // Parse shell words without running se or accessing any installation.
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("set -- {}; printf '%s\\0' \"$@\"", command.command))
            .output()?;
        assert!(output.status.success());
        let words = output
            .stdout
            .strip_suffix(&[0])
            .ok_or("missing NUL")?
            .split(|byte| *byte == 0)
            .map(|word| String::from_utf8(word.to_vec()))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(words, command.argv);
    }
    Ok(())
}
