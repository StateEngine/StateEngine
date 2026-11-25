//! Provider readiness a first launch depends on: each CLI against the launch version floor,
//! and a Codex MCP entry that its configuration files split across two transports.
use super::{Bootstrap, CheckFix, CheckState, DiagnosisCheck};
use se_host::{
    adoption::Kind,
    provider_cli::{self, CliState},
    provider_mcp::codex_transport::{self, Config, Transports},
};
use se_types::RenderCx;

pub(super) fn checks(cx: &Bootstrap, at: &str) -> Vec<DiagnosisCheck> {
    let states: Vec<_> = Kind::ALL
        .into_iter()
        .map(|kind| (kind, provider_cli::observe(&cx.config.value, kind)))
        .collect();
    let any_ready = states
        .iter()
        .any(|(_, state)| matches!(state, CliState::Ready { .. }));
    let mut checks: Vec<_> = states
        .into_iter()
        .map(|(kind, state)| cli(kind, state, any_ready, at))
        .collect();
    checks.push(codex_mcp(at));
    checks
}

fn cli(kind: Kind, state: CliState, any_ready: bool, at: &str) -> DiagnosisCheck {
    let id = format!("provider.{}", kind.name());
    let title = format!("{} CLI", kind.label());
    let mut value = super::check(&id, &title, CheckState::Ok, String::new(), at);
    value.expected = Some(format!(
        "Installed, meeting the version StateEngine launches with ({})",
        provider_cli::minimum(kind)
    ));
    match state {
        CliState::Ready {
            executable,
            version,
        } => {
            value.observed = Some(format!("{version} at {}", executable.display()));
        }
        CliState::Missing => {
            // One signed-in provider is enough; the other is only needed to launch with it.
            value.state = if any_ready {
                CheckState::NotApplicable
            } else {
                CheckState::Failed
            };
            value.observed = Some(format!("`{}` was not found on PATH", kind.name()));
            value.fix = Some(text(format!(
                "Install {} {} or newer, sign in, then rerun se doctor.",
                kind.label(),
                provider_cli::minimum(kind)
            )));
        }
        CliState::Refused(error) => {
            value.state = CheckState::Failed;
            value.observed = Some(error.body.message());
            value.code = Some(error.code().as_str().into());
            let remedy = error.body.remedy(&RenderCx::default()).ok();
            value.fix = Some(text(remedy.map_or_else(
                || {
                    format!(
                        "Install {} {} or newer.",
                        kind.label(),
                        provider_cli::minimum(kind)
                    )
                },
                |remedy| remedy.text,
            )));
        }
    }
    value
}

fn codex_mcp(at: &str) -> DiagnosisCheck {
    let mut value = super::check(
        "provider.codex_mcp",
        "Codex MCP entry",
        CheckState::Ok,
        String::new(),
        at,
    );
    value.expected = Some(
        "The Codex `stateengine` MCP server sets one transport across the user and project configuration files, and its home and executable exist"
            .into(),
    );
    let observed = std::env::current_dir()
        .map_err(|error| error.to_string())
        .and_then(|cwd| codex_transport::observe(&cwd).map_err(|error| error.body.message()));
    match observed {
        Ok(Transports::Read(config)) => codex_entries(&mut value, &config),
        Ok(Transports::Unreadable { file, reason }) => {
            value.state = CheckState::Unmeasured;
            value.observed = Some(format!("{} could not be read: {reason}", file.display()));
        }
        Err(reason) => {
            value.state = CheckState::Unmeasured;
            value.observed = Some(format!("Codex configuration was not located: {reason}"));
        }
    }
    value
}

fn codex_entries(value: &mut DiagnosisCheck, read: &Config) {
    let files = &read.files;
    let mut problems: Vec<String> = read.conflict().into_iter().collect();
    problems.extend(read.stale());
    if let Some((command, url)) = read.split() {
        value.observed = Some(format!(
            "`command` in {}; `url` in {}",
            command.display(),
            url.display()
        ));
    } else if files.is_empty() {
        value.observed = Some("No Codex configuration file exists yet".into());
    } else {
        value.observed = Some(format!(
            "Read {}",
            files
                .iter()
                .map(|file| file.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !problems.is_empty() {
        value.state = CheckState::Failed;
        value.fix = Some(text(problems.join(" ")));
    } else if let Some(note) = read.advisory() {
        value.state = CheckState::Warning;
        value.fix = Some(text(note));
    }
}

fn text(text: String) -> CheckFix {
    CheckFix {
        text,
        command: None,
        argv: None,
    }
}
