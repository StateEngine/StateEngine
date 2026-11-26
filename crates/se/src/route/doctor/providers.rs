//! Provider readiness a first launch depends on: each CLI against the launch version floor,
//! and a Codex MCP entry that its configuration files split across two transports.
use super::{Bootstrap, CheckFix, CheckState, DiagnosisCheck};
use se_host::{
    adoption::Kind,
    provider_cli::{self, CliState},
    provider_mcp::codex_transport::{self, Observation, Severity},
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
        "The Codex user configuration file is readable and its `stateengine` MCP server sets one transport, with a home and executable that exist; no project configuration file defines that server"
            .into(),
    );
    let observed = std::env::current_dir()
        .map_err(|error| error.to_string())
        .and_then(|cwd| codex_transport::observe(&cwd).map_err(|error| error.body.message()));
    match observed {
        Ok(observation) => codex_findings(&mut value, &observation),
        Err(reason) => {
            value.state = CheckState::Unmeasured;
            value.observed = Some(format!("Codex configuration was not located: {reason}"));
        }
    }
    value
}

/// Broken user entry: failed. Unreadable file: unmeasured. Project-file entry: warning.
fn codex_findings(value: &mut DiagnosisCheck, observation: &Observation) {
    let files = observation.files();
    value.observed = Some(if files.is_empty() {
        "No Codex configuration file exists yet".into()
    } else {
        format!(
            "Found {}",
            files
                .iter()
                .map(|file| file.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    });
    let findings = observation.findings();
    let rank = |severity: Severity| match severity {
        Severity::Blocking | Severity::Problem => (3, CheckState::Failed),
        Severity::UnreadableUser | Severity::Unmeasured => (2, CheckState::Unmeasured),
        Severity::Advisory => (1, CheckState::Warning),
    };
    if let Some((_, state)) = findings
        .iter()
        .map(|finding| rank(finding.severity))
        .max_by_key(|(order, _)| *order)
    {
        value.state = state;
        value.fix = Some(text(
            findings
                .into_iter()
                .map(|finding| finding.text)
                .collect::<Vec<_>>()
                .join(" "),
        ));
    }
}

fn text(text: String) -> CheckFix {
    CheckFix {
        text,
        command: None,
        argv: None,
    }
}
