//! Report unresolved startup/cleanup from the same complete protected inventory
//! used for owner admission. Diagnosis grants no process control authority.
use super::*;
use se_core::store_error::store_error;
use se_store::{Actor, ProcessState, ReadStore};

pub(super) fn checks<R: ReadStore>(
    cx: &Bootstrap,
    files: &Files,
    reader: &R,
    at: &str,
) -> Result<Vec<DiagnosisCheck>> {
    let inventory = reader
        .owner_guard(files, super::super::owner::budget()?)
        .map_err(|error| store_error(&error))?;
    let mut checks = Vec::new();
    for entry in inventory.processes {
        let (state, detail) = match entry.state {
            ProcessState::Reserved | ProcessState::Starting => (
                CheckState::Warning,
                "The agent has not finished startup; capture is not ready",
            ),
            ProcessState::StopRequested
            | ProcessState::StopUnproved
            | ProcessState::Lost
            | ProcessState::Exited => (
                CheckState::Failed,
                "Stopping the agent or finishing its session cleanup remains unresolved",
            ),
            _ => continue,
        };
        let subject = match &entry.identity.principal {
            Actor::Agent(agent) => format!("agent {agent}"),
            Actor::Human(human) => format!("owner {human}"),
            Actor::Remote(principal) => format!("remote device {principal}"),
        };
        let mut row = check(
            &format!("runtime.launch.{}", entry.identity.record),
            "Managed launch readiness and cleanup",
            state,
            format!(
                "{detail}; project {}, {subject}, launch {}",
                entry.project, entry.identity.record
            ),
            at,
        );
        row.reason = Some("An endpoint and a held runtime lease do not prove provider readiness or completed cleanup".into());
        if let Actor::Agent(agent) = entry.identity.principal {
            row.fix = Some(CheckFix {
                text: "Inspect this agent with se status; to cancel startup or retry its retained cleanup, stop this exact agent from the owner terminal".into(),
                command: None,
                argv: Some(vec!["se".into(), "--home".into(), cx.home.display().to_string(), "--project".into(), entry.project.to_string(), "stop".into(), agent.to_string()]),
            });
        }
        checks.push(row);
    }
    Ok(checks)
}
