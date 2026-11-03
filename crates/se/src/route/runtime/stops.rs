//! Per-agent results use exact lifecycle exit facts, independently of the fleet bit.
use super::*;
use se_host::client::{closure::RuntimeClosure, endpoint::RuntimeStopResume};

pub(super) fn render(
    report: Option<&RuntimeClosure>,
    retained: Vec<RuntimeStopResume>,
    observed_at: &str,
    pending: &mut Vec<String>,
) -> Vec<StopFact> {
    let mut result = Vec::new();
    if let Some(report) = report {
        for target in &report.stops {
            let witness = target.witness.as_ref().filter(|w| {
                w.lifecycle == target.lifecycle
                    && w.scope_exit.remaining.population == se_proc::Population::Empty
                    && w.scope_exit.exit_basis.is_some()
            });
            let detail = format!(
                "project={}; agent={}; lifecycle={}; original conversation={}; {}",
                target.project,
                target.agent,
                target.lifecycle,
                target
                    .conversation
                    .as_ref()
                    .map(|v| v.as_str())
                    .unwrap_or("not available"),
                target
                    .reason
                    .as_deref()
                    .unwrap_or("exact native exit checkpoint retained")
            );
            if witness.is_none() {
                pending.push(format!("Per-agent exit remains unproved: {detail}"));
            }
            result.push(StopFact {
                target: target.agent.to_string(),
                complete: witness.is_some(),
                witness: Witness {
                    state: if witness.is_some() {
                        WitnessState::Witnessed
                    } else {
                        WitnessState::Unknown
                    },
                    method: witness
                        .map(|w| {
                            format!(
                                "native lifecycle exit checkpoint: {:?}, {:?}",
                                w.guarantee, w.scope_exit.exit_basis
                            )
                        })
                        .unwrap_or_else(|| "individual native exit not witnessed".into()),
                    observed_at: observed_at.into(),
                    detail: Some(detail),
                },
                resume: unavailable(),
            });
        }
    }
    for saved in retained {
        if report.is_some_and(|r| {
            r.stops.iter().any(|v| {
                v.project == saved.project
                    && v.agent == saved.agent
                    && v.conversation.as_ref() == Some(&saved.conversation)
            })
        }) {
            continue;
        }
        let reason = format!(
            "Agent {} has a saved original conversation {}, but this stop reports no separate lifecycle exit witness; aggregate AgentsStopped is insufficient.",
            saved.agent, saved.conversation
        );
        pending.push(reason.clone());
        result.push(StopFact {
            target: saved.agent.to_string(),
            complete: false,
            witness: Witness {
                state: WitnessState::Unknown,
                method: "individual native exit not witnessed".into(),
                observed_at: observed_at.into(),
                detail: Some(reason),
            },
            resume: unavailable(),
        });
    }
    result
}
fn unavailable() -> ResumeCommand {
    ResumeCommand { ready: false, mode: "unknown".into(), reason: Some("The original conversation is retained when available; no provider resume command was independently verified. Runtime shutdown completion does not imply resume readiness.".into()), command: None, argv: None }
}
