//! Status construction for a measured absent store; it creates no identity or runtime.
use super::outputs::*;
use se_types::Read;

/// Unread recipient mail is pending attention even when its process is live.
/// Use the measured agent page; status does not infer a wake or mark mail read.
pub fn pending_mail(output: &mut StatusOutput) {
    let Some(agents) = &output.agents else {
        return;
    };
    for agent in agents.items() {
        let Some(count) = agent.unread.filter(|count| *count > 0) else {
            continue;
        };
        let delivery = if agent.session.state == "running"
            && agent.session.surface.as_deref() == Some("window")
        {
            if agent.provider == se_types::Provider::Claude {
                "Automatic inbox wakeups are unavailable in attended Claude. Ask the agent in its window to read its StateEngine inbox."
            } else {
                "A running window does not confirm that a mail wake was received. Ask the agent in its window to read its StateEngine inbox."
            }
        } else {
            "Mail is waiting for the agent to read its StateEngine inbox; a process or mail notice does not mark it read."
        };
        let recovery = if agent.session.state == "never-launched" {
            "Launch this agent with the task: Read your StateEngine inbox and handle incoming mail."
        } else {
            "If it does not respond, stop and reopen the same conversation with the task: Read your StateEngine inbox and handle incoming mail."
        };
        let noun = if count == 1 { "message" } else { "messages" };
        output.pending.push(PendingFact {
            what: "unread agent mail".into(),
            since: None,
            detail: format!(
                "{} ({}) has {count} unread {noun}. {delivery} {recovery}",
                agent.name, agent.id,
            ),
        });
    }
}

pub fn missing(home: String, generated_at: String, checked: String) -> StatusOutput {
    StatusOutput {
        scope: "home".into(),
        generated_at,
        version: env!("CARGO_PKG_VERSION").into(),
        setup: SetupView {
            state: SetupState::NotSetUp,
            home,
            reason: Some("StateEngine has not been initialized in this home.".into()),
        },
        runtime: RuntimeView {
            state: "unknown".into(),
            detachment: None,
            host: None,
            process: None,
            generation: None,
            endpoint: None,
            version: None,
            observed_at: None,
            resources: None,
            resources_unavailable: None,
        },
        project: Read::Absent { checked },
        removal: None,
        principal: None,
        agents: None,
        inbox: InboxCounts {
            owner_unread: None,
            self_unread: None,
        },
        decisions: DecisionCounts { pending: None },
        capture: CaptureView {
            state: "unknown".into(),
            last_turn_at: None,
        },
        atlas: AtlasView {
            state: "not-built".into(),
            history: "unavailable".into(),
        },
        pending: vec![],
        projects: None,
        next: NextStep {
            text: "Initialize this repository, then launch your first agent.".into(),
            command: "se init".into(),
            argv: vec!["se".into(), "init".into()],
        },
    }
}
