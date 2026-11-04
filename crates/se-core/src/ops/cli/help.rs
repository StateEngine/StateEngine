//! One-line summaries for the live CLI grammar. The catalogue plus this table
//! are the only source of public command help; wording states the supported
//! effect, starts with an ordinary verb and avoids fleet vocabulary.

/// Group summaries, keyed by the visible root group name. Groups are command
/// families whose own node carries no operation; the first inserted leaf
/// cannot name them.
pub(super) fn group(name: &str) -> Option<&'static str> {
    Some(match name {
        "msg" => "Send, inspect and settle messages",
        "working-state" => "Read or save an agent's working notes",
        "agent" => "Create and inspect saved agents",
        "config" => "Read or change saved agent settings",
        "hook" => "Receive provider lifecycle events",
        "session" => "Read the current agent session",
        "decision" => "Inspect proposals and record owner decisions",
        _ => return None,
    })
}

/// Operation summaries, keyed by catalogue name. A leaf that is itself the
/// root entry (status, up, down, ...) takes its summary here.
pub(super) fn command(name: &str) -> Option<&'static str> {
    Some(match name {
        "meta.help" => "Explain a command and its options",
        "meta.schema" => "Show registered operation input and output schemas",
        "store.import_node" => {
            "Import supported user history without changing the original Node state"
        }
        "project.init" => "Register this folder and save your first agent",
        "doctor.inspect" => "Check this installation and name exact supported repairs",
        "project.status" => "Show project, agent and unread-message status",
        "history.event_read" => "Read one committed event by ID",
        "history.list" => {
            "Read the public timeline: conversations, mail, decisions, working state and saved identity changes"
        }
        "message.send" => "Send one direct message or a floor work message",
        "message.read" => "Read one complete message and mark it read as its recipient",
        "message.ack" => "Mark your received message read without returning its body",
        "message.dismiss" => "Dismiss your received message without marking it read",
        "message.list" => "List authorized messages with explicit completeness",
        "message.inbox" => "List unread inbox messages",
        "session.context" => "Read context for the currently bound agent session",
        "hook.claude" => "Receive a Claude Code lifecycle event on stdin",
        "working_state.get" => "Read or save an agent's working notes",
        "working_state.set" => "Replace a working-state note behind a revision guard",
        "runtime.up" => "Start this data home's background runtime",
        "runtime.down" => "Stop this data home's runtime",
        "installation.uninstall" => "Remove this installation while preserving retained data",
        "agent.create" => "Create a saved agent identity without launching a process",
        "continuity.resume" => {
            "Restore your saved context and recent turns; this read acknowledges nothing"
        }
        "agent.list" => "List the saved agents in this project",
        "agent.launch" => "Start or resume a saved agent in a window; --detach runs headless",
        "agent.stop" => "Stop a selected agent's running session",
        "project.remove" => "Unregister projects while preserving repository files and history",
        "agent.show" => "Show one saved agent's identity and saved settings",
        "config.get" => "Read one saved agent setting",
        "config.set" => "Change one saved agent setting",
        "decision.list" => "List current and pending project decisions",
        "decision.show" => "Show one decision with its exact current revision",
        "decision.propose" => "Propose a project decision",
        "decision.ratify" => "Ratify a proposal so it governs the project",
        "decision.reject" => "Reject a proposal with a recorded reason",
        "decision.retract" => "Retract a decision with a recorded reason",
        "decision.supersede" => "Replace one decision with a newer one",
        _ => return None,
    })
}
