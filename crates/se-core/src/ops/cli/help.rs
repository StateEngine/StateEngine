//! One-line summaries for the live CLI grammar. The catalogue plus this table
//! are the only source of public command help; wording states the supported
//! effect, starts with an ordinary verb and avoids fleet vocabulary.

/// Group summaries, keyed by the visible root group name. Groups are command
/// families whose own node carries no operation; the first inserted leaf
/// cannot name them.
pub(super) fn group(name: &str) -> Option<&'static str> {
    Some(match name {
        "remote" => "List, watch and message agents through an Owner-configured remote binding",
        "msg" => "Send and read direct or shared project messages",
        "working-state" => "Read or save an agent's working notes",
        "agent" => "Create and inspect saved agents",
        "atlas" => "Find code and inspect references, impact, changes and file outlines",
        "config" => "Read or change user configuration and saved agent settings",
        "hook" => "Receive provider lifecycle events",
        "session" => "Read the current agent session",
        _ => return None,
    })
}

/// Operation summaries, keyed by catalogue name. A leaf that is itself the
/// root entry (status, up, down, ...) takes its summary here.
pub(super) fn command(name: &str) -> Option<&'static str> {
    Some(match name {
        "remote.list" => "List the agents allowed by a saved remote binding",
        "remote.watch" => "Read one bounded live/durable page; disconnect never stops work",
        "remote.send" => "Send keyed direct mail to an exact remote agent session",
        "meta.help" => "Explain a command and its options",
        "meta.guide" => "List guide topics or read one named topic",
        "meta.schema" => "Show registered operation input and output schemas",
        #[cfg(feature = "import")]
        "store.import_node" => "Import retained history without changing its source files",
        "project.init" => "Register this folder and save your first agent",
        "diagnostic.bundle" => "Save a private redacted diagnostic file to share for support",
        "doctor.inspect" => "Check this installation and name exact supported repairs",
        "project.status" => "Show project, agent and unread-message status",
        "history.event_read" => "Read one committed event by ID",
        "history.list" => {
            "Read the public timeline: conversations, mail, decisions, working state and saved identity changes"
        }
        "message.send" => "Send one direct message or a shared project message (the floor)",
        "message.read" => "Read one complete message and mark it read as its recipient",
        "message.ack" => "Mark your received message read without returning its body",
        "message.dismiss" => "Dismiss your received message without marking it read",
        "message.list" => "List authorized messages with explicit completeness",
        "message.inbox" => "List unread inbox messages",
        "session.context" => "Read context for the currently bound agent session",
        "hook.claude" => "Receive a Claude Code lifecycle event on stdin",
        "working_state.get" => "Read or save an agent's working notes",
        "working_state.set" => "Save working notes only if their revision still matches",
        "runtime.up" => "Start this data home's background runtime",
        "runtime.down" => "Stop this data home's runtime",
        "installation.uninstall" => "Remove this installation while preserving retained data",
        "agent.create" => "Create a saved agent identity without launching a process",
        "agent.rename" => "Rename a saved agent's display name",
        "continuity.resume" => {
            "Read the current session's saved context; owners use --preview AGENT"
        }
        "agent.list" => "List the saved agents in this project",
        "agent.launch" => "Start or resume a saved agent; --detach runs without opening a window",
        "agent.stop" => "Stop a selected agent's running session",
        "agent.wake" => "Offer a running agent's pending mail and report the committed result",
        "project.remove" => "Unregister projects while preserving repository files and history",
        "agent.show" => "Show one saved agent's identity and saved settings",
        "config.get" => "Read one saved agent setting",
        "config.list" => "List the effective user configuration settings",
        "config.set" => "Change one saved agent setting",
        _ => return None,
    })
}
