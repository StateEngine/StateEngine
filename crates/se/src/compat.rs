//! Inert refusals for removed syntax. Never forwards arguments or opens state.
use se_types::{Detail, SeError, details};
use std::ffi::OsString;

/// Arguments exclude argv[0]. Unknown options remain the generated grammar's job.
pub fn refusal(args: &[OsString]) -> Option<SeError> {
    let command = command_start(args)?;
    let rest = &args[command..];
    let first = rest.first()?.to_str()?;
    let second = rest.get(1).and_then(|arg| arg.to_str());
    let unavailable = match (first, second) {
        ("launch", _) | ("seat", Some("launch")) => Some((
            "agent launch",
            "Use se init to save a project and se status to inspect it.",
        )),
        ("seat", Some("stop")) => Some(("agent stop", "Use se status to inspect running work.")),
        ("wake", _) | ("seat", Some("wake")) => Some((
            "agent wake",
            "Use se agent show AGENT to inspect a saved agent.",
        )),
        ("agents", _) => Some((
            "agent listing",
            "Use se status to inspect the project's saved agents.",
        )),
        ("decision", _) if only_presentation_flags(&rest[1..]) => Some((
            "decision listing",
            "Use se decision show ID for a known decision, or se status for its pending count.",
        )),
        ("decisions" | "pending", _) => Some((
            "decision listing",
            "Use se decision show ID for a known decision, or se status for its pending count.",
        )),
        ("agent-rename", _) => Some((
            "agent rename",
            "Use se agent show AGENT to inspect saved metadata.",
        )),
        ("rawlog-search", _) => Some((
            "history search",
            "Use se history --event ID to inspect a known event.",
        )),
        ("packet", _) => Some((
            "agent resume",
            "Use se agent show AGENT to inspect a saved agent.",
        )),
        ("decommission", _) | ("init", Some("--remove")) => Some((
            "project removal",
            "Use se status --all to inspect registered projects.",
        )),
        ("plugin" | "hook-install" | "hook-uninstall", _) => {
            Some(("integration repair", "Use se status to inspect setup."))
        }
        ("verify-chain", _) => Some(("integrity verification", "Use se status to inspect setup.")),
        ("hook-emit" | "capture-turn", _) => {
            Some(("legacy hook emission", "Use se status to inspect capture."))
        }
        _ => None,
    };
    if let Some((subject, next_step)) = unavailable {
        return Some(SeError::new(Detail::FeatureUnavailable(
            details::FeatureUnavailable {
                subject: subject.into(),
                reason: "not available in this build".into(),
                next_step: next_step.into(),
            },
        )));
    }
    let pair = match (first, second) {
        ("seat", Some("create")) => Some("se agent add NAME"),
        ("ratify", Some("all")) => {
            Some("se decision ratify ID (once per decision; no bulk approval)")
        }
        ("init", Some("--status")) => Some("se status"),
        _ => None,
    };
    if let Some(replacement) = pair {
        return Some(renamed(&format!("{first} {}", second?), replacement));
    }
    let replacement = match first {
        "projects" => "se status --all",
        "stop" if only_presentation_flags(&rest[1..]) => "se down",
        "ratify" => "se decision ratify ID",
        "ratifyall" => "se decision ratify ID (once per decision; no bulk approval)",
        "reject" => "se decision reject ID",
        "retract" => "se decision retract ID",
        "reverse" => "se decision supersede ID WITH_ID",
        "floor-event" => "se history --event ID",
        "capture-status" | "context" => "se status",
        "working-state-show" => "se working-state",
        "working-state-set" | "seat-continuity-write" => "se working-state set TEXT --expect REV",
        _ => return retired(first, second),
    };
    Some(renamed(first, replacement))
}

fn renamed(old: &str, replacement: &str) -> SeError {
    SeError::new(Detail::Renamed(details::Renamed {
        old: old.into(),
        replacement: replacement.into(),
    }))
}

fn retired(first: &str, second: Option<&str>) -> Option<SeError> {
    let (reason, workflow, paired) = match (first, second) {
        ("process", Some("start" | "inspect" | "stop" | "list"))
        | (
            "process-start"
            | "process-stop"
            | "stateengine_process_start"
            | "stateengine_process_stop",
            _,
        ) => (
            "the arbitrary process service was removed",
            "Use se status to inspect running work; arbitrary process control is unavailable.",
            first == "process",
        ),
        ("backup", _) => (
            "backups are automatic",
            "Use se status to inspect the store; owner recovery is unavailable in this build.",
            false,
        ),
        ("rebuild-index", _) => (
            "alpha has no projection replay command",
            "Use se status to inspect setup; projection repair is unavailable in this build.",
            false,
        ),
        ("agent", Some("alias")) | ("agent-alias" | "stateengine_agent_alias", _) => (
            "new aliases are no longer supported",
            "Use stable IDs with se agent show AGENT.",
            first == "agent",
        ),
        (
            "msg",
            Some(
                "complete" | "reconcile" | "treat" | "deliver" | "retry-delivery"
                | "recover-delivery" | "handoff" | "unread-ids" | "wake-backlog" | "turn-outcome"
                | "index-build",
            ),
        ) => (
            "legacy message maintenance commands were removed",
            "Use se msg list --full to inspect messages",
            true,
        ),
        ("seat", Some("cut" | "move" | "prompt")) => (
            "seat plumbing is no longer a product operation",
            "Use se status or se agent show AGENT to inspect saved work.",
            true,
        ),
        ("doctor", Some("contradictions")) => (
            "contradiction machinery was removed",
            "Use se status to inspect setup",
            true,
        ),
        ("mail-tunnel" | "stateengine_mail_tunnel", _) => (
            "native notifications replaced mail tunnels",
            "Use se status to inspect integration.",
            false,
        ),
        ("memories" | "stateengine_memory_suggest", _) => (
            "memories are no longer a separate store",
            "Use se decision show ID; imported memories are decisions",
            false,
        ),
        (name, _) if name.starts_with("memory-") => (
            "memories are no longer a separate store",
            "Use se decision show ID; imported memories are decisions",
            false,
        ),
        (
            "floor"
            | "floor-serve"
            | "projection-drain"
            | "drain-outbox"
            | "capture-receipts"
            | "file-write"
            | "project-owner-assign"
            | "human-bootstrap"
            | "state"
            | "run"
            | "serve"
            | "server"
            | "start"
            | "refresh"
            | "deps",
            _,
        ) => (
            "internal engine plumbing is not a public operation",
            "Use se status, se history --event ID for a known event, or se up to start the runtime.",
            false,
        ),
        (name, _) if name.starts_with("substrate-") || name.starts_with("brick") => (
            "legacy substrate plumbing was removed",
            "Use se status to inspect setup.",
            false,
        ),
        (
            "campaign" | "campaigns" | "review" | "reviews" | "gate" | "gates" | "landing"
            | "landings" | "land" | "land-preflight" | "merge-land" | "census" | "compute"
            | "remote" | "routing" | "route" | "mutation" | "mutation-check",
            _,
        ) => (
            "factory coordination is not part of StateEngine",
            "Use your project's external development workflow",
            false,
        ),
        _ => return None,
    };
    let old = if paired {
        format!("{first} {}", second?)
    } else {
        first.into()
    };
    Some(SeError::new(Detail::CommandRetired(
        details::CommandRetired {
            old,
            reason: reason.into(),
            workflow: workflow.into(),
        },
    )))
}

fn only_presentation_flags(args: &[OsString]) -> bool {
    args.iter().all(|arg| {
        matches!(
            arg.to_str(),
            Some("--json" | "--quiet" | "-q" | "--no-color")
        )
    })
}

/// Skip only documented root options, including their values. Do not scan option
/// values for command names, and never reinterpret a token after an unknown flag.
fn command_start(args: &[OsString]) -> Option<usize> {
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        let text = arg.to_str()?;
        match text {
            "--home" | "--project" | "-p" => {
                args.get(index + 1)?;
                index += 2;
            }
            "--json" | "--quiet" | "-q" | "--no-color" => index += 1,
            "--" => return args.get(index + 1).map(|_| index + 1),
            value
                if value.starts_with("--home=")
                    || value.starts_with("--project=")
                    || (value.starts_with("-p") && value.len() > 2) =>
            {
                index += 1
            }
            value if value.starts_with('-') => return None,
            _ => return Some(index),
        }
    }
    None
}
