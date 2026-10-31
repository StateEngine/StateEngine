//! Inert refusals for removed syntax. Never forwards arguments or opens state.
use se_types::{Detail, SeError, details};
use std::ffi::OsString;

/// Arguments exclude argv[0]. Unknown options remain the generated grammar's job.
pub fn refusal(args: &[OsString]) -> Option<SeError> {
    let command = command_start(args)?;
    let rest = &args[command..];
    let first = rest.first()?.to_str()?;
    let second = rest.get(1).and_then(|arg| arg.to_str());
    if first == "launch" {
        return Some(SeError::new(Detail::FeatureUnavailable(
            details::FeatureUnavailable {
                subject: "agent launch".into(),
                reason: "launching agents isn't available in this build yet".into(),
                next_step: "Use se init to save a project and se status to inspect it.".into(),
            },
        )));
    }
    let pair = match (first, second) {
        ("seat", Some("create")) => Some("se agent add NAME"),
        ("seat", Some("launch")) => Some("se launch AGENT"),
        ("seat", Some("stop")) => Some("se stop AGENT"),
        ("seat", Some("wake")) => Some("se wake AGENT"),
        ("ratify", Some("all")) => {
            Some("se decision ratify ID (once per decision; no bulk approval)")
        }
        ("init", Some("--status")) => Some("se status"),
        ("init", Some("--remove")) => Some("se remove --project P"),
        (
            "msg",
            Some(
                "deliver" | "retry-delivery" | "recover-delivery" | "handoff" | "unread-ids"
                | "wake-backlog" | "turn-outcome" | "index-build",
            ),
        ) => Some("se doctor --fix"),
        _ => None,
    };
    if let Some(replacement) = pair {
        return Some(renamed(&format!("{first} {}", second?), replacement));
    }
    let replacement = match first {
        "agents" => "se agent list",
        "projects" => "se status --all",
        "decision" if only_presentation_flags(&rest[1..]) => "se decision list",
        "decisions" => "se decision list",
        "pending" => "se decision list --pending",
        "agent-rename" => "se agent rename AGENT NAME",
        "launch" if only_presentation_flags(&rest[1..]) => "se up",
        "stop" if only_presentation_flags(&rest[1..]) => "se down",
        "wake" if only_presentation_flags(&rest[1..]) => "se wake AGENT",
        "ratify" => "se decision ratify ID",
        "ratifyall" => "se decision ratify ID (once per decision; no bulk approval)",
        "reject" => "se decision reject ID",
        "retract" => "se decision retract ID",
        "reverse" => "se decision supersede ID WITH_ID",
        "rawlog-search" => "se search QUERY",
        "floor-event" => "se history --event ID",
        "capture-status" | "context" => "se status",
        "working-state-show" => "se working-state",
        "working-state-set" | "seat-continuity-write" => "se working-state set TEXT --expect REV",
        "packet" => "se resume --preview AGENT",
        "decommission" => "se remove --project P",
        "plugin" | "hook-install" | "hook-uninstall" => {
            "se doctor --fix (repair setup); se status (inspect); se remove (remove with project)"
        }
        "verify-chain" => "se doctor",
        "hook-emit" | "capture-turn" => "se doctor --fix",
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
            "Use se launch AGENT and se stop AGENT for managed agents",
            first == "process",
        ),
        ("backup", _) => (
            "backups are automatic",
            "Use se restore for owner recovery",
            false,
        ),
        ("rebuild-index", _) => (
            "alpha has no projection replay command",
            "Use owner-human se restore on projection disagreement",
            false,
        ),
        ("agent", Some("alias")) | ("agent-alias" | "stateengine_agent_alias", _) => (
            "new aliases are no longer supported",
            "Use stable IDs or se agent rename AGENT NAME",
            first == "agent",
        ),
        ("msg", Some("complete" | "reconcile" | "treat")) => (
            "mail uses recipient read and dismiss markers",
            "Use se msg read ID or se msg dismiss ID as the recipient",
            true,
        ),
        ("seat", Some("cut" | "move" | "prompt")) => (
            "seat plumbing is no longer a product operation",
            "Use se launch AGENT, se stop AGENT or se resume",
            true,
        ),
        ("doctor", Some("contradictions")) => (
            "contradiction machinery was removed",
            "Use se doctor to inspect setup",
            true,
        ),
        ("mail-tunnel" | "stateengine_mail_tunnel", _) => (
            "native notifications replaced mail tunnels",
            "Use se doctor --fix to repair integration",
            false,
        ),
        ("memories" | "stateengine_memory_suggest", _) => (
            "memories are no longer a separate store",
            "Use se decision list; imported memories are decisions",
            false,
        ),
        (name, _) if name.starts_with("memory-") => (
            "memories are no longer a separate store",
            "Use se decision list; imported memories are decisions",
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
            "Use se status, se history or se doctor; use se up to start the runtime",
            false,
        ),
        (name, _) if name.starts_with("substrate-") || name.starts_with("brick") => (
            "legacy substrate plumbing was removed",
            "Use se status or se doctor",
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
