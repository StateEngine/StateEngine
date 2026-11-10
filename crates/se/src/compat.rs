//! Inert replacement hints for renamed commands. Never forwards arguments or opens state.
use se_types::{Detail, SeError, details};
use std::ffi::OsString;

/// Arguments exclude argv[0]. Unknown options remain the generated grammar's job.
pub fn refusal(args: &[OsString]) -> Option<SeError> {
    let command = command_start(args)?;
    let rest = &args[command..];
    let first = rest.first()?.to_str()?;
    let second = rest.get(1).and_then(|arg| arg.to_str());
    let pair = match (first, second) {
        ("init", Some("--status")) => Some("se status"),
        _ => None,
    };
    if let Some(replacement) = pair {
        return Some(renamed(&format!("{first} {}", second?), replacement));
    }
    let replacement = match first {
        "projects" => "se status --all",
        "floor-event" => "se history --event ID",
        "capture-status" | "context" => "se status",
        "working-state-show" => "se working-state",
        "working-state-set" => "se working-state set TEXT --expect REV",
        _ => return None,
    };
    Some(renamed(first, replacement))
}

fn renamed(old: &str, replacement: &str) -> SeError {
    SeError::new(Detail::Renamed(details::Renamed {
        old: old.into(),
        replacement: replacement.into(),
    }))
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
