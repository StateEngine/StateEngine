//! Shell choice belongs at the CLI adapter; literal argv remains portable.
use se_core::ops::{AgentCommand, NextStep};
pub(super) fn next(command: AgentCommand, text: &str) -> NextStep {
    #[cfg(windows)]
    {
        let image = match se_proc::parent_process_image() {
            Ok(image) => image,
            Err(error) => {
                return NextStep {
                    text: format!(
                        "Shell could not be detected ({error}); open PowerShell, then {}",
                        text.to_lowercase()
                    ),
                    command: command.command,
                    argv: command.argv,
                };
            }
        };
        let shell = image
            .as_ref()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .map(str::to_ascii_lowercase);
        if shell.as_deref() == Some("cmd.exe") {
            if let Some(command) = command.for_cmd() {
                return NextStep {
                    text: format!("In cmd.exe, {}", text.to_lowercase()),
                    command: command.command,
                    argv: command.argv,
                };
            }
        } else if matches!(shell.as_deref(), Some("powershell.exe" | "pwsh.exe")) {
            return NextStep {
                text: format!("In PowerShell, {}", text.to_lowercase()),
                command: command.command,
                argv: command.argv,
            };
        }
        // An unobserved shell is not assumed to understand PowerShell syntax.
        // The named alternative is safe even for cmd variable-expansion bytes.
    }
    NextStep {
        text: AgentCommand::instruction(text),
        command: command.command,
        argv: command.argv,
    }
}
