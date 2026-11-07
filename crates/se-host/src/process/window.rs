//! Resolve terminal presentation before reserving or starting any native work.
use super::*;
use se_core::ops::agent_launch::LaunchPlan;
#[cfg(target_os = "linux")]
use se_proc::TerminalAdapter;
use se_proc::WindowSpec;

pub(super) fn select(plan: &LaunchPlan, configuration: &ConfigFile) -> Result<Option<WindowSpec>> {
    if plan.input.detach {
        return Ok(None);
    }
    #[cfg(windows)]
    if plan.profile.provider == se_store::Provider::Codex {
        return Err(se_types::SeError::new(
            se_types::Detail::ProviderIncompatible(se_types::details::ProviderIncompatible {
                subject: "codex".into(),
                reason: "this build cannot open an attended Codex window on Windows".into(),
                next_step:
                    "For an attended Windows console, initialize a project with Claude Code.".into(),
            }),
        ));
    }
    #[cfg(windows)]
    {
        let _ = configuration;
        Ok(Some(WindowSpec::WindowsConsole))
    }
    #[cfg(target_os = "linux")]
    {
        let command = if configuration.launch.terminal.is_empty() {
            "xterm"
        } else {
            &configuration.launch.terminal
        };
        let executable = super::launch_util::resolve_command(command)
            .map_err(|e| unavailable(vec![e.to_string()]))?;
        if !executable.file_name().is_some_and(|name| name == "xterm") {
            return Err(unavailable(vec![format!(
                "{} has no qualified PTY adapter; select xterm",
                executable.display()
            )]));
        }
        if std::env::var_os("DISPLAY").is_none_or(|value| value.is_empty()) {
            return Err(unavailable(vec![
                "xterm requires the logged-in desktop's DISPLAY".into(),
            ]));
        }
        Ok(Some(
            if plan.profile.provider == se_store::Provider::Codex {
                WindowSpec::UnixTerminalWithBackend {
                    executable,
                    adapter: TerminalAdapter::Xterm,
                }
            } else {
                WindowSpec::UnixTerminal {
                    executable,
                    adapter: TerminalAdapter::Xterm,
                }
            },
        ))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = configuration;
        Err(unavailable(vec![
            "no qualified native terminal adapter on this platform".into(),
        ]))
    }
}
#[cfg(not(windows))]
fn unavailable(tried: Vec<String>) -> se_types::SeError {
    se_types::SeError::new(se_types::Detail::WindowUnavailable(
        se_types::details::WindowUnavailable { tried },
    ))
}
