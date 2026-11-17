use std::{ffi::OsStr, process::Command};

/// A short-lived background probe with redirected or discarded streams.
///
/// Windows probes never allocate a console. Programs that run console tools
/// use `inherited_console_command` from a console-bearing host, or the managed
/// `LaunchMode::HeadlessConsole` launcher.
pub fn probe_command(program: impl AsRef<OsStr>) -> Command {
    let command = Command::new(program);
    #[cfg(windows)]
    let command = {
        use std::os::windows::process::CommandExt;
        let mut command = command;
        command.creation_flags(crate::LaunchMode::Headless.creation_flags());
        command
    };
    command
}

/// A background host helper that may start console children of its own.
///
/// Inherit the host's console rather than allocating another one. The native
/// runtime bootstrap supplies a hidden console even when its caller has none.
pub fn inherited_console_command(program: impl AsRef<OsStr>) -> std::io::Result<Command> {
    #[cfg(windows)]
    {
        // SAFETY: reads only the calling process's console code page.
        if unsafe { windows_sys::Win32::System::Console::GetConsoleCP() } == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "background helper has no console to inherit; ask the owner to run se down, then se up, and retry",
            ));
        }
    }
    Ok(Command::new(program))
}
