use std::{ffi::OsStr, process::Command};

/// A background command with caller-selected redirected or discarded streams.
/// Windows requests windowless creation directly, without show-window flags.
pub fn background_command(program: impl AsRef<OsStr>) -> Command {
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
