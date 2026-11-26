//! Recover through a current archive, never by running an incompatible old image.
use super::{args, manifest, native};
use se_types::Result;
use std::ffi::OsString;

#[cfg(unix)]
fn unix_command(
    program: &OsString,
    home: &std::path::Path,
    archive: &std::path::Path,
    no_modify_path: bool,
) -> Result<Vec<OsString>> {
    let mut command = vec![
        program.clone(),
        "__install-hold".into(),
        "--prepare-program".into(),
        "--home".into(),
        home.as_os_str().to_os_string(),
    ];
    if std::env::var_os("SHELL").is_some_and(|shell| {
        std::path::Path::new(&shell)
            .file_name()
            .is_some_and(|name| name == "fish")
    }) {
        let config = match std::env::var_os("XDG_CONFIG_HOME") {
            Some(value) => args::path(&value)?,
            None => args::path(&std::env::var_os("HOME").ok_or_else(|| args::invalid("HOME"))?)?
                .join(".config"),
        };
        command.extend([
            "--fish-directory".into(),
            config.join("fish/conf.d").into_os_string(),
        ]);
    }
    command.extend([
        "--".into(),
        "/bin/sh".into(),
        archive.join("install.sh").into_os_string(),
        "--native-held".into(),
    ]);
    if no_modify_path {
        command.push("--no-modify-path".into());
    }
    Ok(command)
}

pub fn replace_installation(arguments: &[OsString]) -> Result<i32> {
    const USAGE: &str = "__install-replace <selected data home> [--no-modify-path]";
    if !(3..=4).contains(&arguments.len()) {
        return Err(args::invalid(USAGE));
    }
    let home = args::path(&arguments[2])?;
    if home != crate::bootstrap::state_home(None)? {
        return Err(args::invalid("the selected platform data home"));
    }
    #[cfg(any(unix, windows))]
    let no_modify_path = if arguments.len() == 4 {
        if arguments[3] != std::ffi::OsStr::new("--no-modify-path") {
            return Err(args::invalid(USAGE));
        }
        true
    } else {
        false
    };
    // Verify the replacement before removal. This does not prepare directories
    // or open a writer/migrate the retained database.
    manifest::verify()?;
    let archive = std::env::current_exe()
        .map_err(|error| se_core::scope::unreadable("current archive image", &error.to_string()))?;
    let archive = archive
        .parent()
        .ok_or_else(|| args::invalid("an archive directory"))?;
    let operation = se_core::ops::AnyOp::Uninstall(se_core::ops::Uninstall {
        idempotency_key: se_types::IdempotencyKey::new(uuid::Uuid::new_v4().to_string())?,
        yes: false,
    });
    crate::bootstrap::check_session_route(&operation)?;
    let context =
        crate::bootstrap::Bootstrap::resolve(Some(home.clone()), None, false, false, &operation)?;
    let claim = se_proc::NativeInstallationClaim::acquire().map_err(native)?;
    let (bin, _) = manifest::program_paths()?;
    let image = bin.join(if cfg!(windows) { "se.exe" } else { "se" });
    // The complete native inventory must be closed; unlike ordinary uninstall,
    // replacement never stops a live runtime. Both claims stay held while the
    // existing fresh-install journal publishes the new archive.
    let mut diagnostic = |text: &str| {
        use std::io::Write;
        let mut stderr = std::io::stderr().lock();
        stderr.write_all(text.as_bytes())?;
        stderr.flush()
    };
    let _lease = crate::runtime::remove_for_reinstall(&context, &claim, &image, &mut diagnostic)?;
    #[cfg(unix)]
    {
        let command = unix_command(&arguments[0], &home, archive, no_modify_path)?;
        super::run_claimed(&command, &claim)
    }
    #[cfg(windows)]
    {
        let windows =
            args::path(&std::env::var_os("WINDIR").ok_or_else(|| args::invalid("WINDIR"))?)?;
        let powershell = windows.join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let mut child_args: Vec<OsString> = vec![
            "-NoProfile".into(),
            "-ExecutionPolicy".into(),
            "Bypass".into(),
            "-File".into(),
            archive.join("install.ps1").into_os_string(),
        ];
        if no_modify_path {
            child_args.push("-NoModifyPath".into());
        }
        claim
            .run_child(powershell.as_os_str(), &child_args)
            .map_err(native)
    }
    #[cfg(not(any(unix, windows)))]
    Err(se_types::SeError::invalid(
        "installation replacement",
        "a supported native platform",
    ))
}
