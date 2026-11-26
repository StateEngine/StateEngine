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
    inherited: Option<&str>,
) -> Result<Vec<OsString>> {
    let mut command = vec![
        program.clone(),
        "__install-hold".into(),
        "--prepare-program".into(),
        "--home".into(),
        home.as_os_str().to_os_string(),
    ];
    if !no_modify_path
        && std::env::var_os("SHELL").is_some_and(|shell| {
            std::path::Path::new(&shell)
                .file_name()
                .is_some_and(|name| name == "fish")
        })
    {
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
    if let Some(inherited) = inherited {
        command.push("--inherit-path-edits".into());
        command.push(inherited.into());
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
    let mut no_modify_path = if arguments.len() == 4 {
        if arguments[3] != std::ffi::OsStr::new("--no-modify-path") {
            return Err(args::invalid(USAGE));
        }
        true
    } else {
        false
    };
    if !no_modify_path && load_replace_custody(&home)?.is_some_and(|custody| custody.no_modify_path)
    {
        no_modify_path = true;
    }
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
    let (_lease, inherited) = crate::runtime::remove_for_reinstall(
        &context,
        &claim,
        &image,
        no_modify_path,
        &mut diagnostic,
    )?;
    #[cfg(unix)]
    {
        let command = unix_command(
            &arguments[0],
            &home,
            archive,
            no_modify_path,
            inherited.as_deref(),
        )?;
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
        if let Some(inherited) = &inherited {
            child_args.push("-InheritPathEdits".into());
            child_args.push(inherited.into());
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

fn load_replace_custody(home: &std::path::Path) -> Result<Option<crate::runtime::ReplaceCustody>> {
    se_proc::NativeStateFiles::open(home).map_err(native)?;
    let path = home.join("standalone-install.replace.json");
    let Some(mut file) = se_proc::OwnedFile::open(&path).map_err(native)? else {
        return Ok(None);
    };
    let bytes = file.read(1024 * 1024).map_err(native)?;
    let custody: crate::runtime::ReplaceCustody = serde_json::from_slice(&bytes)
        .map_err(|e| args::invalid("a valid replacement custody record").with_cause(e))?;
    if custody.schema != "stateengine-install-replace/v1"
        || custody.owner != crate::route::owner::observe(&[])?.os_owner()
    {
        return Err(args::invalid("the native-owned replacement custody record"));
    }
    Ok(Some(custody))
}

fn validate_inherited_directories(custody: &crate::runtime::ReplaceCustody) -> Result<&[String]> {
    let mut seen = Vec::<&str>::new();
    for dir in &custody.inherited_directories {
        let path = std::path::Path::new(dir);
        if dir.is_empty()
            || !path.is_absolute()
            || seen.contains(&dir.as_str())
            || !custody
                .inherited_files
                .iter()
                .any(|file| std::path::Path::new(&file.path).starts_with(path))
        {
            return Err(args::invalid(
                "unique absolute ancestor directories of inherited files",
            ));
        }
        seen.push(dir.as_str());
    }
    Ok(&custody.inherited_directories)
}

/// Read and natively validate any durable replacement custody left by a
/// `--no-modify-path` replacement before the child installer wrote its journal.
pub fn read_replace_custody(arguments: &[OsString]) -> Result<i32> {
    if arguments.len() != 3 {
        return Err(args::invalid(
            "__install-replace-custody <selected data home>",
        ));
    }
    let home = args::path(&arguments[2])?;
    if home != crate::bootstrap::state_home(None)? {
        return Err(args::invalid("the selected platform data home"));
    }
    let Some(custody) = load_replace_custody(&home)? else {
        return Ok(0);
    };
    let mut seen_bases = Vec::<&str>::new();
    for edit in &custody.inherited_path_edits {
        #[cfg(windows)]
        {
            if edit.target != r"HKCU\Environment\Path" || !seen_bases.is_empty() {
                return Err(args::invalid("the original registry PATH target"));
            }
            seen_bases.push(r"HKCU\Environment\Path");
        }
        #[cfg(not(windows))]
        {
            let base = std::path::Path::new(&edit.target)
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| args::invalid("inherited profile paths"))?;
            if !matches!(
                base,
                ".profile" | ".bash_profile" | ".bash_login" | ".zprofile" | ".bashrc" | ".zshrc"
            ) || seen_bases.contains(&base)
            {
                return Err(args::invalid("unique inherited login profiles"));
            }
            seen_bases.push(base);
        }
    }
    let mut fish_path = String::new();
    let mut fish_sha = String::new();
    if custody.inherited_files.len() > 1 {
        return Err(args::invalid("at most one inherited Fish PATH file"));
    }
    if let Some(entry) = custody.inherited_files.first() {
        if !se_core::ops::installation::is_fish_path_file(&entry.path) {
            return Err(args::invalid("an inherited Fish PATH file"));
        }
        let mut owned = se_proc::OwnedFile::open(std::path::Path::new(&entry.path))
            .map_err(native)?
            .ok_or_else(|| args::invalid("the preserved Fish PATH file on disk"))?;
        let actual = se_types::Sha256::from_bytes(owned.sha256().map_err(native)?);
        if actual.hex() != entry.sha256 {
            return Err(args::invalid("unchanged preserved Fish PATH file"));
        }
        fish_path = entry.path.clone();
        fish_sha = entry.sha256.clone();
    }
    let dirs = validate_inherited_directories(&custody)?;
    let edits_json = if custody.inherited_path_edits.is_empty() {
        String::new()
    } else {
        serde_json::to_string(&custody.inherited_path_edits)
            .map_err(|e| se_core::scope::unreadable("inherited PATH custody", &e.to_string()))?
    };
    println!(
        "{}\n{}\n{}\n{}",
        if custody.no_modify_path { 1 } else { 0 },
        edits_json,
        fish_path,
        fish_sha
    );
    for dir in dirs {
        println!("{dir}");
    }
    Ok(0)
}
