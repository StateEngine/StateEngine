//! Resolve the installed Codex package entry to its native payload before
//! qualification and owned launch. Other scripts keep their stable parent.
use std::{
    fs, io,
    io::Read,
    path::{Path, PathBuf},
};

pub(crate) fn packaged_codex(launcher: &Path) -> io::Result<Option<(PathBuf, PathBuf)>> {
    let entry = fs::canonicalize(launcher)?;
    let package = if entry.file_name().is_some_and(|name| name == "codex.js") {
        let Some(bin) = entry
            .parent()
            .filter(|bin| bin.file_name().is_some_and(|name| name == "bin"))
        else {
            return Ok(None);
        };
        let Some(package) = bin.parent() else {
            return Ok(None);
        };
        package.to_path_buf()
    } else if launcher.file_name().is_some_and(|name| name == "codex")
        && let Some(directory) = launcher.parent()
        && let Some(package) = resolve_codex_dispatcher(directory, &entry)?
    {
        package
    } else {
        return Ok(None);
    };
    let metadata = match fs::File::open(package.join("package.json")) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    metadata.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Codex package metadata exceeds 64 KiB",
        ));
    }
    let metadata: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if metadata.get("name").and_then(serde_json::Value::as_str) != Some("@openai/codex") {
        return Ok(None);
    }
    let command = metadata.get("bin").and_then(|bin| {
        bin.as_str()
            .or_else(|| bin.get("codex").and_then(serde_json::Value::as_str))
    });
    if !matches!(command, Some("bin/codex.js" | "./bin/codex.js")) {
        return Ok(None);
    }
    let Some((platform, target)) = platform() else {
        return Ok(None);
    };
    let Some(scope) = package.parent() else {
        return Ok(None);
    };
    for vendor in [
        package
            .join("node_modules/@openai")
            .join(platform)
            .join("vendor"),
        scope.join(platform).join("vendor"),
        package.join("vendor"),
    ] {
        let candidate = vendor.join(target).join("bin/codex");
        if native_image(&candidate)? {
            return fs::canonicalize(candidate).map(|image| Some((image, package)));
        }
    }
    Ok(None)
}

fn platform() -> Option<(&'static str, &'static str)> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some(("codex-linux-x64", "x86_64-unknown-linux-musl")),
        ("linux", "aarch64") => Some(("codex-linux-arm64", "aarch64-unknown-linux-musl")),
        ("macos", "x86_64") => Some(("codex-darwin-x64", "x86_64-apple-darwin")),
        ("macos", "aarch64") => Some(("codex-darwin-arm64", "aarch64-apple-darwin")),
        _ => None,
    }
}

/// Resolve only known package-manager dispatchers before inspecting any
/// package manifests:
/// - Volta's `volta-shim` resolves only inside Volta's own `tools/image/packages`.
/// - A `#!` shell shim resolves only when a real `exec`/`node` command line
///   (ignoring `#` comments and diagnostic strings) directly executes a
///   `.../bin/codex.js` target.
///
/// Standalone binaries and independent user wrappers return `Ok(None)` without
/// scanning neighboring package directories.
fn resolve_codex_dispatcher(directory: &Path, canonical: &Path) -> io::Result<Option<PathBuf>> {
    if canonical
        .file_name()
        .is_some_and(|name| name == "volta-shim")
    {
        return resolve_volta_codex_root(directory);
    }
    let mut bytes = Vec::new();
    fs::File::open(canonical)?
        .take(8192)
        .read_to_end(&mut bytes)?;
    if !bytes.starts_with(b"#!") {
        return Ok(None);
    }
    let Ok(script) = std::str::from_utf8(&bytes) else {
        return Ok(None);
    };
    let Some(target_js) = parse_shim_codex_js_target(directory, script)? else {
        return Ok(None);
    };
    let Some(bin) = target_js
        .parent()
        .filter(|bin| bin.file_name().is_some_and(|name| name == "bin"))
    else {
        return Ok(None);
    };
    Ok(bin.parent().map(Path::to_path_buf))
}

fn resolve_volta_codex_root(directory: &Path) -> io::Result<Option<PathBuf>> {
    let volta_pkg = directory
        .parent()
        .unwrap_or(directory)
        .join("tools/image/packages/@openai/codex");
    let mut holding = Vec::new();
    for root in [
        volta_pkg.join("lib/node_modules/@openai/codex"),
        volta_pkg.join("node_modules/@openai/codex"),
    ] {
        if crate::package_roots::holds_package_manifest(&root)? {
            let canonical = se_proc::canonicalize_path(&root)?;
            if !holding.contains(&canonical) {
                holding.push(canonical);
            }
        }
    }
    match holding.as_slice() {
        [] => Ok(None),
        [root] => Ok(Some(root.clone())),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "several Volta installs beside {} hold @openai/codex; remove the extra installs, then retry",
                directory.display()
            ),
        )),
    }
}

fn parse_shim_codex_js_target(directory: &Path, script: &str) -> io::Result<Option<PathBuf>> {
    let mut found: Option<PathBuf> = None;
    for raw_line in script.lines().skip(1) {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let after_exec = match tokens.first().copied() {
            Some("exec") => &tokens[1..],
            _ => &tokens[..],
        };
        let Some(cmd) = after_exec.first().copied() else {
            continue;
        };
        let cmd_clean = cmd.trim_matches(|c| c == '"' || c == '\'');
        let is_node = cmd_clean == "node"
            || cmd_clean.ends_with("/node")
            || cmd_clean == "$node"
            || cmd_clean == "${node}";
        if !is_node {
            continue;
        }
        // Only recognize direct `node <codex.js> "$@"` dispatcher invocations
        // (no extra wrapper flags before the script path).
        let Some(arg) = after_exec.get(1).copied() else {
            continue;
        };
        let arg = arg.trim_matches(|c| c == '"' || c == '\'');
        if !arg.ends_with("/@openai/codex/bin/codex.js") {
            continue;
        }
        let candidate = if let Some(rel) = arg
            .strip_prefix("$basedir/")
            .or_else(|| arg.strip_prefix("${basedir}/"))
        {
            directory.join(rel)
        } else if Path::new(arg).is_absolute() {
            PathBuf::from(arg)
        } else {
            continue;
        };
        let canonical = match fs::canonicalize(&candidate) {
            Ok(path) => path,
            Err(error) if crate::package_roots::absent(&error) => continue,
            Err(error) => return Err(error),
        };
        if let Some(prev) = &found
            && prev != &canonical
        {
            return Ok(None);
        }
        found = Some(canonical);
    }
    Ok(found)
}

fn native_image(path: &Path) -> io::Result<bool> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() || se_proc::file_access::require_executable_access(path).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Codex package payload is not an executable file",
        ));
    }
    let mut header = [0; 4];
    fs::File::open(path)?.read_exact(&mut header)?;
    let native = if cfg!(target_os = "linux") {
        header == *b"\x7fELF"
    } else {
        matches!(
            header,
            [0xfe, 0xed, 0xfa, 0xce | 0xcf]
                | [0xce | 0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe | 0xbf]
                | [0xbe | 0xbf, 0xba, 0xfe, 0xca]
        )
    };
    if !native {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Codex package payload has no native image header",
        ));
    }
    Ok(true)
}
