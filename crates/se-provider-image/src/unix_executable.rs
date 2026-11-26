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
        && let Some(package) =
            crate::package_roots::unique_installed_root(directory, "@openai/codex")?
        && dispatcher_binds_package(directory, &entry, &package)?
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

/// Bind package resolution strictly to the selected launcher:
/// - Volta's `volta-shim` only resolves packages inside Volta's own `tools/image/packages`.
/// - A `#!` shell shim only resolves `package` when its script body explicitly
///   dispatches to that exact `package/bin/codex.js`.
///
/// Independent user wrappers and standalone binaries stay untouched.
fn dispatcher_binds_package(
    directory: &Path,
    canonical: &Path,
    package: &Path,
) -> io::Result<bool> {
    if canonical
        .file_name()
        .is_some_and(|name| name == "volta-shim")
    {
        let volta_pkg = directory
            .parent()
            .unwrap_or(directory)
            .join("tools/image/packages/@openai/codex");
        return Ok(fs::canonicalize(volta_pkg)
            .ok()
            .is_some_and(|root| package.starts_with(root)));
    }
    let mut bytes = Vec::new();
    fs::File::open(canonical)?
        .take(8192)
        .read_to_end(&mut bytes)?;
    if !bytes.starts_with(b"#!") {
        return Ok(false);
    }
    let Ok(script) = std::str::from_utf8(&bytes) else {
        return Ok(false);
    };
    if !script.contains("@openai/codex/bin/codex.js") {
        return Ok(false);
    }
    let target_js = match fs::canonicalize(package.join("bin/codex.js")) {
        Ok(path) => path,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if let Some(exact) = target_js.to_str()
        && script.contains(exact)
    {
        return Ok(true);
    }
    let canon_dir = fs::canonicalize(directory)?;
    if let Ok(rel) = target_js.strip_prefix(&canon_dir)
        && let Some(rel) = rel.to_str()
        && (script.contains(&format!("$basedir/{rel}"))
            || script.contains(&format!("${{basedir}}/{rel}")))
    {
        return Ok(true);
    }
    if let Some(parent) = canon_dir.parent()
        && let Ok(rel) = target_js.strip_prefix(parent)
        && let Some(rel) = rel.to_str()
        && (script.contains(&format!("$basedir/../{rel}"))
            || script.contains(&format!("${{basedir}}/../{rel}")))
    {
        return Ok(true);
    }
    Ok(false)
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
