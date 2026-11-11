//! Resolve the installed Codex package entry to its native payload before
//! qualification and owned launch. Other scripts keep their stable parent.
use std::{
    fs, io,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

pub(super) fn packaged_codex(launcher: &Path) -> io::Result<Option<PathBuf>> {
    let entry = fs::canonicalize(launcher)?;
    if entry.file_name().is_none_or(|name| name != "codex.js") {
        return Ok(None);
    }
    let Some(bin) = entry
        .parent()
        .filter(|bin| bin.file_name().is_some_and(|name| name == "bin"))
    else {
        return Ok(None);
    };
    let Some(package) = bin.parent() else {
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
            return fs::canonicalize(candidate).map(Some);
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

fn native_image(path: &Path) -> io::Result<bool> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
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
