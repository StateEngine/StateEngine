//! Package launchers are scripts on Windows. Resolve the provider's packaged
//! native image so version probes and owned launches use the same executable.
use se_types::Provider;
use std::{
    fs, io,
    io::Read,
    path::{Path, PathBuf},
};

fn file(path: &Path) -> io::Result<bool> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.is_file()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn native_image(path: &Path) -> io::Result<bool> {
    if !file(path)? {
        return Ok(false);
    }
    let mut header = [0; 2];
    let mut input = fs::File::open(path)?;
    let native = match input.read_exact(&mut header) {
        Ok(()) => header == *b"MZ",
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => false,
        Err(error) => return Err(error),
    };
    if !native
        && path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} has no native Windows image header", path.display()),
        ));
    }
    Ok(native)
}

pub(super) fn resolve(path: &Path, provider: Option<Provider>) -> io::Result<Option<PathBuf>> {
    if path.extension().is_none() {
        let candidate = path.with_extension("exe");
        if native_image(&candidate)? {
            return Ok(Some(candidate));
        }
    }
    if native_image(path)? {
        return Ok(Some(path.to_path_buf()));
    }
    if provider != Some(Provider::Codex)
        || !path
            .file_stem()
            .is_some_and(|name| name.eq_ignore_ascii_case("codex"))
    {
        return Ok(None);
    }
    let mut launcher = file(path)?;
    if path.extension().is_none() {
        for extension in ["cmd", "ps1"] {
            launcher |= file(&path.with_extension(extension))?;
        }
    }
    if !launcher {
        return Ok(None);
    }
    let Some(prefix) = path.parent() else {
        return Ok(None);
    };
    let package = prefix.join("node_modules/@openai/codex");
    let manifest = package.join("package.json");
    if !file(&manifest)? {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    fs::File::open(&manifest)?
        .take(65537)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Codex package metadata exceeds 64 KiB",
        ));
    }
    let metadata: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if metadata.get("name").and_then(serde_json::Value::as_str) != Some("@openai/codex") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Codex package identity differs",
        ));
    }
    let (platform, target) = if cfg!(target_arch = "x86_64") {
        ("codex-win32-x64", "x86_64-pc-windows-msvc")
    } else if cfg!(target_arch = "aarch64") {
        ("codex-win32-arm64", "aarch64-pc-windows-msvc")
    } else {
        return Ok(None);
    };
    for vendor in [
        package
            .join("node_modules/@openai")
            .join(platform)
            .join("vendor"),
        prefix
            .join("node_modules/@openai")
            .join(platform)
            .join("vendor"),
        package.join("vendor"),
    ] {
        let candidate = vendor.join(target).join("bin/codex.exe");
        if native_image(&candidate)? {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}
