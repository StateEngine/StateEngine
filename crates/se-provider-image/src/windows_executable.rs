//! Package launchers are scripts on Windows. Resolve the provider's packaged
//! native image so version probes and owned launches use the same executable.
use se_types::Provider;
use std::{
    fs, io,
    io::Read,
    path::{Component, Path, PathBuf},
};

enum PackageImage {
    Vendor,
    DeclaredBin,
}

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
    let native = se_proc::file_access::with_readable_regular_file(path, |input| {
        match input.read_exact(&mut header) {
            Ok(()) => Ok(header == *b"MZ"),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
            Err(error) => Err(error),
        }
    })?;
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
    #[cfg(windows)]
    if native {
        se_proc::file_access::require_executable_access(path)?;
    }
    Ok(native)
}

pub(crate) fn resolve(path: &Path, provider: Option<Provider>) -> io::Result<Option<PathBuf>> {
    resolve_package(path, provider).map(|value| value.map(|(image, _)| image))
}

pub(crate) fn resolve_package(
    path: &Path,
    provider: Option<Provider>,
) -> io::Result<Option<(PathBuf, Option<PathBuf>)>> {
    if path.extension().is_none() {
        let candidate = path.with_extension("exe");
        if native_image(&candidate)? {
            return Ok(Some((candidate, None)));
        }
    }
    if native_image(path)? {
        return Ok(Some((path.to_path_buf(), None)));
    }
    let (command, package_name, title, layout) = match provider {
        Some(Provider::Codex) => ("codex", "@openai/codex", "Codex", PackageImage::Vendor),
        Some(Provider::Claude) => (
            "claude",
            "@anthropic-ai/claude-code",
            "Claude",
            PackageImage::DeclaredBin,
        ),
        _ => return Ok(None),
    };
    if !path
        .file_stem()
        .is_some_and(|name| name.eq_ignore_ascii_case(command))
    {
        return Ok(None);
    }
    let mut launcher = file(path)?;
    if path.extension().is_none() {
        for extension in ["cmd", "bat", "ps1"] {
            launcher |= file(&path.with_extension(extension))?;
        }
    }
    if !launcher {
        return Ok(None);
    }
    let Some(prefix) = path.parent() else {
        return Ok(None);
    };
    let Some(package) = crate::package_roots::unique_installed_root(prefix, package_name)? else {
        return Ok(None);
    };
    let manifest = package.join("package.json");
    let bytes = se_proc::file_access::read_bounded_regular_file(&manifest, 65536)?;
    let metadata: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if metadata.get("name").and_then(serde_json::Value::as_str) != Some(package_name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{title} package identity differs"),
        ));
    }
    let image = match layout {
        PackageImage::Vendor => codex_image(&package)?,
        PackageImage::DeclaredBin => declared_image(&package, command, &metadata)?,
    };
    Ok(image.map(|image| (image, Some(package))))
}

fn declared_image(
    package: &Path,
    command: &str,
    metadata: &serde_json::Value,
) -> io::Result<Option<PathBuf>> {
    let Some(entry) = metadata
        .get("bin")
        .and_then(|bin| bin.as_str().or_else(|| bin.get(command)?.as_str()))
    else {
        return Ok(None);
    };
    let entry = Path::new(entry);
    if entry.components().any(|component| {
        matches!(
            component,
            Component::Prefix(_) | Component::RootDir | Component::ParentDir
        )
    }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "installed provider command must be relative to its package",
        ));
    }
    if !entry
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
    {
        return Ok(None);
    }
    let root = fs::canonicalize(package)?;
    let image = match fs::canonicalize(root.join(entry)) {
        Ok(path) => path,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !image.starts_with(&root) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "installed provider command escapes its package",
        ));
    }
    if native_image(&image)? {
        return se_proc::canonicalize_path(image).map(Some);
    }
    Ok(None)
}

fn codex_image(package: &Path) -> io::Result<Option<PathBuf>> {
    let (platform, target) = if cfg!(target_arch = "x86_64") {
        ("codex-win32-x64", "x86_64-pc-windows-msvc")
    } else if cfg!(target_arch = "aarch64") {
        ("codex-win32-arm64", "aarch64-pc-windows-msvc")
    } else {
        return Ok(None);
    };
    let mut vendors = vec![
        package
            .join("node_modules/@openai")
            .join(platform)
            .join("vendor"),
    ];
    if let Some(scope) = package.parent() {
        vendors.push(scope.join(platform).join("vendor"));
    }
    vendors.push(package.join("vendor"));
    for vendor in vendors {
        let candidate = vendor.join(target).join("bin/codex.exe");
        if native_image(&candidate)? {
            #[cfg(windows)]
            let candidate = se_proc::canonicalize_path(&candidate)?;
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}
