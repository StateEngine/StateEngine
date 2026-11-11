//! Resolve the provider's standard npm launcher to its native package image.
//! The selected native executable still undergoes version and ancestry proof.
use super::*;
pub fn resolve(command: &Path) -> Result<std::path::PathBuf> {
    let path = se_proc::canonicalize_path(command).map_err(io)?;
    if path.file_name().is_none_or(|name| name != "codex.js") {
        return Ok(command.to_owned());
    }
    let Some(package) = path.parent().and_then(Path::parent) else {
        return Err(invalid("the native Codex package executable"));
    };
    let mut bytes = Vec::new();
    std::fs::File::open(package.join("package.json"))
        .map_err(io)?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    let manifest: Value = crate::client::wire::decode_json(&bytes, 65536)?;
    if manifest.get("name").and_then(Value::as_str) != Some("@openai/codex") {
        return Err(invalid("the Codex package identity"));
    }
    let (platform, target) = if cfg!(target_arch = "x86_64") {
        ("codex-linux-x64", "x86_64-unknown-linux-musl")
    } else if cfg!(target_arch = "aarch64") {
        ("codex-linux-arm64", "aarch64-unknown-linux-musl")
    } else {
        return Err(invalid("a supported native Codex architecture"));
    };
    let sibling = package
        .parent()
        .ok_or_else(|| invalid("the Codex package directory"))?;
    for vendor in [
        package
            .join("node_modules/@openai")
            .join(platform)
            .join("vendor"),
        sibling.join(platform).join("vendor"),
        package.join("vendor"),
    ] {
        let native = vendor.join(target).join("bin/codex");
        let mut file = match std::fs::File::open(&native) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(io(e)),
        };
        let mut header = [0; 4];
        file.read_exact(&mut header).map_err(io)?;
        if header != *b"\x7fELF" {
            return Err(invalid("a native Codex package image"));
        }
        return Ok(native);
    }
    Err(invalid(
        "the installed native Codex optional package; repair the Codex installation and retry se init --adopt --provider codex",
    ))
}
