//! Native Codex hooks retain provider policy, history and user-owned processes.
use super::*;
use serde_json::{Value, json};
mod queue;
mod rpc;
mod trust;
pub use queue::offer;
pub use trust::install as trust;
#[cfg(not(target_os = "linux"))]
pub fn native_executable(command: &Path) -> Result<std::path::PathBuf> {
    Ok(command.to_owned())
}

fn run<T: Send + 'static>(
    work: impl std::future::Future<Output = Result<T>> + Send + 'static,
) -> Result<T> {
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(io)?
            .block_on(work)
    })
    .join()
    .map_err(|_| invalid("a completed native Codex helper"))?
}

pub fn qualify(command: &Path) -> Result<()> {
    let command = command.to_owned();
    run(async move {
        let version =
            crate::harness::codex_rpc::probe::probe(&command, std::time::Duration::from_secs(5))
                .await?;
        let parts = version
            .version
            .split('.')
            .map(str::parse::<u16>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| invalid("a stable supported Codex version"))?;
        if parts.as_slice() < [0, 166, 0].as_slice() {
            return Err(invalid(
                "Codex 0.166.0 or newer; update Codex and repeat se init --adopt --provider codex",
            ));
        }
        Ok(())
    })
}

/// Constrain the native hook's path to the provider's history directory, then
/// require the pinned provider header to name this exact conversation and root.
pub fn transcript(registration: &Registration, input: &Input) -> Result<std::path::PathBuf> {
    crate::codex_capture::location(
        &input.transcript.to_local()?,
        &registration.config_home.to_local()?,
    )
}
pub fn current(registration: &Registration, input: &Input) -> Result<bool> {
    let path = transcript(registration, input)?;
    let Some(mut pin) = se_proc::NativeSourcePin::open(&path).map_err(native)? else {
        return Ok(false);
    };
    crate::codex_capture::validate_header(&mut pin, &input.conversation)?;
    let mut bytes = Vec::new();
    let mut offset = 0;
    loop {
        let remaining = crate::client::wire::MAX_FRAME_BYTES
            .saturating_add(1)
            .saturating_sub(bytes.len());
        let chunk = pin.read_at(offset, remaining.min(65536)).map_err(native)?;
        let end = chunk.bytes.iter().position(|b| *b == b'\n');
        bytes.extend_from_slice(&chunk.bytes[..end.unwrap_or(chunk.bytes.len())]);
        if bytes.len() > crate::client::wire::MAX_FRAME_BYTES {
            return Err(invalid("a bounded native Codex session header"));
        }
        if end.is_some() {
            break;
        }
        if chunk.end_of_file {
            return Err(invalid("a complete native Codex session header"));
        }
        offset = chunk.next_offset;
    }
    let row: Value =
        crate::client::wire::decode_json(&bytes, crate::client::wire::MAX_FRAME_BYTES)?;
    let cwd = row
        .get("payload")
        .and_then(|p| p.get("cwd"))
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("a native Codex working directory"))?;
    let same_root =
        se_proc::canonicalize_path(Path::new(cwd)).map_err(io)? == input.cwd.to_local()?;
    pin.validate_path(&path).map_err(native)?;
    Ok(same_root)
}

pub fn hooks(executable: &Path, home: &Path) -> Result<Vec<(String, Value)>> {
    let executable = executable
        .to_str()
        .ok_or_else(|| invalid("a Unicode hook executable"))?;
    let home = home
        .to_str()
        .ok_or_else(|| invalid("a Unicode adoption home"))?;
    let quoted = |text: &str| format!("'{}'", text.replace('\'', "'\\''"));
    let windows_quoted = |text: &str| {
        let mut quoted = String::from("'");
        for character in text.chars() {
            if matches!(character, '\'' | '\u{2018}'..='\u{201b}') {
                quoted.push(character);
            }
            quoted.push(character);
        }
        quoted.push('\'');
        quoted
    };
    let mut entries = Vec::new();
    // Provider hook timeouts are seconds. The mail hook waits for the session
    // lifetime; its individual queue RPC has a separate five-second budget.
    for (event, action, _) in super::settings::EVENTS {
        let command = format!(
            "{} __se-codex-adopt {} {action}",
            quoted(executable),
            quoted(home)
        );
        let command_windows = format!(
            "& {} '__se-codex-adopt' {} '{action}'",
            windows_quoted(executable),
            windows_quoted(home)
        );
        entries.push((event.into(), json!({"hooks":[{
            "type":"command", "command":command, "commandWindows":command_windows,
            "async": action != "end", "timeout": if action == "mail" { 2_000_000 } else if action == "end" { 2 } else { 30 }
        }]})));
    }
    Ok(entries)
}

/// Resolve the standard package launcher to its native executable.
/// Version qualification and native ancestry remain separate checks.
#[cfg(target_os = "linux")]
pub fn native_executable(command: &Path) -> Result<std::path::PathBuf> {
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
