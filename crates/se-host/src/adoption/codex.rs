//! Native Codex hooks retain provider policy, history and user-owned processes.
use super::*;
use serde_json::{Value, json};
#[cfg(target_os = "linux")]
mod executable;
mod queue;
mod rpc;
mod trust;
#[cfg(target_os = "linux")]
pub use executable::resolve as native_executable;
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
    let windows_quoted = |text: &str| format!("'{}'", text.replace('\'', "''"));
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
