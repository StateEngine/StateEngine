use super::*;

#[cfg(windows)]
fn counters(mode: &str) -> Observed<Value> {
    let result = std::process::Command::new("python")
        .args([
            "-I",
            "-c",
            include_str!("native.py"),
            mode,
            &std::process::id().to_string(),
        ])
        .output()?;
    if !result.status.success() {
        return Err(format!(
            "native Windows counters: {}: {}",
            result.status,
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&result.stdout)?)
}

pub fn memory() -> Observed<Value> {
    #[cfg(windows)]
    return counters("memory");
    #[cfg(not(windows))]
    Ok(Value::Null)
}

pub fn load() -> Observed<Value> {
    #[cfg(windows)]
    return counters("load");
    #[cfg(not(windows))]
    Ok(Value::Null)
}

pub fn commit() -> Observed<Value> {
    #[cfg(windows)]
    return Ok(json!(se_proc::atlas_worker::memory_usage()?.0));
    #[cfg(not(windows))]
    Ok(Value::Null)
}
