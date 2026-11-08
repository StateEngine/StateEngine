//! Refuse before any account-wide product lock unless this native account was
//! registered by its administrator as a disposable test account.
pub fn require() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::process::Command::new(if cfg!(windows) { "python" } else { "python3" })
        .args([
            "-I",
            "-c",
            include_str!("../../../../scripts/ci/installation_account.py"),
            "check",
        ])
        .output()
        .map_err(|error| format!("account-wide installation fixture refused: Python is required to verify the dedicated OS test account: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "account-wide installation fixture refused: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}
