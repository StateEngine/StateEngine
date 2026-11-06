#![cfg(target_os = "linux")]

/// Protects: bounded startup diagnostics keep their advertised log and preserve the refusal when protected cleanup fails.
#[test]
fn startup_refusals_retain_only_owned_logs_and_keep_cleanup_errors_visible() -> std::io::Result<()>
{
    let output = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/judges/startup_log_retention.py"
        ))
        .arg(env!("CARGO_BIN_EXE_se"))
        .output()?;
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
