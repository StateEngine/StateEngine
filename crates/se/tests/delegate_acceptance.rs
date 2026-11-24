//! Reviewer acceptance judge for one-shot temporary agents on a real host,
//! driven through the public CLI and MCP with a native provider double.
#![cfg(target_os = "linux")]
#[path = "../../test-support/directory.rs"]
mod directory;

type Check = Result<(), Box<dyn std::error::Error>>;

/// Protects: owner and agent delegation through the public doors. A one-shot
/// child answers once and retires Completed with one atomic notice; same-key
/// retries return the original child; mail never starts a second turn; cancel,
/// TTL expiry and a parent's end keep their own retirement reasons; the cap
/// holds under concurrent starts; a failed launch leaves no counted orphan;
/// the allowlist gates only delegation, never a saved child; a child cannot
/// delegate again; and a capture-disabled notice never claims verified capture.
#[test]
fn delegated_temporary_agents_finish_once_and_keep_honest_outcomes() -> Check {
    let parent = directory::private_directory()?;
    let output = std::process::Command::new("python3")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/judges/delegate_acceptance.py"
        ))
        .arg("--se")
        .arg(env!("CARGO_BIN_EXE_se"))
        .arg("--output")
        .arg(parent.join("output"))
        .output()?;
    assert!(
        output.status.success(),
        "delegation acceptance judge failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
