//! Reviewer acceptance judge for one-shot temporary agents on a real host,
//! driven through the public CLI and MCP with a native provider double.
#![cfg(target_os = "linux")]
#[path = "../../test-support/directory.rs"]
mod directory;

type Check = Result<(), Box<dyn std::error::Error>>;

fn run_case(case: &str) -> Check {
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
        .arg("--case")
        .arg(case)
        .output()?;
    assert!(
        output.status.success(),
        "delegation acceptance judge ({case}) failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

/// Protects: owner delegation through the public doors. A one-shot child
/// answers once and retires Completed with one atomic notice; same-key retries
/// return the original child; mail never starts a second turn; cancel and TTL
/// expiry keep their own retirement reasons; the cap holds under concurrent
/// starts; and a failed launch leaves no counted orphan.
#[test]
fn owner_delegated_temporary_agents_finish_once_and_keep_honest_outcomes() -> Check {
    run_case("owner")
}

/// Protects: agent delegation through the public doors. The allowlist gates
/// only delegation, never a saved child; a child cannot delegate again; and a
/// parent's end retires its running child ParentEnded with a matching notice.
#[test]
fn agent_delegated_temporary_agents_enforce_allowlist_depth_and_parent_end() -> Check {
    run_case("agent")
}

/// Protects: a capture-disabled delegation notice never claims verified capture.
#[test]
fn capture_disabled_delegated_temporary_agent_reports_unverified_capture() -> Check {
    run_case("capture-off")
}
