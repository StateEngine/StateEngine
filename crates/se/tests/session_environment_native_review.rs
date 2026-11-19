//! Native provider launch controls. The fixture emits only credential-presence flags.
use std::process::Command;

fn judge(case: &str) -> Result<(), Box<dyn std::error::Error>> {
    let python = if cfg!(windows) { "python" } else { "python3" };
    let output = Command::new(python)
        .arg("-B")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/judges/session_environment_review.py"
        ))
        .arg(case)
        .arg(env!("CARGO_BIN_EXE_se"))
        .output()?;
    assert!(
        output.status.success(),
        "native launch judge {case}: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    Ok(())
}

#[test]
fn acp_child_has_only_the_public_session_handle() -> Result<(), Box<dyn std::error::Error>> {
    judge("acp-environment")
}

#[test]
fn acp_child_calls_se_using_the_public_session_handle() -> Result<(), Box<dyn std::error::Error>> {
    judge("acp-consumer")
}

#[test]
fn codex_with_atlas_hooks_launches_with_one_session_entry() -> Result<(), Box<dyn std::error::Error>>
{
    judge("codex")
}
