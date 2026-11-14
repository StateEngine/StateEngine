//! Execute a refusal's literal remedy without restoring discarded CLI context.
#![cfg(target_os = "linux")]
#[path = "../../test-support/directory.rs"]
mod directory;

fn run(mode: &str) -> Result<(), Box<dyn std::error::Error>> {
    let parent = directory::private_directory()?;
    let evidence = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/judge-diagnostics/launch-refusal-remedy")
        .join(mode);
    let output = std::process::Command::new("python3")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/judges/launch_refusal_remedy_review.py"
        ))
        .arg("--se")
        .arg(env!("CARGO_BIN_EXE_se"))
        .arg("--output")
        .arg(parent.join("fixture"))
        .arg("--evidence")
        .arg(evidence)
        .arg("--mode")
        .arg(mode)
        .output()?;
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn printed_force_command_runs_with_environment_selected_home()
-> Result<(), Box<dyn std::error::Error>> {
    run("environment")
}

#[test]
fn printed_force_command_preserves_explicit_home_without_environment_help()
-> Result<(), Box<dyn std::error::Error>> {
    run("explicit")
}
