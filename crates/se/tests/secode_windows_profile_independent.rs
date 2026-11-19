//! Native public launch regression with a finite provider and a disposable home.
#![cfg(windows)]
#[path = "../../test-support/directory.rs"]
mod directory;
#[path = "support/installation_account.rs"]
mod installation_account;
#[path = "support/installation_claim_guard.rs"]
mod installation_claim_guard;

#[test]
fn existing_windows_profile_refuses_before_initializer() -> Result<(), Box<dyn std::error::Error>> {
    installation_account::require()?;
    let _claim = installation_claim_guard::acquire()?;
    se_proc::initialize_file_creation_owner()?;
    let root = directory::private_case_directory()?;
    // The build output may have a second link. Use a single-link private copy.
    let image = root.join("se.exe");
    std::fs::copy(env!("CARGO_BIN_EXE_se"), &image)?;
    let output = std::process::Command::new("python")
        .arg("-B")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/judges/secode_windows_profile.py"
        ))
        .arg("--se")
        .arg(image)
        .arg("--output")
        .arg(root.join("judge"))
        .output()?;
    println!("{}", String::from_utf8_lossy(&output.stdout));
    assert!(
        output.status.success(),
        "Windows profile fixture retained at {}: {}",
        root.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    root.finish(Ok(()))
}
