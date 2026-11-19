//! Disposable real-consumer probe; the provider refuses after native preparation.
#![cfg(windows)]
#[path = "../../test-support/directory.rs"]
mod directory;
#[test]
fn managed_launch_qualifies_and_pins_private_profile() -> Result<(), Box<dyn std::error::Error>> {
    let root = directory::private_case_directory()?;
    let result = (|| {
        let output = std::process::Command::new("python")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/judges/windows_profile_qualification_probe.py"
            ))
            .arg("--se")
            .arg(env!("CARGO_BIN_EXE_se"))
            .arg("--source")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/support/windows_profile_fixture.rs"
            ))
            .arg("--capabilities")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/judges/secode_headless_capabilities.json"
            ))
            .arg("--root")
            .arg(root.as_ref())
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "fixture probe failed: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    })();
    root.finish(result)
}
