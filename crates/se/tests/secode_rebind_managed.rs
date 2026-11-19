//! Real managed launch with a native contract service and a private test home.
#![cfg(target_os = "linux")]
#[path = "../../test-support/directory.rs"]
mod directory;

#[test]
fn managed_service_restart_reoffers_uncertain_mail_after_possession_proof()
-> Result<(), Box<dyn std::error::Error>> {
    let root = directory::private_case_directory()?;
    let source = std::path::Path::new(env!("CARGO_BIN_EXE_se"));
    let image = if source.metadata()?.len() > 512 * 1024 * 1024 {
        let image = root.join("se");
        std::fs::copy(source, &image)?;
        let stripped = std::process::Command::new("strip")
            .arg("--strip-debug")
            .arg(&image)
            .output()?;
        if !stripped.status.success() {
            return Err("owned fixture image could not be stripped".into());
        }
        image
    } else {
        source.to_path_buf()
    };
    let output = std::process::Command::new("python3")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/judges/secode_rebind_fixture.py"
        ))
        .arg("--se")
        .arg(image)
        .arg("--fixture")
        .arg(env!("CARGO_BIN_EXE_secode-rebind-fixture"))
        .arg("--root")
        .arg(root.as_ref())
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "managed fixture failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    root.finish(Ok(()))
}
