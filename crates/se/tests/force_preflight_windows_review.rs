//! Observe the native Windows process before and after each force preflight outcome.
#![cfg(windows)]

#[test]
fn force_preflight_windows_preserves_the_incumbent_until_checks_pass()
-> Result<(), Box<dyn std::error::Error>> {
    let package = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = package.join("../../target/judge-diagnostics/force-preflight-windows.json");
    let result = std::process::Command::new("python")
        .arg("-B")
        .arg(package.join("tests/judges/force_preflight_windows_review.py"))
        .args(["--se", env!("CARGO_BIN_EXE_se"), "--output"])
        .arg(output)
        .output()?;
    println!("{}", String::from_utf8_lossy(&result.stdout));
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}
