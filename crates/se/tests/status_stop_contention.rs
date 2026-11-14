//! A real attended status read must not turn sibling cleanup into inaccessible custody.
#![cfg(target_os = "linux")]

#[path = "../../test-support/directory.rs"]
mod cleanup_directory;

#[test]
#[ignore = "requires native Xvfb/xterm; run the Python judge with an exact installed CLI"]
fn status_overlapping_stop_waits_within_one_bound_and_preserves_retry()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "se-status-stop-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    // This exclusively named child output has no pre-existing data.
    assert!(!root.exists(), "preserve existing fixture data");
    std::fs::create_dir(&root)?;
    let _root_owner = cleanup_directory::PrivateDirectory::for_case(root.clone());

    let output = std::process::Command::new("python3")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/judges/status_stop_contention.py"
        ))
        .args(["--se", env!("CARGO_BIN_EXE_se"), "--output"])
        .arg(&root)
        .output()?;
    assert!(
        output.status.success(),
        "retained {}: {} {}",
        root.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    _root_owner.finish(Ok(()))
}
