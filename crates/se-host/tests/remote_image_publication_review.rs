//! Execute the real remote publication transaction against native filesystem tools.
#![cfg(all(feature = "remote", any(target_os = "linux", target_os = "macos")))]
#![allow(
    dead_code,
    reason = "Included production modules expose other constructors."
)]
use sha2::{Digest, Sha256};
use std::{path::PathBuf, process::Command};

#[path = "../../test-support/directory.rs"]
mod directory;
#[path = "remote_image_publication_review/remote.rs"]
mod remote;

fn judge(case: &str) -> Result<(), Box<dyn std::error::Error>> {
    let home = directory::private_case_directory()?;
    let digest = format!("{:x}", Sha256::digest(b"synthetic-image-payload\n"));
    let script = remote::publication(
        "cache/se.upload-0123456789abcdef",
        "cache/se",
        &digest,
        cfg!(target_os = "macos"),
    );
    let command = home.join("publication.sh");
    std::fs::write(&command, &script)?;
    let driver = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/remote_image_publication_review/consumer.py");
    let root = home.join("case");
    let output = Command::new("python3")
        .arg(driver)
        .arg("--case")
        .arg(case)
        .arg("--root")
        .arg(&root)
        .arg("--command")
        .arg(&command)
        .output()?;
    let diagnostics = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/judge-diagnostics/image-publication")
        .join(case);
    std::fs::create_dir_all(&diagnostics)?;
    std::fs::write(diagnostics.join("stdout.txt"), &output.stdout)?;
    std::fs::write(diagnostics.join("stderr.txt"), &output.stderr)?;
    std::fs::write(diagnostics.join("publication.sh"), script)?;
    if root.join("result.json").exists() {
        std::fs::copy(root.join("result.json"), diagnostics.join("result.json"))?;
    }
    assert!(
        output.status.success(),
        "publication case {case}: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    home.finish(Ok(()))
}

#[test]
fn absent_destination_publishes_the_exact_image() -> Result<(), Box<dyn std::error::Error>> {
    judge("absent")
}
#[test]
fn incumbent_file_is_preserved() -> Result<(), Box<dyn std::error::Error>> {
    judge("file")
}
#[test]
fn matching_incumbent_image_is_accepted_without_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    judge("matching-file")
}
#[test]
fn incumbent_directory_is_not_modified() -> Result<(), Box<dyn std::error::Error>> {
    judge("directory")
}
#[test]
fn incumbent_directory_link_is_not_followed() -> Result<(), Box<dyn std::error::Error>> {
    judge("directory-link")
}
#[test]
fn incumbent_dangling_link_is_preserved() -> Result<(), Box<dyn std::error::Error>> {
    judge("dangling-link")
}
#[test]
fn directory_arriving_at_the_link_boundary_is_not_modified()
-> Result<(), Box<dyn std::error::Error>> {
    judge("race-directory")
}
#[test]
fn directory_link_arriving_at_the_link_boundary_is_not_followed()
-> Result<(), Box<dyn std::error::Error>> {
    judge("race-directory-link")
}
#[test]
fn file_arriving_at_the_link_boundary_is_preserved() -> Result<(), Box<dyn std::error::Error>> {
    judge("race-file")
}
