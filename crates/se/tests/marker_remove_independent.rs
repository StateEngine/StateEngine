//! Public owner-terminal consumers of repository marker custody, without providers.
#![cfg(target_os = "linux")]
#[path = "../../test-support/directory.rs"]
mod directory;

type Check = Result<(), Box<dyn std::error::Error>>;

fn fixture_links(root: &std::path::Path) -> Result<Vec<std::path::PathBuf>, std::io::Error> {
    fn visit(path: &std::path::Path, links: &mut Vec<std::path::PathBuf>) -> std::io::Result<()> {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            links.push(path.to_path_buf());
        } else if metadata.is_dir() {
            for entry in std::fs::read_dir(path)? {
                visit(&entry?.path(), links)?;
            }
        }
        Ok(())
    }
    let mut links = Vec::new();
    visit(root, &mut links)?;
    Ok(links)
}

fn cleanup_fixture(root: &std::path::Path) -> Check {
    if !std::fs::symlink_metadata(root)?.is_dir() {
        return Err(format!("fixture root is not a real directory: {}", root.display()).into());
    }
    // The successful judge already witnessed public down for every case. Unlink
    // only observed link leaves, without entering any directory link's target.
    for link in fixture_links(root)? {
        std::fs::remove_file(link)?;
    }
    let remaining = fixture_links(root)?;
    if !remaining.is_empty() {
        return Err(format!("fixture cleanup retained unexpected links: {remaining:?}").into());
    }
    // The root guard removes the tree itself once this check has run.
    Ok(())
}

fn judge(scenario: &str) -> Check {
    let parent = directory::private_directory()?;
    let output = std::process::Command::new("python3")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/judges/marker_remove.py"
        ))
        .args(["--se", env!("CARGO_BIN_EXE_se"), "--output"])
        .arg(parent.join("output"))
        .args(["--scenario", scenario])
        .output()?;
    assert!(
        output.status.success(),
        "retained marker fixture {}: {} {}",
        parent.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    cleanup_fixture(&parent)
}

/// Protects: init adds only its exact marker, including with a shared Git directory.
#[test]
fn init_preserves_all_original_repository_bytes() -> Check {
    judge("init")
}

/// Protects: Remove deletes its marker and only an empty parent.
#[test]
fn remove_accounts_for_its_marker_and_empty_parent() -> Check {
    judge("empty")
}

/// Protects: registering a subdirectory resolves the same shared Git marker.
#[test]
fn remove_finds_markers_for_registered_repository_subdirectories() -> Check {
    judge("nested")
}

/// Protects: a sibling project's marker and unrelated nonempty folders survive.
#[test]
fn remove_preserves_neighboring_project_and_user_files() -> Check {
    judge("neighbors")
}

/// Protects: a directory at the marker path never grants recursive deletion.
#[test]
fn remove_never_recursively_deletes_a_nonempty_marker_directory() -> Check {
    judge("directory")
}

/// Protects: neither a marker link nor its linked parent authorizes target deletion.
#[test]
fn remove_does_not_follow_marker_or_parent_links() -> Check {
    judge("links")
}

/// Protects: a changed repository ancestor never grants custody of foreign marker bytes.
#[test]
fn remove_keeps_foreign_markers_beyond_replaced_repository_ancestors()
-> Result<(), Box<dyn std::error::Error>> {
    judge("ancestor-link")
}

/// Protects: a same-named user file is preserved with an explicit kept reason.
#[test]
fn remove_keeps_foreign_regular_marker_contents() -> Check {
    judge("foreign")
}

/// Protects: an absent marker never grants custody of an empty foreign parent.
#[test]
fn remove_keeps_empty_foreign_marker_folders_beyond_linked_ancestors() -> Check {
    judge("ancestor-empty")
}

/// Protects: a missing marker authorizes no deletion, including its empty parent.
#[test]
fn remove_keeps_its_empty_state_folder_when_the_marker_is_missing() -> Check {
    judge("missing-marker")
}

/// Protects: subsequent real commits do not make the original product marker foreign.
#[test]
fn remove_finds_its_original_marker_after_subsequent_commits()
-> Result<(), Box<dyn std::error::Error>> {
    judge("head-moved")
}
