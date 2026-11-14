//! The repository's recorded git identity. `se init` writes one small marker
//! under the repository's common Git directory — tool state inside `.git`,
//! never a worktree file, so it follows the repository through a folder move
//! and is never committed or pushed. `se project move` verifies a moved
//! folder against that marker before proposing the root revision, so a move
//! can only re-attach the repository that was registered. Every Git
//! invocation passes a top-precedence `core.fsmonitor=false` command
//! parameter and bounded output, matching the init repository observation.
use se_types::{Result, SeError, details};
#[cfg(test)]
use std::process::Command;
use std::{
    path::{Path, PathBuf},
    process::Output,
};
#[path = "git_identity/command.rs"]
mod command;
use command::run;

const STDOUT_BOUND: usize = 4096;

/// True when the selected path is itself a bare repository (no working tree).
/// A path that is not a Git repository at all is not bare, and a path cannot
/// be detected as bare when Git is not installed: a missing binary leaves no
/// repository state to observe, so the path proceeds as a plain folder and
/// its git identity is recorded as absent.
pub fn is_bare(root: &Path) -> Result<bool> {
    let output = match run(root, &["rev-parse", "--is-bare-repository"]) {
        Spawn::Output(output) => output,
        Spawn::Missing => return Ok(false),
        Spawn::Unreadable(error) => return Err(error),
    };
    if output.status.success() {
        Ok(text(&output)? == "true")
    } else if output.status.code() == Some(128) {
        Ok(false)
    } else {
        Err(unreadable(root, "bare repository check", &output))
    }
}
/// The common Git directory: the main `.git` of a worktree or bare
/// repository, wherever the working copy sits.
fn common_dir(root: &Path) -> Result<PathBuf> {
    let output = match run(root, &["rev-parse", "--git-common-dir"]) {
        Spawn::Output(output) => output,
        Spawn::Missing => return Err(missing_refusal()),
        Spawn::Unreadable(error) => return Err(error),
    };
    if !output.status.success() {
        return Err(unreadable(root, "Git common directory", &output));
    }
    let value = text(&output)?;
    let path = PathBuf::from(&value);
    Ok(if path.is_absolute() {
        path
    } else {
        root.join(path)
    })
}
fn marker_path(root: &Path, project_id: &str) -> Result<PathBuf> {
    Ok(common_dir(root)?
        .join("stateengine")
        .join(format!("project-{project_id}")))
}
/// Write the identity marker for a fresh registration. Returns the marker
/// path when written; a repository without commits records nothing and
/// later refuses a move on exactly that ground.
pub fn record(
    root: &Path,
    project_id: &str,
    head: &str,
    branch: &Option<String>,
) -> Result<PathBuf> {
    let path = marker_path(root, project_id)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| se_core::scope::unreadable("Git identity marker", &e.to_string()))?;
    }
    let marker = serde_json::json!({
        "v": 1,
        "project": project_id,
        "head": head,
        "branch": branch,
        "ts": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    });
    let bytes = serde_json::to_vec(&marker).map_err(|e| {
        SeError::invalid("git identity marker", "a serializable identity record").with_cause(e)
    })?;
    std::fs::write(&path, bytes)
        .map_err(|e| se_core::scope::unreadable("Git identity marker", &e.to_string()))?;
    Ok(path)
}
/// Verify a moved folder against the recorded identity. Returns the recorded
/// HEAD and branch from the marker. The marker proves this repository was
/// the one registered for the project; the HEAD relation check additionally
/// refuses a repository that has diverged from the recorded commit in both
/// directions (unrelated history), while allowing continued work and
/// ordinary resets after the registration.
pub fn verify(root: &Path, project_id: &str) -> Result<(String, Option<String>)> {
    let path = marker_path(root, project_id)?;
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(refusal(
                "moved repository folder",
                "no recorded git identity for this project in the folder's .git",
                "The folder was never initialized for this project, or its .git state was replaced. Restore the original folder, or register this folder as a new project with se init.",
            ));
        }
        Err(error) => {
            return Err(se_core::scope::unreadable(
                "Git identity marker",
                &error.to_string(),
            ));
        }
    };
    let marker: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
        refusal(
            "Git identity marker",
            "the recorded identity is unreadable JSON",
            "Restore the folder's .git state from a backup, then retry the move with the original folder.",
        )
    })?;
    if marker.get("v").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(refusal(
            "Git identity marker",
            "the recorded identity version is not supported",
            "Restore the original folder, or register this folder as a new project with se init.",
        ));
    }
    if marker.get("project").and_then(serde_json::Value::as_str) != Some(project_id) {
        return Err(refusal(
            "moved repository folder",
            "the recorded identity names a different project",
            "The folder belongs to another project registration. Do not move it here; open the original project and move it from its own folder.",
        ));
    }
    let recorded_head = marker
        .get("head")
        .and_then(serde_json::Value::as_str)
        .filter(|value| {
            matches!(value.len(), 40 | 64) && value.bytes().all(|b| b.is_ascii_hexdigit())
        })
        .ok_or_else(|| {
            refusal(
                "Git identity marker",
                "the recorded HEAD is missing or malformed",
                "Restore the original folder, or register this folder as a new project with se init.",
            )
        })?
        .to_owned();
    let output = match run(root, &["rev-parse", "--verify", "--quiet", "HEAD"]) {
        Spawn::Output(output) => output,
        Spawn::Missing => return Err(missing_refusal()),
        Spawn::Unreadable(error) => return Err(error),
    };
    let current_head = if output.status.success() {
        text(&output)?
    } else if output.status.code() == Some(1) {
        return Err(refusal(
            "moved repository folder",
            "the folder has no commits yet, so its identity cannot be verified",
            "Commit in the moved folder and retry, or restore the original folder.",
        ));
    } else {
        return Err(unreadable(root, "moved repository HEAD", &output));
    };
    if current_head != recorded_head
        && !ancestor(root, &current_head, &recorded_head)?
        && !ancestor(root, &recorded_head, &current_head)?
    {
        return Err(refusal(
            "moved repository folder",
            "its current HEAD and the recorded HEAD share no ancestry",
            "The folder is not the moved repository. Restore the original folder, or register this folder as a new project with se init.",
        ));
    }
    let branch = marker
        .get("branch")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_owned());
    Ok((recorded_head, branch))
}
fn ancestor(root: &Path, candidate: &str, head: &str) -> Result<bool> {
    let output = match run(root, &["merge-base", "--is-ancestor", candidate, head]) {
        Spawn::Output(output) => output,
        Spawn::Missing => return Err(missing_refusal()),
        Spawn::Unreadable(error) => return Err(error),
    };
    if output.status.success() || output.status.code() == Some(1) {
        return Ok(output.status.success());
    }
    Err(unreadable(root, "HEAD ancestry check", &output))
}
fn refusal(subject: &str, reason: &str, next_step: &str) -> SeError {
    SeError::new(se_types::Detail::RepoInvalid(details::RepoInvalid {
        subject: subject.into(),
        reason: reason.into(),
        next_step: next_step.into(),
    }))
}
fn unreadable(root: &Path, subject: &str, output: &Output) -> SeError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let tail: String = stderr.chars().take(160).collect();
    se_core::scope::unreadable(
        subject,
        &format!(
            "git failed for {} with exit {:?}: {tail}",
            root.display(),
            output.status.code()
        ),
    )
}
/// The outcome of one bounded Git invocation. `Missing` keeps a spawn that
/// found no Git binary distinct from a command that ran and failed: absent
/// is a different fact from unreadable, and each caller reports it as such.
enum Spawn {
    Output(Output),
    Missing,
    Unreadable(SeError),
}
fn missing_refusal() -> SeError {
    refusal(
        "moved repository folder",
        "Git is not installed on this machine",
        "A moved repository is verified against its recorded commit history, which requires Git. Install Git (https://git-scm.com) and retry the move.",
    )
}
fn text(output: &Output) -> Result<String> {
    if output.stdout.len() > STDOUT_BOUND {
        return Err(SeError::too_large(
            "Git metadata",
            STDOUT_BOUND,
            output.stdout.len(),
        ));
    }
    std::str::from_utf8(&output.stdout)
        .map(|s| s.trim_end_matches(['\r', '\n']).to_owned())
        .map_err(|_| se_core::scope::unreadable("Git metadata", "Git returned non-UTF-8 metadata"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(root: &Path, args: &[&str]) -> Result<()> {
        let output = Command::new("git")
            .args(["-c", "user.email=t@e.st", "-c", "user.name=t"])
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .map_err(|e| SeError::invalid("git", &e.to_string()))?;
        if !output.status.success() {
            return Err(SeError::invalid(
                "git test fixture",
                &format!("git {args:?}: {}", String::from_utf8_lossy(&output.stderr)),
            ));
        }
        Ok(())
    }
    fn fresh_repo(tag: &str) -> Result<PathBuf> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir =
            std::env::temp_dir().join(format!("se-git-id-{}-{stamp}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir)
            .map_err(|e| SeError::invalid("test repository", &e.to_string()))?;
        git(&dir, &["init", "-b", "main"])?;
        Ok(dir)
    }
    fn commit(dir: &Path, file: &str, body: &str) -> Result<()> {
        std::fs::write(dir.join(file), body)
            .map_err(|e| SeError::invalid("test file", &e.to_string()))?;
        git(dir, &["add", file])?;
        git(dir, &["commit", "-m", file])
    }
    fn head(dir: &Path) -> Result<String> {
        let output = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["rev-parse", "HEAD"])
            .output()
            .map_err(|e| SeError::invalid("git", &e.to_string()))?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }
    fn marker(dir: &Path, project_id: &str) -> Result<PathBuf> {
        let output = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["rev-parse", "--git-common-dir"])
            .output()
            .map_err(|e| SeError::invalid("git", &e.to_string()))?;
        let common = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
        let common = if common.is_absolute() {
            common
        } else {
            dir.join(common)
        };
        Ok(common
            .join("stateengine")
            .join(format!("project-{project_id}")))
    }
    fn refusal(result: Result<(String, Option<String>)>, expected: &str) -> Result<()> {
        match result {
            Err(error) if error.to_string().contains(expected) => Ok(()),
            Err(error) => Err(SeError::invalid(
                "test expectation",
                &format!("refusal does not name {expected}: {error}"),
            )),
            Ok(_) => Err(SeError::invalid(
                "test expectation",
                "verify succeeded where a refusal was expected",
            )),
        }
    }
    #[test]
    fn bare_checks_separate_bare_plain_and_absent() -> Result<()> {
        let plain = fresh_repo("plain")?;
        assert!(!is_bare(&plain)?);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let bare =
            std::env::temp_dir().join(format!("se-git-id-{}-{stamp}-bare", std::process::id()));
        git(
            &plain,
            &[
                "clone",
                "--bare",
                plain.to_str().unwrap_or("plain"),
                bare.to_str().unwrap_or("bare"),
            ],
        )?;
        assert!(is_bare(&bare)?);
        let absent = fresh_repo("absent")?;
        assert!(!is_bare(&absent)?);
        for dir in [plain, bare, absent] {
            std::fs::remove_dir_all(dir).ok();
        }
        Ok(())
    }
    #[test]
    fn marker_roundtrip_verifies_head_and_branch() -> Result<()> {
        let dir = fresh_repo("roundtrip")?;
        commit(&dir, "a.txt", "one\n")?;
        let first = head(&dir)?;
        record(&dir, "p1", &first, &Some("main".to_owned()))?;
        let (current, branch) = verify(&dir, "p1")?;
        assert_eq!(current, first);
        assert_eq!(branch.as_deref(), Some("main"));
        std::fs::remove_dir_all(dir).ok();
        Ok(())
    }
    #[test]
    fn verify_refuses_wrong_project_and_bad_marker() -> Result<()> {
        let dir = fresh_repo("wrongid")?;
        commit(&dir, "a.txt", "one\n")?;
        let first = head(&dir)?;
        record(&dir, "p1", &first, &None)?;
        // A marker is stored per project id: an id with no marker is absent,
        // and a marker whose content names another project is refused.
        refusal(verify(&dir, "p2"), "no recorded git identity")?;
        let path = marker(&dir, "p1")?;
        std::fs::write(
            &path,
            serde_json::to_vec(
                &serde_json::json!({"v":1,"project":"p2","head":first,"branch":null,"ts":1}),
            )
            .map_err(|e| SeError::invalid("test marker", &e.to_string()))?,
        )
        .map_err(|e| SeError::invalid("test marker", &e.to_string()))?;
        refusal(verify(&dir, "p1"), "different project")?;
        std::fs::write(&path, b"{\"v\":1}")
            .map_err(|e| SeError::invalid("test marker", &e.to_string()))?;
        std::fs::write(&path, b"{\"v\":2}")
            .map_err(|e| SeError::invalid("test marker", &e.to_string()))?;
        refusal(verify(&dir, "p1"), "version")?;
        std::fs::write(
            &path,
            serde_json::to_vec(
                &serde_json::json!({"v":1,"project":"p1","head":"abc","branch":null,"ts":1}),
            )
            .map_err(|e| SeError::invalid("test marker", &e.to_string()))?,
        )
        .map_err(|e| SeError::invalid("test marker", &e.to_string()))?;
        refusal(verify(&dir, "p1"), "malformed")?;
        std::fs::remove_file(&path).map_err(|e| SeError::invalid("test marker", &e.to_string()))?;
        refusal(verify(&dir, "p1"), "no recorded git identity")?;
        std::fs::remove_dir_all(dir).ok();
        Ok(())
    }
    #[test]
    fn verify_allows_ancestry_either_way_and_refuses_unrelated() -> Result<()> {
        let dir = fresh_repo("ancestry")?;
        commit(&dir, "a.txt", "one\n")?;
        let first = head(&dir)?;
        record(&dir, "p1", &first, &None)?;
        commit(&dir, "b.txt", "two\n")?;
        let (recorded, _) = verify(&dir, "p1")?;
        assert_eq!(recorded, first);
        assert_ne!(head(&dir)?, first);
        git(&dir, &["reset", "--hard", first.as_str()])?;
        verify(&dir, "p1")?;
        git(&dir, &["checkout", "--orphan", "other"])?;
        git(&dir, &["add", "-A"])?;
        commit(&dir, "c.txt", "three\n")?;
        refusal(verify(&dir, "p1"), "share no ancestry")?;
        std::fs::remove_dir_all(dir).ok();
        Ok(())
    }
    #[test]
    fn verify_refuses_unborn_head() -> Result<()> {
        let dir = fresh_repo("unborn")?;
        commit(&dir, "a.txt", "one\n")?;
        let first = head(&dir)?;
        record(&dir, "p1", &first, &None)?;
        git(&dir, &["update-ref", "-d", "HEAD"])?;
        refusal(verify(&dir, "p1"), "no commits yet")?;
        std::fs::remove_dir_all(dir).ok();
        Ok(())
    }
}
