//! Real Git observation: the branch, HEAD identity, dirty fact and commit count
//! must survive the single-`status` read that replaced three separate calls.
//!
//! Each case builds a real repository with real `git`, because the facts under
//! test are Git's own: a stub would only re-assert this parser's assumptions.
#![cfg(unix)]
#[path = "../src/route/git_state.rs"]
mod git_state;
use std::{error::Error, path::Path, process::Command};

type Check = Result<(), Box<dyn Error>>;

struct Repo(std::path::PathBuf);
impl Drop for Repo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
impl Repo {
    fn new(label: &str) -> Result<Self, Box<dyn Error>> {
        let mut nonce = [0u8; 8];
        se_proc::fill_entropy(&mut nonce)?;
        let root = std::env::temp_dir().join(format!(
            "git-observe-{label}-{}",
            se_types::hex_lower(&nonce)
        ));
        std::fs::create_dir_all(&root)?;
        let repo = Self(root);
        repo.git(&repo.0, &["init", "-q", "."])?;
        repo.git(&repo.0, &["config", "user.email", "test@example.invalid"])?;
        repo.git(&repo.0, &["config", "user.name", "test"])?;
        Ok(repo)
    }
    fn git(&self, cwd: &Path, args: &[&str]) -> Result<String, Box<dyn Error>> {
        let output = Command::new("git")
            .args(["-c", "core.fsmonitor=false", "-C"])
            .arg(cwd)
            .args(args)
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(String::from_utf8(output.stdout)?)
    }
    fn commit(&self, message: &str) -> Check {
        // Each commit writes new bytes, so successive commits are real ones.
        std::fs::write(self.0.join("a.txt"), message.as_bytes())?;
        self.git(&self.0, &["add", "a.txt"])?;
        self.git(&self.0, &["commit", "-qm", message])?;
        Ok(())
    }
}

#[test]
fn a_clean_repository_reports_head_branch_count_and_not_dirty() -> Check {
    let repo = Repo::new("clean")?;
    repo.commit("one")?;
    let view = git_state::observe(&repo.0)?.ok_or("repository not observed")?;
    let head = repo.git(&repo.0, &["rev-parse", "HEAD"])?.trim().to_owned();
    assert_eq!(view.head.as_deref(), Some(head.as_str()));
    assert_eq!(view.branch.as_deref(), Some("master"));
    assert_eq!(view.commits, Some(1));
    assert_eq!(view.uncommitted, Some(false));
    Ok(())
}

#[test]
fn an_uncommitted_change_reports_dirty_with_the_same_identity() -> Check {
    let repo = Repo::new("dirty")?;
    repo.commit("one")?;
    std::fs::write(repo.0.join("untracked.txt"), b"new")?;
    let view = git_state::observe(&repo.0)?.ok_or("repository not observed")?;
    assert_eq!(view.uncommitted, Some(true));
    assert_eq!(view.commits, Some(1));
    assert_eq!(view.branch.as_deref(), Some("master"));
    Ok(())
}

#[test]
fn an_unborn_branch_reports_its_name_and_no_commit() -> Check {
    let repo = Repo::new("unborn")?;
    let view = git_state::observe(&repo.0)?.ok_or("repository not observed")?;
    assert_eq!(view.head, None);
    assert_eq!(view.branch.as_deref(), Some("master"));
    assert_eq!(view.commits, None);
    assert_eq!(view.uncommitted, None);
    Ok(())
}

#[test]
fn a_detached_head_reports_the_commit_and_no_branch() -> Check {
    let repo = Repo::new("detached")?;
    repo.commit("one")?;
    repo.commit("two")?;
    repo.git(&repo.0, &["checkout", "-q", "--detach", "HEAD"])?;
    let view = git_state::observe(&repo.0)?.ok_or("repository not observed")?;
    let head = repo.git(&repo.0, &["rev-parse", "HEAD"])?.trim().to_owned();
    assert_eq!(view.head.as_deref(), Some(head.as_str()));
    assert_eq!(view.branch, None);
    assert_eq!(view.commits, Some(2));
    Ok(())
}

#[test]
fn a_repository_with_many_changes_is_not_buffered_into_a_failure() -> Check {
    // The old buffered metadata read capped output at 4 KiB; the streaming read
    // must settle at the first entry no matter how many entries follow.
    let repo = Repo::new("many")?;
    repo.commit("one")?;
    for index in 0..4000 {
        std::fs::write(repo.0.join(format!("f{index}.txt")), b"x")?;
    }
    let view = git_state::observe(&repo.0)?.ok_or("repository not observed")?;
    assert_eq!(view.uncommitted, Some(true));
    assert_eq!(view.branch.as_deref(), Some("master"));
    Ok(())
}
