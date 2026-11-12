//! Real Git observation: the branch, HEAD identity, dirty fact and commit count
//! must survive the single-`status` read that replaced three separate calls.
//!
//! Each case builds a real repository with real `git`, because the facts under
//! test are Git's own: a stub would only re-assert this parser's assumptions.
//! The absence and unknown cases replace the `git` executable itself with a
//! stand-in that behaves as the situation requires — a machine with no Git at
//! all, and a Git that never finishes reporting — and run in a child process so
//! the stand-in `PATH` never reaches another case's Git.
#![cfg(unix)]
#[path = "../src/route/git_state.rs"]
mod git_state;
use std::{
    error::Error,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

type Check = Result<(), Box<dyn Error>>;

const CHILD: &str = "git_observation_child";
const CHILD_ABSENT: &str = "absent";
const CHILD_SILENT: &str = "silent";
const CHILD_HEADER_ONLY: &str = "header-only";
/// The environment key carrying the repository root to the spawned child, so a
/// replaced `PATH` never has to carry it.
const CHILD_ROOT: &str = "GIT_OBSERVATION_ROOT";
/// The environment key carrying the machine's real `git` to the child, so a
/// stand-in `git` can answer every subcommand but `status` by delegating to it.
const REAL_GIT: &str = "GIT_OBSERVATION_REAL_GIT";

struct Repo(PathBuf);
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

/// A directory holding only the `git` this case wants: an empty one is a
/// machine without Git, and one holding a script is a Git that behaves as the
/// script says.
struct PathOnly(PathBuf);
impl Drop for PathOnly {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
impl PathOnly {
    fn new(label: &str) -> Result<Self, Box<dyn Error>> {
        let mut nonce = [0u8; 8];
        se_proc::fill_entropy(&mut nonce)?;
        let root =
            std::env::temp_dir().join(format!("git-path-{label}-{}", se_types::hex_lower(&nonce)));
        std::fs::create_dir_all(&root)?;
        Ok(Self(root))
    }
    fn install_git(&self, script: &str) -> Check {
        let path = self.0.join("git");
        std::fs::write(&path, script)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
        Ok(())
    }
}

/// Resolve the machine's real `git`, so a stand-in can answer every subcommand
/// but `status` by delegating to it.
fn real_git() -> Result<String, Box<dyn Error>> {
    let output = Command::new("sh").args(["-c", "command -v git"]).output()?;
    if !output.status.success() {
        return Err("the machine has no real git to delegate to".into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

/// Run one observation case in a child process whose `PATH` holds nothing but
/// `git` as `case` wants it. `observe` is the real production entry: the child
/// runs exactly it, and prints the `GitView` it saw or the error it refused
/// with.
fn in_child(case: &str, want: &str, root: &Path) -> Result<String, Box<dyn Error>> {
    let binary = std::env::current_exe()?;
    let output = Command::new(binary)
        .args(["--exact", CHILD, "--ignored", "--nocapture", "--skip"])
        .arg(want)
        .env("PATH", case)
        .env(REAL_GIT, real_git()?)
        .env(CHILD_ROOT, root)
        .output()?;
    let stdout = String::from_utf8(output.stdout)?;
    if !output.status.success() {
        return Err(format!(
            "child {want} failed: {stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("observation: "))
        .map(str::to_owned)
        .ok_or_else(|| format!("child {want} printed no observation: {stdout}").into())
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

#[test]
fn a_machine_without_git_reports_the_repository_as_absent() -> Check {
    // Git metadata is present, so this machine may make a repository; but no
    // Git binary exists here. That is absent to this machine, not unreadable,
    // and status must not fail because of it.
    let repo = Repo::new("no-git")?;
    repo.commit("one")?;
    let empty = PathOnly::new("no-git")?;
    let observed = in_child(
        empty.0.to_str().ok_or("PATH is not UTF-8")?,
        CHILD_ABSENT,
        &repo.0,
    )?;
    assert_eq!(
        observed, "absent",
        "a machine without Git must report the repository as absent"
    );
    Ok(())
}

const NEITHER_REPORTS_NOR_EXITS: &str = r#"#!/bin/sh
# The real Git for every subcommand but `status`; `status` never reports.
case "$*" in
    *status*)
        trap '' TERM INT
        exec /bin/sleep 30
        ;;
esac
exec "$GIT_OBSERVATION_REAL_GIT" "$@"
"#;
const HEADER_THEN_SILENCE: &str = r#"#!/bin/sh
# The real Git for every subcommand but `status`; `status` reports the whole
# header and then never reports an entry or an exit.
case "$*" in
    *status*)
        printf '# branch.oid 0123456789012345678901234567890123456789\n# branch.head main\n'
        trap '' TERM INT
        exec /bin/sleep 30
        ;;
esac
exec "$GIT_OBSERVATION_REAL_GIT" "$@"
"#;
const HALF_HEADER_THEN_SILENCE: &str = r#"#!/bin/sh
# The real Git for every subcommand but `status`; `status` reports the commit
# identity alone and never the branch name, so the header never finishes.
case "$*" in
    *status*)
        printf '# branch.oid 0123456789012345678901234567890123456789\n'
        trap '' TERM INT
        exec /bin/sleep 30
        ;;
esac
exec "$GIT_OBSERVATION_REAL_GIT" "$@"
"#;

#[test]
fn a_status_that_never_reports_is_unreadable_not_an_unborn_repository() -> Check {
    // A Git that never wrote a header was once read as an unborn, detached,
    // clean repository: an empty header with a false dirty fact. It is unknown,
    // and the observation must refuse rather than spell emptiness.
    let repo = Repo::new("silent")?;
    repo.commit("one")?;
    let shim = PathOnly::new("silent")?;
    shim.install_git(NEITHER_REPORTS_NOR_EXITS)?;
    let observed = in_child(
        shim.0.to_str().ok_or("PATH is not UTF-8")?,
        CHILD_SILENT,
        &repo.0,
    )?;
    assert!(
        observed.contains("refused: "),
        "a status that never reported was accepted as {observed}"
    );
    assert!(
        observed.contains("unknown"),
        "the refusal must name the unknown state: {observed}"
    );
    Ok(())
}

#[test]
fn a_header_without_a_settled_entry_reports_dirty_as_unknown() -> Check {
    // The header proves the branch and the commit, but no entry and no exit
    // status arrived, so the tree may be clean or dirty. The dirty fact must
    // stay unknown while the header facts are still reported.
    let repo = Repo::new("header-only")?;
    repo.commit("one")?;
    let shim = PathOnly::new("header-only")?;
    shim.install_git(HEADER_THEN_SILENCE)?;
    let observed = in_child(
        shim.0.to_str().ok_or("PATH is not UTF-8")?,
        CHILD_HEADER_ONLY,
        &repo.0,
    )?;
    assert_eq!(
        observed,
        format!("head=0123456789012345678901234567890123456789 branch=main dirty={CHILD_ABSENT}"),
        "an unsettled scan must report the dirty fact as unknown"
    );
    Ok(())
}

#[test]
fn a_header_that_never_finishes_is_unreadable_not_detached_and_clean() -> Check {
    // Only the commit identity arrived. The branch name and the dirty fact are
    // both unknown, and reading the missing branch name as `None` would spell a
    // detached HEAD in a clean tree.
    let repo = Repo::new("half-header")?;
    repo.commit("one")?;
    let shim = PathOnly::new("half-header")?;
    shim.install_git(HALF_HEADER_THEN_SILENCE)?;
    let observed = in_child(
        shim.0.to_str().ok_or("PATH is not UTF-8")?,
        CHILD_HEADER_ONLY,
        &repo.0,
    )?;
    assert!(
        observed.starts_with("refused: ") && observed.contains("unknown"),
        "a half header must refuse as unknown, not as a detached clean tree: {observed}"
    );
    Ok(())
}

/// Protects: a machine without Git, a Git that never reports, and a Git that
/// reports only a header each keep absent, unreadable-unknown and
/// known-header-unknown distinct in the observation status reads.
#[test]
#[ignore = "explicitly spawned by the environment cases above"]
fn git_observation_child() -> Check {
    let root = PathBuf::from(std::env::var_os(CHILD_ROOT).ok_or("child root absent")?);
    // A short bound keeps a slow case quick; every case here settles or
    // refuses well inside it.
    let deadline = Instant::now() + Duration::from_millis(750);
    let observed = git_state::observe_within(&root, deadline);
    let line = match observed {
        Ok(Some(view)) => format!(
            "head={} branch={} dirty={}",
            view.head.as_deref().unwrap_or(CHILD_ABSENT),
            view.branch.as_deref().unwrap_or(CHILD_ABSENT),
            match view.uncommitted {
                Some(true) => "dirty".to_owned(),
                Some(false) => "clean".to_owned(),
                None => CHILD_ABSENT.to_owned(),
            }
        ),
        Ok(None) => "absent".to_owned(),
        Err(error) => format!("refused: {error}"),
    };
    println!("observation: {line}");
    Ok(())
}
