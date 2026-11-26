use git2::Repository;
use se_repository::worktree::{WorktreeRemoveError, remove_worktree};
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

type TestResult = Result<(), Box<dyn Error>>;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempCase {
    dir: PathBuf,
}

impl TempCase {
    fn new(label: &str) -> Result<Self, Box<dyn Error>> {
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("se-wt-remove-{label}-{}-{seq}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn init_repo_with_worktree(&self, wt_name: &str) -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
        let main_dir = self.dir.join("main");
        fs::create_dir_all(&main_dir)?;
        let repo = Repository::init(&main_dir)?;
        let tracked = main_dir.join("README.md");
        fs::write(&tracked, "hello\n")?;
        let mut index = repo.index()?;
        index.add_path(Path::new("README.md"))?;
        index.write()?;
        let tree_id = index.write_tree()?;
        let tree = repo.find_tree(tree_id)?;
        let sig = git2::Signature::now("Test", "test@example.invalid")?;
        repo.commit(Some("HEAD"), &sig, &sig, "init", &tree, &[])?;

        let wt_dir = self.dir.join(wt_name);
        repo.worktree(wt_name, &wt_dir, None)?;
        Ok((main_dir, wt_dir))
    }
}

impl Drop for TempCase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn removes_clean_linked_worktree_and_prunes_metadata() -> TestResult {
    let case = TempCase::new("clean")?;
    let (main_dir, wt_dir) = case.init_repo_with_worktree("wt-clean")?;

    let report = remove_worktree(&wt_dir, false)
        .map_err(|err| format!("clean removal should succeed: {err:?}"))?;
    assert_eq!(report.worktree_name, "wt-clean");
    assert!(report.pruned);
    assert!(!report.forced);
    assert!(!wt_dir.exists());

    let repo = Repository::open(&main_dir)?;
    assert!(repo.find_worktree("wt-clean").is_err());
    Ok(())
}

#[test]
fn refuses_primary_repo_unrelated_dir_subdirectory_and_absent_path() -> TestResult {
    let case = TempCase::new("not-wt")?;
    let (main_dir, wt_dir) = case.init_repo_with_worktree("wt-sub")?;

    assert!(matches!(
        remove_worktree(&main_dir, true),
        Err(WorktreeRemoveError::NotLinkedWorktree { .. })
    ));
    assert!(main_dir.exists());

    let unrelated = case.dir.join("plain-dir");
    fs::create_dir_all(&unrelated)?;
    assert!(matches!(
        remove_worktree(&unrelated, true),
        Err(WorktreeRemoveError::NotLinkedWorktree { .. })
    ));
    assert!(unrelated.exists());

    let subdir = wt_dir.join("nested");
    fs::create_dir_all(&subdir)?;
    assert!(matches!(
        remove_worktree(&subdir, true),
        Err(WorktreeRemoveError::NotLinkedWorktree { .. })
    ));
    assert!(subdir.exists());

    let absent = case.dir.join("does-not-exist");
    assert!(matches!(
        remove_worktree(&absent, true),
        Err(WorktreeRemoveError::Absent { .. })
    ));
    Ok(())
}

#[test]
fn refuses_dirty_worktree_without_force_and_removes_with_force() -> TestResult {
    let case = TempCase::new("dirty")?;
    let (_main_dir, wt_dir) = case.init_repo_with_worktree("wt-dirty")?;
    fs::write(wt_dir.join("untracked.txt"), "wip\n")?;

    let err = remove_worktree(&wt_dir, false)
        .err()
        .ok_or("dirty must refuse without force")?;
    assert!(matches!(err, WorktreeRemoveError::Dirty { count: 1, .. }));
    assert!(wt_dir.exists());

    let report = remove_worktree(&wt_dir, true)
        .map_err(|err| format!("dirty removal should succeed with force: {err:?}"))?;
    assert!(report.forced);
    assert!(!wt_dir.exists());
    Ok(())
}

#[test]
fn refuses_locked_worktree_even_with_force() -> TestResult {
    let case = TempCase::new("locked")?;
    let (main_dir, wt_dir) = case.init_repo_with_worktree("wt-locked")?;
    let repo = Repository::open(&main_dir)?;
    let wt = repo.find_worktree("wt-locked")?;
    wt.lock(Some("in use"))?;

    let err = remove_worktree(&wt_dir, true)
        .err()
        .ok_or("locked must refuse")?;
    assert!(matches!(err, WorktreeRemoveError::Locked { .. }));
    assert!(wt_dir.exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn refuses_symlink_inside_worktree_even_with_force_and_preserves_target() -> TestResult {
    use std::os::unix::fs::symlink;

    let case = TempCase::new("symlink")?;
    let (_main_dir, wt_dir) = case.init_repo_with_worktree("wt-sym")?;
    let shared = case.dir.join("shared-node-modules");
    fs::create_dir_all(&shared)?;
    let precious = shared.join("keep.txt");
    fs::write(&precious, "precious\n")?;

    let linked = wt_dir.join("node_modules");
    symlink(&shared, &linked)?;

    let err = remove_worktree(&wt_dir, true)
        .err()
        .ok_or("symlink must refuse even with force")?;
    match err {
        WorktreeRemoveError::LinksDetected {
            links, total_links, ..
        } => {
            assert_eq!(total_links, 1);
            assert!(links[0].0.ends_with("node_modules"));
        }
        other => return Err(format!("expected LinksDetected, got {other:?}").into()),
    }
    assert!(wt_dir.exists());
    assert!(precious.exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn refuses_symlinked_worktree_root_even_with_force() -> TestResult {
    use std::os::unix::fs::symlink;

    let case = TempCase::new("sym-root")?;
    let (_main_dir, wt_dir) = case.init_repo_with_worktree("wt-real")?;
    let alias = case.dir.join("wt-alias");
    symlink(&wt_dir, &alias)?;

    let err = remove_worktree(&alias, true)
        .err()
        .ok_or("symlinked root must refuse")?;
    assert!(matches!(err, WorktreeRemoveError::LinksDetected { .. }));
    assert!(wt_dir.exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn refuses_unreadable_directory_inside_worktree_even_with_force() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    let case = TempCase::new("unreadable")?;
    let (_main_dir, wt_dir) = case.init_repo_with_worktree("wt-unreadable")?;
    let secret_dir = wt_dir.join("locked-dir");
    fs::create_dir_all(&secret_dir)?;
    fs::write(secret_dir.join("inner.txt"), "x")?;
    fs::set_permissions(&secret_dir, fs::Permissions::from_mode(0o000))?;

    let actually_unreadable = fs::read_dir(&secret_dir).is_err();
    if actually_unreadable {
        let err = remove_worktree(&wt_dir, true)
            .err()
            .ok_or("unreadable dir must refuse even with force")?;
        assert!(matches!(err, WorktreeRemoveError::Unreadable { .. }));
        assert!(wt_dir.exists());
    }
    fs::set_permissions(&secret_dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
