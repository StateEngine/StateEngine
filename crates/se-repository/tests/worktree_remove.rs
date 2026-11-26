use git2::Repository;
use se_repository::worktree::{WorktreeRemoveError, parse_linux_mountinfo, remove_worktree};
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
        fs::write(main_dir.join("README.md"), "hello\n")?;
        fs::write(main_dir.join(".gitignore"), "*.ignored\n")?;
        let mut index = repo.index()?;
        index.add_path(Path::new("README.md"))?;
        index.add_path(Path::new(".gitignore"))?;
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
fn refuses_dirty_and_ignored_files_without_force_and_removes_with_force() -> TestResult {
    let case = TempCase::new("dirty-ignored")?;
    let (_main_dir, wt_dir) = case.init_repo_with_worktree("wt-ignored")?;
    fs::write(wt_dir.join("secret.ignored"), "local-only\n")?;

    let err = remove_worktree(&wt_dir, false)
        .err()
        .ok_or("ignored unversioned file must refuse without force")?;
    assert!(matches!(err, WorktreeRemoveError::Dirty { count: 1, .. }));
    assert!(wt_dir.exists());

    let report = remove_worktree(&wt_dir, true)
        .map_err(|err| format!("forced removal should succeed: {err:?}"))?;
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

#[test]
fn parses_linux_mountinfo_including_escaped_spaces_and_bind_mounts() {
    let root = Path::new("/tmp/wt");
    let sample = "\
36 35 98:0 / / rw,relatime - ext4 /dev/sda1 rw
142 36 98:0 /srv/shared /tmp/wt/bind\\040dir rw,relatime - ext4 /dev/sda1 rw
143 36 98:0 /srv/other /tmp/other rw,relatime - ext4 /dev/sda1 rw
";
    let mounts = parse_linux_mountinfo(sample, root);
    assert!(mounts.contains(Path::new("/tmp/wt/bind dir")));
    assert!(!mounts.contains(Path::new("/tmp/other")));
    assert!(!mounts.contains(Path::new("/")));
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

#[cfg(unix)]
#[test]
fn partial_delete_failure_preserves_dot_git_and_allows_retry() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    let case = TempCase::new("partial-retry")?;
    let (main_dir, wt_dir) = case.init_repo_with_worktree("wt-retry")?;
    let ro_dir = wt_dir.join("ro-sub");
    fs::create_dir_all(&ro_dir)?;
    let stuck = ro_dir.join("stuck.txt");
    fs::write(&stuck, "cannot unlink while parent is 0500\n")?;
    fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o500))?;

    // Root bypasses DAC write bits; only assert when unlink actually fails.
    let unlink_blocked = fs::remove_file(ro_dir.join("probe")).is_err()
        && fs::write(ro_dir.join("probe"), "x").is_err();
    if unlink_blocked {
        let err = remove_worktree(&wt_dir, true)
            .err()
            .ok_or("unwritable subdir must fail deletion")?;
        assert!(matches!(
            err,
            WorktreeRemoveError::DeleteFailed {
                dot_git_preserved: true,
                ..
            }
        ));
        assert!(wt_dir.join(".git").is_file(), "root .git must survive");
        fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o700))?;

        let report = remove_worktree(&wt_dir, true)
            .map_err(|e| format!("retry after fixing perms must succeed: {e:?}"))?;
        assert!(report.pruned);
        assert!(!wt_dir.exists());
        let repo = Repository::open(&main_dir)?;
        assert!(repo.find_worktree("wt-retry").is_err());
    } else {
        fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn parent_dir_permission_failure_preserves_dot_git_and_allows_retry() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let case = TempCase::new("ro-parent")?;
    let parent_holder = case.dir.join("parent");
    fs::create_dir_all(&parent_holder)?;
    let main_dir = case.dir.join("main");
    fs::create_dir_all(&main_dir)?;
    let repo = Repository::init(&main_dir)?;
    fs::write(main_dir.join("README.md"), "hello\n")?;
    let mut index = repo.index()?;
    index.add_path(Path::new("README.md"))?;
    index.write()?;
    let tree_id = index.write_tree()?;
    let tree = repo.find_tree(tree_id)?;
    let sig = git2::Signature::now("Test", "test@example.invalid")?;
    repo.commit(Some("HEAD"), &sig, &sig, "init", &tree, &[])?;

    let wt_dir = parent_holder.join("wt-ro-parent");
    repo.worktree("wt-ro-parent", &wt_dir, None)?;

    fs::set_permissions(&parent_holder, fs::Permissions::from_mode(0o500))?;
    let probe = parent_holder.join(".probe-writable");
    if fs::write(&probe, "x").is_err() {
        let err = remove_worktree(&wt_dir, false)
            .err()
            .ok_or("read-only parent directory must fail removal")?;
        assert!(matches!(
            err,
            WorktreeRemoveError::DeleteFailed {
                dot_git_preserved: true,
                ..
            }
        ));
        assert!(
            wt_dir.join(".git").is_file(),
            "root .git must survive when parent directory prevents rmdir"
        );
        fs::set_permissions(&parent_holder, fs::Permissions::from_mode(0o700))?;

        let report = remove_worktree(&wt_dir, false)
            .map_err(|e| format!("retry after restoring parent perms must succeed: {e:?}"))?;
        assert!(report.pruned);
        assert!(!wt_dir.exists());
        let repo = Repository::open(&main_dir)?;
        assert!(repo.find_worktree("wt-ro-parent").is_err());
    } else {
        let _ = fs::remove_file(&probe);
        fs::set_permissions(&parent_holder, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(windows)]
#[test]
fn refuses_windows_directory_junction_even_with_force_and_preserves_target_and_registration()
-> TestResult {
    let case = TempCase::new("win-junction")?;
    let (main_dir, wt_dir) = case.init_repo_with_worktree("wt-junc")?;
    let shared = case.dir.join("shared-node-modules");
    fs::create_dir_all(&shared)?;
    let precious = shared.join("keep.txt");
    fs::write(&precious, "precious\n")?;

    let junction = wt_dir.join("node_modules");
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&shared)
        .status()?;
    assert!(status.success(), "mklink /J must succeed");

    let err = remove_worktree(&wt_dir, true)
        .err()
        .ok_or("Windows directory junction must refuse even with force")?;
    match err {
        WorktreeRemoveError::LinksDetected {
            links, total_links, ..
        } => {
            assert_eq!(total_links, 1);
            assert!(links[0].0.ends_with("node_modules"));
        }
        other => return Err(format!("expected LinksDetected, got {other:?}").into()),
    }
    assert!(wt_dir.exists(), "worktree directory must survive");
    assert!(precious.exists(), "junction target file must survive");
    let repo = Repository::open(&main_dir)?;
    assert!(
        repo.find_worktree("wt-junc").is_ok(),
        "worktree registration must survive untouched"
    );
    Ok(())
}
