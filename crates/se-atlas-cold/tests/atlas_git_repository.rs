//! Registered metadata absence, configuration isolation and no-follow refusals.
#![cfg(target_os = "linux")]
use se_atlas_cold::atlas_git::*;
use se_proc::NativeSourceRoot;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};
type Check = Result<(), Box<dyn std::error::Error>>;
static SERIAL: Mutex<()> = Mutex::new(());
struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "git-source-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        fs::create_dir(&root)?;
        let f = Self(root);
        fs::create_dir(f.0.join("templates"))?;
        let mut cmd = f.command();
        let output = cmd
            .args(["init", "--bare", "--template"])
            .arg(f.0.join("templates"))
            .arg(f.0.join("git"))
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(f)
    }
    fn command(&self) -> Command {
        let mut command = Command::new("/usr/bin/git");
        command
            .env_clear()
            .env("HOME", &self.0)
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("LC_ALL", "C")
            .stdin(Stdio::null());
        command
    }
    fn registration(&self) -> Result<GitRegistration, Box<dyn std::error::Error>> {
        let path = self.0.join("git");
        let identity = NativeSourceRoot::open(&path)?.physical_identity()?;
        Ok(GitRegistration {
            git_directory: path.clone(),
            common_directory: path,
            git_identity: identity,
            common_identity: identity,
        })
    }
    fn reader(&self) -> Result<GitRepository, Box<dyn std::error::Error>> {
        Ok(GitRepository::open(
            Path::new("/usr/bin/git"),
            &self.registration()?,
            &self.0.join("control"),
        )?)
    }
    fn hash_blob(&self, data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        let mut command = self.command();
        command
            .arg("--git-dir")
            .arg(self.0.join("git"))
            .args(["hash-object", "-w", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut child = command.spawn()?;
        child
            .stdin
            .take()
            .ok_or("git stdin absent")?
            .write_all(data)?;
        let output = child.wait_with_output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(String::from_utf8(output.stdout)?.trim().to_owned())
    }
    fn make_tree(&self, names: &[String]) -> Result<String, Box<dyn std::error::Error>> {
        let blob = self.hash_blob(b"content\n")?;
        let mut listing = String::new();
        for name in names {
            listing.push_str(&format!("100644 blob {blob}\t{name}\n"));
        }
        let mut command = self.command();
        command
            .arg("--git-dir")
            .arg(self.0.join("git"))
            .arg("mktree")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut child = command.spawn()?;
        child
            .stdin
            .take()
            .ok_or("git stdin absent")?
            .write_all(listing.as_bytes())?;
        let output = child.wait_with_output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(String::from_utf8(output.stdout)?.trim().to_owned())
    }
    fn make_commit(
        &self,
        tree: &str,
        parent: Option<&str>,
        message: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut command = self.command();
        command.arg("--git-dir").arg(self.0.join("git")).args([
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=atlas-fixture.invalid",
            "commit-tree",
        ]);
        command.arg(tree);
        if let Some(parent) = parent {
            command.args(["-p", parent]);
        }
        command
            .args(["-m", message])
            .stdin(Stdio::null())
            .stdout(Stdio::piped());
        let output = command.output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(String::from_utf8(output.stdout)?.trim().to_owned())
    }
}
#[test]
fn unborn_is_absent_but_missing_or_linked_head_and_foreign_roots_refuse() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = Fixture::new()?;
    let reader = f.reader()?;
    assert_eq!(reader.head()?, None);
    reader.close()?;
    fs::remove_file(f.0.join("git/HEAD"))?;
    assert!(
        f.reader().is_err(),
        "missing registered HEAD was treated as an unborn branch"
    );
    let outside = f.0.join("outside-head");
    fs::write(&outside, format!("{}\n", "a".repeat(40)))?;
    std::os::unix::fs::symlink(&outside, f.0.join("git/HEAD"))?;
    assert!(
        f.reader().is_err(),
        "linked HEAD escaped registered metadata"
    );
    fs::remove_file(f.0.join("git/HEAD"))?;
    fs::write(f.0.join("git/HEAD"), "ref: refs/heads/main\n")?;
    let mut registration = f.registration()?;
    registration.git_identity = [0; 32];
    assert!(
        GitRepository::open(
            Path::new("/usr/bin/git"),
            &registration,
            &f.0.join("control")
        )
        .is_err()
    );
    assert!(!f.0.join("control").exists());
    Ok(())
}
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one real git fixture per oversized commit, so setup dominates"
)]
fn oversized_commit_degrades_only_itself_and_keeps_the_window() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = Fixture::new()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut blob_cmd = f.command();
    blob_cmd
        .arg("--git-dir")
        .arg(f.0.join("git"))
        .args(["hash-object", "-w", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut child = blob_cmd.spawn()?;
    child
        .stdin
        .take()
        .ok_or("git stdin absent")?
        .write_all(b"content\n")?;
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let blob = String::from_utf8(output.stdout)?.trim().to_owned();
    let small_tree = |f: &Fixture, names: &[&str]| -> Result<String, Box<dyn std::error::Error>> {
        let mut listing = String::new();
        for name in names {
            listing.push_str(&format!("100644 blob {blob}\t{name}\n"));
        }
        let mut mktree = f.command();
        mktree
            .arg("--git-dir")
            .arg(f.0.join("git"))
            .arg("mktree")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut child = mktree.spawn()?;
        child
            .stdin
            .take()
            .ok_or("git stdin absent")?
            .write_all(listing.as_bytes())?;
        let output = child.wait_with_output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(String::from_utf8(output.stdout)?.trim().to_owned())
    };
    let small = small_tree(&f, &["one.rs", "two.rs"])?;
    let mut big_listing = String::new();
    for i in 0..2400 {
        big_listing.push_str(&format!(
            "100644 blob {blob}\tgenerated-files-module-{i:04}-data-part-{i:04}.txt\n"
        ));
    }
    let mut mktree = f.command();
    mktree
        .arg("--git-dir")
        .arg(f.0.join("git"))
        .arg("mktree")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut child = mktree.spawn()?;
    child
        .stdin
        .take()
        .ok_or("git stdin absent")?
        .write_all(big_listing.as_bytes())?;
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let big = String::from_utf8(output.stdout)?.trim().to_owned();
    let commit = |args: &[&str]| -> Result<String, Box<dyn std::error::Error>> {
        let mut command = f.command();
        command
            .arg("--git-dir")
            .arg(f.0.join("git"))
            .args([
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=atlas-fixture.invalid",
                "commit-tree",
            ])
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped());
        let output = command.output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(String::from_utf8(output.stdout)?.trim().to_owned())
    };
    let old = commit(&[&small, "-m", "Small commit"])?;
    let head = commit(&[&big, "-p", &old, "-m", "Oversized commit"])?;
    fs::write(f.0.join("git/HEAD"), format!("{head}\n"))?;
    let reader = f.reader()?;
    let window = reader.window(&head, 2, deadline)?;
    assert_eq!(window.commits.len(), 2);
    assert_eq!(window.commits[0].subject, "Oversized commit");
    assert!(
        window.commits[0].paths.is_empty(),
        "a degraded commit retains no paths"
    );
    assert!(
        window.commits[0]
            .paths_note
            .as_deref()
            .is_some_and(|n| n.contains("256-path or 1024-byte bound"))
            && window.commits[0]
                .paths_note
                .as_deref()
                .is_some_and(|n| n.ends_with("paths omitted")),
        "the capped read proves its allowed prefix: {:?}",
        window.commits[0].paths_note
    );
    assert_eq!(window.commits[1].subject, "Small commit");
    assert_eq!(
        window.commits[1].paths,
        vec!["one.rs".to_owned(), "two.rs".to_owned()]
    );
    assert_eq!(
        window.commits[0].allowed_paths,
        Some(256),
        "the window reader proves the 256 allowed paths it parsed"
    );
    assert!(window.commits[1].paths_note.is_none());
    assert_eq!(window.commits[1].allowed_paths, None);
    assert_eq!(window.limit, HistoryLimit::Complete);
    reader.close()?;
    Ok(())
}
#[test]
fn oversized_all_allowed_commit_keeps_its_entry_with_the_truncated_list() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = Fixture::new()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let small = f.make_tree(&["one.rs".to_owned(), "two.rs".to_owned()])?;
    // 300 allowed paths: the bounded read succeeds, the parser stops at the
    // 256-path bound, and every parsed path clears the denial policy.
    let allowed: Vec<String> = (0..300).map(|i| format!("module-{i:04}.rs")).collect();
    let wide = f.make_tree(&allowed)?;
    let old = f.make_commit(&small, None, "Small commit")?;
    let head = f.make_commit(&wide, Some(&old), "Wide allowed commit")?;
    fs::write(f.0.join("git/HEAD"), format!("{head}\n"))?;
    let reader = f.reader()?;
    let window = reader.window(&head, 2, deadline)?;
    assert_eq!(window.commits.len(), 2);
    let commit = &window.commits[0];
    assert_eq!(commit.subject, "Wide allowed commit");
    assert!(
        commit.paths.is_empty(),
        "a degraded commit retains no paths"
    );
    assert!(
        commit
            .paths_note
            .as_deref()
            .is_some_and(|n| n.contains("256-path or 1024-byte bound"))
            && commit
                .paths_note
                .as_deref()
                .is_some_and(|n| n.ends_with("paths omitted")),
        "proven allowed paths keep the entry with the truncated list: {:?}",
        commit.paths_note
    );
    assert_eq!(
        commit.allowed_paths,
        Some(256),
        "the reader proves the 256 allowed paths it parsed"
    );
    assert_eq!(window.commits[1].subject, "Small commit");
    assert_eq!(window.commits[1].allowed_paths, None);
    assert_eq!(window.limit, HistoryLimit::Complete);
    reader.close()?;
    Ok(())
}
#[test]
fn oversized_denied_first_commit_is_withheld_for_size() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = Fixture::new()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let small = f.make_tree(&["one.rs".to_owned(), "two.rs".to_owned()])?;
    // 257 denied paths (id_ prefix) sort before the one allowed path: the
    // reader stops at the 256-path bound having proven no allowed path, so
    // the entry is withheld for size even though an allowed path exists past
    // the bound.
    let mixed: Vec<String> = (0..257)
        .map(|i| format!("id_data-{i:04}"))
        .chain(std::iter::once("kept-module.rs".to_owned()))
        .collect();
    let wide = f.make_tree(&mixed)?;
    let old = f.make_commit(&small, None, "Small commit")?;
    let head = f.make_commit(&wide, Some(&old), "Wide denied-first commit")?;
    fs::write(f.0.join("git/HEAD"), format!("{head}\n"))?;
    let reader = f.reader()?;
    let window = reader.window(&head, 2, deadline)?;
    assert_eq!(window.commits.len(), 2);
    let commit = &window.commits[0];
    assert_eq!(commit.subject, "Wide denied-first commit");
    assert!(commit.paths.is_empty(), "a withheld entry retains no paths");
    assert!(
        commit
            .paths_note
            .as_deref()
            .is_some_and(|n| n.ends_with("commit entry withheld for size")),
        "no proven allowed path withholds the entry, and the note says so: {:?}",
        commit.paths_note
    );
    assert_eq!(
        commit.allowed_paths,
        Some(0),
        "denied paths are not evidence of an allowed path"
    );
    reader.close()?;
    Ok(())
}
#[test]
fn byte_capped_changed_paths_keep_the_proven_allowed_prefix() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = Fixture::new()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let small = f.make_tree(&["one.rs".to_owned(), "two.rs".to_owned()])?;
    // 200 allowed paths of 499 bytes each: 100000 path bytes exceed the
    // 65536-byte read cap, so the reader returns its bounded prefix of 122
    // to 131 complete records, every one clearing the denial policy.
    let wide: Vec<String> = (0..200)
        .map(|i| format!("generated-module-{i:04}-{}", "x".repeat(477)))
        .collect();
    let tree = f.make_tree(&wide)?;
    let old = f.make_commit(&small, None, "Small commit")?;
    let head = f.make_commit(&tree, Some(&old), "Capped allowed commit")?;
    fs::write(f.0.join("git/HEAD"), format!("{head}\n"))?;
    let reader = f.reader()?;
    let window = reader.window(&head, 2, deadline)?;
    assert_eq!(window.commits.len(), 2);
    let commit = &window.commits[0];
    assert_eq!(commit.subject, "Capped allowed commit");
    assert!(
        commit.paths.is_empty(),
        "a capped commit retains no raw path list"
    );
    assert!(
        commit
            .paths_note
            .as_deref()
            .is_some_and(|n| n.contains("bounded Git read") && n.ends_with("paths omitted")),
        "the capped read keeps the entry and says so: {:?}",
        commit.paths_note
    );
    assert!(
        (100..=256).contains(&commit.allowed_paths.unwrap_or(0)),
        "the prefix proves its complete allowed records: {:?}",
        commit.allowed_paths
    );
    reader.close()?;
    Ok(())
}
#[test]
fn byte_capped_changed_paths_withhold_the_entry_when_the_prefix_is_denied() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = Fixture::new()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let small = f.make_tree(&["one.rs".to_owned(), "two.rs".to_owned()])?;
    // 200 denied paths (id_ prefix) of 495 bytes each: 99200 path bytes
    // exceed the 65536-byte read cap; the bounded prefix proves only denied
    // records, so the entry is withheld for size.
    let wide: Vec<String> = (0..200)
        .map(|i| format!("id_generated-{i:04}-{}", "x".repeat(477)))
        .collect();
    let tree = f.make_tree(&wide)?;
    let old = f.make_commit(&small, None, "Small commit")?;
    let head = f.make_commit(&tree, Some(&old), "Capped denied commit")?;
    fs::write(f.0.join("git/HEAD"), format!("{head}\n"))?;
    let reader = f.reader()?;
    let window = reader.window(&head, 2, deadline)?;
    assert_eq!(window.commits.len(), 2);
    let commit = &window.commits[0];
    assert_eq!(commit.subject, "Capped denied commit");
    assert!(commit.paths.is_empty(), "a withheld entry retains no paths");
    assert!(
        commit
            .paths_note
            .as_deref()
            .is_some_and(|n| n.contains("bounded Git read"))
            && commit
                .paths_note
                .as_deref()
                .is_some_and(|n| n.ends_with("commit entry withheld for size")),
        "a denied prefix withholds the entry, and the note says so: {:?}",
        commit.paths_note
    );
    assert_eq!(
        commit.allowed_paths,
        Some(0),
        "denied paths are not evidence of an allowed path"
    );
    reader.close()?;
    Ok(())
}
#[test]
fn real_commit_reads_ignore_repository_config_and_refuse_alternate_object_roots() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = Fixture::new()?;
    let mut git = f.command();
    let tree = git
        .arg("--git-dir")
        .arg(f.0.join("git"))
        .args(["hash-object", "-w", "-t", "tree", "--stdin"])
        .output()?;
    assert!(tree.status.success());
    let tree = String::from_utf8(tree.stdout)?.trim().to_owned();
    let commit = f
        .command()
        .arg("--git-dir")
        .arg(f.0.join("git"))
        .args([
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=atlas-fixture.invalid",
            "commit-tree",
            &tree,
            "-m",
            "Isolated metadata",
        ])
        .output()?;
    assert!(
        commit.status.success(),
        "{}",
        String::from_utf8_lossy(&commit.stderr)
    );
    let commit = String::from_utf8(commit.stdout)?.trim().to_owned();
    fs::write(f.0.join("git/HEAD"), format!("{commit}\n"))?;
    // Any accidental read of repository config now makes real Git refuse.
    fs::write(
        f.0.join("git/config"),
        "[malformed config that must never load\n",
    )?;
    let reader = f.reader()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    assert_eq!(reader.root_tree(&commit, deadline)?, tree);
    let window = reader.window(&commit, 1, deadline)?;
    assert_eq!(window.commits.len(), 1);
    assert_eq!(window.commits[0].subject, "Isolated metadata");
    assert_eq!(window.limit, HistoryLimit::Complete);
    let fanout = f.0.join("git/objects").join(&commit[..2]);
    let outside = f.0.join("foreign-objects");
    fs::rename(&fanout, &outside)?;
    std::os::unix::fs::symlink(&outside, &fanout)?;
    // Exercise both layers: even bypassing the static no-follow fence cannot
    // make native Git read an object outside the registered physical root.
    let output = read(
        Path::new("/usr/bin/git"),
        &f.0.join("control"),
        &f.0.join("git/objects"),
        GitRead::RootTree { commit: &commit },
        deadline,
    )?;
    assert!(
        !output.status.success(),
        "native Git followed a foreign object directory"
    );
    assert!(reader.root_tree(&commit, deadline).is_err());
    fs::remove_file(&fanout)?;
    fs::rename(&outside, &fanout)?;
    let loose = fanout.join(&commit[2..]);
    let outside = f.0.join("foreign-loose-object");
    fs::rename(&loose, &outside)?;
    std::os::unix::fs::symlink(&outside, &loose)?;
    let output = read(
        Path::new("/usr/bin/git"),
        &f.0.join("control"),
        &f.0.join("git/objects"),
        GitRead::RootTree { commit: &commit },
        deadline,
    )?;
    assert!(
        !output.status.success(),
        "native Git followed a foreign loose object"
    );
    assert!(reader.root_tree(&commit, deadline).is_err());
    fs::remove_file(&loose)?;
    fs::rename(&outside, &loose)?;
    assert_eq!(reader.root_tree(&commit, deadline)?, tree);
    reader.close()?;
    fs::write(
        f.0.join("git/objects/info/alternates"),
        f.0.join("elsewhere").to_string_lossy().as_bytes(),
    )?;
    assert!(
        f.reader().is_err(),
        "alternate object root escaped registered metadata"
    );
    assert!(!f.0.join("control").exists());
    Ok(())
}

#[test]
fn valid_commit_with_no_changed_paths_has_no_truncation_note() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let fixture = Fixture::new()?;
    let tree = fixture.make_tree(&["module.rs".into()])?;
    let old = fixture.make_commit(&tree, None, "Add the module")?;
    let head = fixture.make_commit(&tree, Some(&old), "Empty marker commit")?;
    fs::write(fixture.0.join("git/HEAD"), format!("{head}\n"))?;
    let reader = fixture.reader()?;
    let window = reader.window(&head, 2, Instant::now() + Duration::from_secs(30))?;
    reader.close()?;
    assert_eq!(window.commits.len(), 2);
    assert_eq!(window.commits[0].oid, head);
    assert!(window.commits[0].paths.is_empty());
    assert_eq!(window.commits[0].paths_note, None);
    assert_eq!(window.commits[0].allowed_paths, None);
    assert_eq!(window.commits[1].paths, ["module.rs"]);
    assert_eq!(window.limit, HistoryLimit::Complete);
    Ok(())
}

fn capped_file_names(prefix: &str, count: usize) -> Vec<String> {
    (0..count)
        .map(|index| {
            let lead = format!("{prefix}{index:03}-");
            format!("{lead}{}", "x".repeat(255 - lead.len()))
        })
        .collect()
}

#[test]
fn exact_stdout_limit_uses_only_the_separate_window_budget() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let fixture = Fixture::new()?;
    let paths = capped_file_names("module-", 256);
    assert_eq!(
        paths.iter().map(|path| path.len() + 1).sum::<usize>(),
        65_536
    );
    let tree = fixture.make_tree(&paths)?;
    let head = fixture.make_commit(&tree, None, "Complete records at the cap")?;
    fs::write(fixture.0.join("git/HEAD"), format!("{head}\n"))?;
    let reader = fixture.reader()?;
    let window = reader.window(&head, 1, Instant::now() + Duration::from_secs(30))?;
    reader.close()?;
    let commit = &window.commits[0];
    // The complete stdout is exactly at its limit. Its retained memory cost
    // still exceeds the independent history-window budget after allocation.
    assert!(commit.paths.is_empty());
    assert_eq!(commit.allowed_paths, Some(256));
    let note = commit
        .paths_note
        .as_deref()
        .ok_or("missing history window note")?;
    assert!(
        note.contains("history window") && note.ends_with("paths omitted"),
        "{note}"
    );
    assert_eq!(window.limit, HistoryLimit::Complete);
    Ok(())
}

#[test]
fn partial_changed_path_at_byte_limit_proves_no_allowed_record() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let fixture = Fixture::new()?;
    let denied = capped_file_names("id_", 255);
    let leaf = "x".repeat(255);
    let nested = fixture.make_tree(std::slice::from_ref(&leaf))?;
    let blob = fixture.hash_blob(b"content\n")?;
    let mut tree_listing = String::new();
    for path in &denied {
        tree_listing.push_str(&format!("100644 blob {blob}\t{path}\n"));
    }
    tree_listing.push_str(&format!("040000 tree {nested}\tzoom-folder\n"));
    let mut command = fixture.command();
    command
        .arg("--git-dir")
        .arg(fixture.0.join("git"))
        .arg("mktree")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut child = command.spawn()?;
    child
        .stdin
        .take()
        .ok_or("git stdin absent")?
        .write_all(tree_listing.as_bytes())?;
    let tree = child.wait_with_output()?;
    assert!(tree.status.success());
    let head = fixture.make_commit(
        String::from_utf8(tree.stdout)?.trim(),
        None,
        "Partial record",
    )?;
    fs::write(fixture.0.join("git/HEAD"), format!("{head}\n"))?;
    let complete_prefix = denied.iter().map(|path| path.len() + 1).sum::<usize>();
    assert!(complete_prefix < 65_536);
    assert!(complete_prefix + "zoom-folder/".len() + leaf.len() + 1 > 65_536);
    let reader = fixture.reader()?;
    let window = reader.window(&head, 1, Instant::now() + Duration::from_secs(30))?;
    reader.close()?;
    let commit = &window.commits[0];
    assert_eq!(commit.allowed_paths, Some(0));
    let note = commit
        .paths_note
        .as_deref()
        .ok_or("missing byte-cap note")?;
    assert!(
        note.contains("bounded Git read") && note.ends_with("entry withheld for size"),
        "{note}"
    );
    assert!(commit.paths.is_empty());
    assert_eq!(window.limit, HistoryLimit::Complete);
    Ok(())
}

#[test]
fn final_nul_is_a_separator_and_does_not_add_a_changed_path() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let fixture = Fixture::new()?;
    let paths = vec!["first.rs".to_owned(), "second file.rs".to_owned()];
    let tree = fixture.make_tree(&paths)?;
    let head = fixture.make_commit(&tree, None, "Complete changed paths")?;
    fs::write(fixture.0.join("git/HEAD"), format!("{head}\n"))?;
    let reader = fixture.reader()?;
    let window = reader.window(&head, 1, Instant::now() + Duration::from_secs(30))?;
    reader.close()?;
    let commit = &window.commits[0];
    assert_eq!(commit.paths, paths);
    assert_eq!(commit.paths_note, None);
    assert_eq!(commit.allowed_paths, None);
    assert_eq!(window.limit, HistoryLimit::Complete);
    Ok(())
}
