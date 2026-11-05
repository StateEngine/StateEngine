//! Registered metadata absence, configuration isolation and no-follow refusals.
#![cfg(target_os = "linux")]
use se_proc::{NativeSourceRoot, atlas_git::*};
use std::{
    fs,
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
            "user.email=fixture@example.invalid",
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
