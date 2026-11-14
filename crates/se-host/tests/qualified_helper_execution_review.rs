//! Independent real-probe controls shared unchanged by old and new APIs.
#![cfg(all(target_os = "linux", feature = "listener"))]
use se_host::{
    client::{ClientOptions, lease::Deadline},
    secode_process::{Images, probe},
};
use std::{
    fs,
    fs::{File, FileTimes},
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
type Check<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Package {
    root: PathBuf,
    cli: PathBuf,
    server: PathBuf,
    complete: bool,
    bindings: Vec<se_proc::NativeSourceRoot>,
}
impl Package {
    fn new() -> Check<Self> {
        let mut nonce = [0; 16];
        se_proc::fill_entropy(&mut nonce)?;
        let root =
            std::env::temp_dir().join(format!("review-exec-{}", se_types::hex_lower(&nonce)));
        fs::create_dir(&root)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let physical = fs::canonicalize(&root)?;
        let mut bindings = Vec::new();
        for path in physical.ancestors() {
            bindings.push(se_proc::NativeSourceRoot::open(path)?);
        }
        let owner = Self {
            cli: root.join("secode"),
            server: root.join("secode-server"),
            root,
            complete: false,
            bindings,
        };
        eprintln!("independent executable fixture: {}", owner.root.display());
        let original = owner.root.join("original-fixture");
        let replacement = owner.root.join("replacement-fixture");
        let source = owner.root.join("fixture.rs");
        fs::write(&source, include_str!("support/qualified_helper_fixture.rs"))?;
        let output = std::process::Command::new("rustc")
            .args(["--edition=2024", "-O"])
            .arg(&source)
            .arg("-o")
            .arg(&original)
            .output()?;
        assert!(
            output.status.success(),
            "fixture compile: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut bytes = fs::read(&original)?;
        let positions: Vec<_> = bytes
            .windows(8)
            .enumerate()
            .filter_map(|(i, b)| (b == b"ORIGINAL").then_some(i))
            .collect();
        assert_eq!(
            positions.len(),
            1,
            "fixture identity must have one byte range"
        );
        bytes[positions[0]..positions[0] + 8].copy_from_slice(b"REPLACED");
        fs::write(&replacement, bytes)?;
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700))?;
        for path in [&owner.cli, &owner.server] {
            fs::copy(&original, path)?;
        }
        Ok(owner)
    }
    fn finish(mut self) -> Check {
        for binding in &self.bindings {
            binding.check()?;
        }
        fs::remove_dir_all(&self.root)?;
        assert!(
            matches!(fs::symlink_metadata(&self.root), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
        );
        self.complete = true;
        Ok(())
    }
    fn replace(&self, path: &Path) -> Check {
        let replacement = self.root.join("incoming");
        fs::copy(self.root.join("replacement-fixture"), &replacement)?;
        let before = fs::metadata(path)?;
        File::open(&replacement)?.set_times(FileTimes::new().set_modified(before.modified()?))?;
        assert_eq!(before.len(), fs::metadata(&replacement)?.len());
        assert_eq!(before.modified()?, fs::metadata(&replacement)?.modified()?);
        fs::rename(replacement, path)?;
        Ok(())
    }
}
impl Drop for Package {
    fn drop(&mut self) {
        if !self.complete || std::thread::panicking() {
            eprintln!(
                "retained independent executable fixture {}",
                self.root.display()
            );
        }
    }
}
// On the base, qualification exposes paths. On the head, inherent invocation
// methods win method resolution. Assertions and real production probe calls are
// identical; this fallback only adapts the earlier public argument type.
#[allow(dead_code)]
trait EarlierImages {
    fn cli_invocation(&mut self) -> se_types::Result<&Path>;
    fn server_invocation(&mut self) -> se_types::Result<&Path>;
}
impl EarlierImages for Images {
    fn cli_invocation(&mut self) -> se_types::Result<&Path> {
        self.validate()?;
        Ok(&self.cli)
    }
    fn server_invocation(&mut self) -> se_types::Result<&Path> {
        self.validate()?;
        Ok(&self.server)
    }
}
#[allow(dead_code)]
trait EarlierCommand {
    fn command(&self) -> se_types::Result<(std::process::Command, ())>;
}
impl EarlierCommand for Path {
    fn command(&self) -> se_types::Result<(std::process::Command, ())> {
        Ok((std::process::Command::new(self), ()))
    }
}
macro_rules! selected {
    ($images:expr, $server:expr) => {
        if $server {
            $images.server_invocation()?
        } else {
            $images.cli_invocation()?
        }
    };
}
fn marker(path: &Path) -> Check<Option<String>> {
    match fs::read_to_string(path) {
        Ok(value) => Ok(Some(value)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
fn deadline(duration: Duration) -> Check<Deadline> {
    Ok(Deadline::from_options(&ClientOptions {
        expected_generation: None,
        timeout: duration,
        cancelled: Arc::new(AtomicBool::new(false)),
    })?)
}
#[tokio::test]
async fn reviewer_both_native_images_keep_original_bytes_and_argv_zero() -> Check {
    for server in [false, true] {
        let p = Package::new()?;
        let mut images = Images::open(&p.cli)?;
        let image = selected!(images, server);
        let marker = p.root.join("marker");
        let path = if server { &p.server } else { &p.cli };
        let output = probe::command(
            image,
            &["probe".into(), marker.as_os_str().into()],
            &deadline(Duration::from_secs(5))?,
        )
        .await?;
        assert_eq!(output, b"secode ORIGINAL\n");
        let actual = fs::read_to_string(marker)?;
        assert_eq!(actual.lines().next(), Some("ORIGINAL"));
        assert_eq!(actual.lines().nth(1), path.to_str());
        p.finish()?;
    }
    Ok(())
}
async fn replacement_after_qualification(server: bool) -> Check {
    let p = Package::new()?;
    let mut images = Images::open(&p.cli)?;
    let image = selected!(images, server);
    let report = p.root.join("marker");
    p.replace(if server { &p.server } else { &p.cli })?;
    let result = probe::command(
        image,
        &["probe".into(), report.as_os_str().into()],
        &deadline(Duration::from_secs(5))?,
    )
    .await;
    let actual = marker(&report)?;
    println!("replacement probe server={server} result={result:?} marker={actual:?}");
    assert!(
        !actual
            .as_deref()
            .is_some_and(|text| text.starts_with("REPLACED")),
        "replacement executed before refusal"
    );
    assert!(result.is_err(), "named image drift must refuse");
    p.finish()
}
#[tokio::test]
async fn reviewer_cli_replacement_after_qualification_never_executes_new_bytes() -> Check {
    replacement_after_qualification(false).await
}
#[tokio::test]
async fn reviewer_server_replacement_after_qualification_never_executes_new_bytes() -> Check {
    replacement_after_qualification(true).await
}
#[tokio::test]
async fn reviewer_package_updates_are_not_excluded_between_invocations() -> Check {
    let p = Package::new()?;
    let mut old = Images::open(&p.cli)?;
    let image = selected!(old, false);
    let marker = p.root.join("marker");
    probe::command(
        image,
        &["probe".into(), marker.as_os_str().into()],
        &deadline(Duration::from_secs(5))?,
    )
    .await?;
    p.replace(&p.cli)?;
    p.replace(&p.server)?;
    assert!(old.validate().is_err());
    let mut fresh = Images::open(&p.cli)?;
    for server in [false, true] {
        let image = selected!(fresh, server);
        assert_eq!(
            probe::command(
                image,
                &["probe".into(), marker.as_os_str().into()],
                &deadline(Duration::from_secs(5))?
            )
            .await?,
            b"secode REPLACED\n"
        );
    }
    p.finish()
}
#[tokio::test]
async fn reviewer_probe_keeps_original_deadline_and_reaps_timed_out_child() -> Check {
    let p = Package::new()?;
    let mut images = Images::open(&p.cli)?;
    let image = selected!(images, false);
    let marker = p.root.join("marker");
    let clock = deadline(Duration::from_millis(500))?;
    let start = Instant::now();
    assert!(
        probe::command(image, &["sleep".into(), marker.as_os_str().into()], &clock)
            .await
            .is_err()
    );
    assert!(start.elapsed() < Duration::from_secs(3));
    let observed = fs::read_to_string(marker)?;
    let pid: u32 = observed
        .lines()
        .nth(2)
        .ok_or("child PID missing")?
        .parse()?;
    assert!(
        !PathBuf::from(format!("/proc/{pid}")).try_exists()?,
        "timed out direct child was not reaped"
    );
    p.finish()
}
#[tokio::test]
async fn reviewer_scripts_can_read_retained_source_after_interpreter_exec() -> Check {
    let p = Package::new()?;
    fs::write(&p.cli,b"#!/bin/sh\nIFS= read -r first < \"$0\"\nprintf '%s' \"$first\" > \"$1\"\nprintf 'secode script\\n'\n")?;
    let mut images = Images::open(&p.cli)?;
    let image = selected!(images, false);
    let marker = p.root.join("marker");
    assert_eq!(
        probe::command(
            image,
            &[marker.as_os_str().into()],
            &deadline(Duration::from_secs(5))?
        )
        .await?,
        b"secode script\n"
    );
    assert_eq!(fs::read(marker)?, b"#!/bin/sh");
    p.finish()
}
#[test]
fn reviewer_replacement_after_command_preparation_uses_retained_image() -> Check {
    let p = Package::new()?;
    let marker = p.root.join("marker");
    let mut images = Images::open(&p.cli)?;
    let image = selected!(images, false);
    let (mut command, _guard) = image.command()?;
    p.replace(&p.cli)?;
    let output = command
        .args([std::ffi::OsString::from("probe"), marker.as_os_str().into()])
        .env_clear()
        .output()?;
    assert!(output.status.success());
    let actual = fs::read_to_string(marker)?;
    println!("post-command replacement marker {actual:?}");
    assert_eq!(actual.lines().next(), Some("ORIGINAL"));
    assert_eq!(actual.lines().nth(1), p.cli.to_str());
    p.finish()
}
