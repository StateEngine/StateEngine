//! Native Windows qualification of the closed-stdout deadline refusal.
//!
//! The shipping command's deadline path can report a stdout pipe as closed or
//! still open, but a closed-stdout client that stays alive had never been
//! qualified natively: the earlier disposable client's retained stdout writer
//! was unidentified, so a handle-close call was not EOF proof. A dedicated
//! fixture first proves, through an independent pipe reader, that it reaches
//! stdout and stderr EOF before it exits. The same fixture is then driven
//! through the shipping command so the retained byte counts and the closed-
//! pipe diagnostic are witnessed, not assumed. EOF, a read failure, and an
//! open pipe stay distinct, and the exact child is witnessed gone by an
//! outside census.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test assertions retain the failing native operation"
)]
use super::*;
use se_types::Detail;
use std::{
    io::Read,
    path::{Path, PathBuf},
    thread,
    time::Instant,
};

static NEXT_ROOT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[tokio::test]
async fn closed_stdout_is_qualified_while_the_client_stays_alive() {
    let root = fixture_root();
    let exe = fixture_executable(&root);
    independent_control(&exe, &root);
    shipped_command_qualifies(&exe, &root).await;
    remove_fixture_root(&root);
}

fn fixture_root() -> PathBuf {
    let name = format!(
        "se-host-ssh-stdout-eof-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let root = std::env::temp_dir().join(name);
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn fixture_executable(root: &Path) -> PathBuf {
    let source = root.join("ssh_stdout_eof.rs");
    std::fs::write(
        &source,
        include_str!("../../se-host/tests/support/ssh_stdout_eof_native.rs"),
    )
    .unwrap();
    let image = root.join("ssh_stdout_eof.exe");
    let output = std::process::Command::new(rustc())
        .args(["--edition=2024", "-C", "debuginfo=0"])
        .arg(&source)
        .arg("-o")
        .arg(&image)
        .output()
        .unwrap();
    if !output.status.success() {
        panic!(
            "fixture compilation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    image
}

fn rustc() -> std::ffi::OsString {
    std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into())
}

/// The independent control: a separate reader, not the shipping command's,
/// must witness stdout and stderr EOF while the exact client is still alive.
fn independent_control(exe: &Path, root: &Path) {
    let marker = root.join("control-marker");
    let mut child = std::process::Command::new(exe)
        .arg(&marker)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let out = read_pipe_to_eof(stdout);
    let err = read_pipe_to_eof(stderr);
    // The fixture closes both pipes and stays alive: both reads must have
    // reached EOF (not a failure, not an open pipe) with the client running.
    let status = child.try_wait().unwrap();
    assert!(
        status.is_none(),
        "fixture exited before proving EOF: {status:?}"
    );
    match out {
        ReadOutcome::Eof(bytes) => assert_eq!(bytes, b"hello", "stdout EOF bytes"),
        ReadOutcome::Failure(error) => panic!("stdout read failed, so EOF is unproven: {error}"),
        ReadOutcome::StillOpen => panic!("stdout pipe still open; no EOF witnessed"),
    }
    match err {
        ReadOutcome::Eof(bytes) => assert_eq!(bytes, b"err\n", "stderr EOF bytes"),
        ReadOutcome::Failure(error) => panic!("stderr read failed, so EOF is unproven: {error}"),
        ReadOutcome::StillOpen => panic!("stderr pipe still open; no EOF witnessed"),
    }
    let recorded: u32 = std::fs::read_to_string(&marker)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!(
        recorded,
        child.id(),
        "the marker must name the exact child read"
    );
    child.kill().unwrap();
    child.wait().unwrap();
    assert_absent(exe, recorded);
}

/// One pipe read, kept distinct: EOF with its bytes, a read failure, or a
/// pipe that stayed open past the read bound.
fn read_pipe_to_eof(mut stream: impl Read + Send + 'static) -> ReadOutcome {
    let handle = thread::spawn(move || {
        let mut buffer = Vec::new();
        stream.read_to_end(&mut buffer).map(|_| buffer)
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if handle.is_finished() {
            return match handle.join() {
                Ok(Ok(bytes)) => ReadOutcome::Eof(bytes),
                Ok(Err(error)) => ReadOutcome::Failure(error),
                Err(_) => ReadOutcome::Failure(std::io::Error::other("the pipe reader panicked")),
            };
        }
        if Instant::now() >= deadline {
            return ReadOutcome::StillOpen;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

enum ReadOutcome {
    Eof(Vec<u8>),
    Failure(std::io::Error),
    StillOpen,
}

/// The shipping command must report the closed pipes with their retained
/// counts, name the still-running client, and clean up the exact child.
async fn shipped_command_qualifies(exe: &Path, root: &Path) {
    let marker = root.join("shipped-marker");
    let error = run(
        exe.to_str().unwrap(),
        "localhost",
        marker.to_str().unwrap().to_owned(),
        Duration::from_secs(2),
    )
    .await
    .unwrap_err();
    let (reason, next_step) = deadline_detail(error);
    assert!(
        reason.contains("SSH bootstrap exceeded 2 seconds"),
        "{reason}"
    );
    assert!(reason.contains("5 stdout bytes (pipe closed)"), "{reason}");
    assert!(reason.contains("4 stderr bytes (pipe closed)"), "{reason}");
    assert!(
        reason.contains("the client was still running at the deadline"),
        "{reason}"
    );
    assert!(next_step.contains("retry the bootstrap"), "{next_step}");
    let recorded: u32 = std::fs::read_to_string(&marker)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_absent(exe, recorded);
}

fn deadline_detail(error: SeError) -> (String, String) {
    match error.body.detail() {
        Detail::ListenerUnavailable(detail) => (detail.reason.clone(), detail.next_step.clone()),
        other => panic!("expected listener-unavailable, got {other:?}"),
    }
}

/// Outside census: a separate process must witness the exact child stopped.
/// A terminated child is gone even while its process object lingers; a
/// still-running pid past the bound is a real failure.
fn assert_absent(exe: &Path, pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let output = std::process::Command::new(exe)
            .args(["--census", &pid.to_string()])
            .output()
            .unwrap();
        match output.status.code().unwrap_or(255) {
            0 => return,
            1 => {
                if Instant::now() >= deadline {
                    panic!("exact child {pid} is still present after cleanup");
                }
                thread::sleep(Duration::from_millis(50));
            }
            other => panic!("census returned unexpected code {other}"),
        }
    }
}

/// Remove only the known fixture entries; never recurse blindly.
fn remove_fixture_root(root: &Path) {
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            if matches!(
                file_name.to_string_lossy().as_ref(),
                "ssh_stdout_eof.rs"
                    | "ssh_stdout_eof.exe"
                    | "ssh_stdout_eof.pdb"
                    | "control-marker"
                    | "shipped-marker"
            ) {
                std::fs::remove_file(entry.path()).ok();
            }
        }
    }
    std::fs::remove_dir(root).ok();
}
