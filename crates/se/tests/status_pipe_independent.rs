#![cfg(windows)]
#![allow(dead_code)]
#[path = "../src/repository/mod.rs"]
mod repository;
use repository::state as git_state;

use serde_json::{Value, json};
use std::{
    fs, io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const HEAD: &str = "1234567890123456789012345678901234567890";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("status-pipe-{}-{nonce}", std::process::id()));
        fs::create_dir_all(path.join("bin")).unwrap();
        fs::create_dir(path.join(".git")).unwrap();
        let source = path.join("fixture.rs");
        fs::write(&source, include_str!("support/status_pipe_fixture.rs")).unwrap();
        let output = Command::new("rustc")
            .args(["--edition=2024", "-o"])
            .arg(path.join("bin/git.exe"))
            .arg(&source)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "fixture compile: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self(path)
    }

    fn join_descendant(&self, expected: bool) {
        let record = self.0.join("descendant.pid");
        if !expected {
            assert!(!record.exists(), "unexpected descendant");
            return;
        }
        let until = Instant::now() + Duration::from_secs(6);
        while !record.exists() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
        let pid: u32 = fs::read_to_string(record)
            .expect("descendant identity receipt")
            .parse()
            .unwrap();
        // Waiting is observational: no process is signalled, and the child has a finite lifetime.
        let raw = unsafe { OpenProcess(0x00100000 | 0x1000, 0, pid) };
        if raw.is_null() {
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(87),
                "open exact fixture PID"
            );
            assert!(self.0.join("descendant.closed").exists(), "exit receipt");
            return;
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        if unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) } != 0 {
            let mut image = vec![0u16; 32768];
            let mut size = image.len() as u32;
            let observed = unsafe {
                QueryFullProcessImageNameW(handle.as_raw_handle(), 0, image.as_mut_ptr(), &mut size)
            };
            if observed != 0 {
                use std::os::windows::ffi::OsStringExt;
                let image = PathBuf::from(std::ffi::OsString::from_wide(&image[..size as usize]));
                assert_eq!(
                    fs::canonicalize(image).unwrap(),
                    fs::canonicalize(self.0.join("bin/git.exe")).unwrap()
                );
            } else {
                assert_eq!(
                    unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) },
                    0,
                    "identity read failed on live fixture"
                );
            }
        }
        assert_eq!(
            unsafe { WaitForSingleObject(handle.as_raw_handle(), 6000) },
            0,
            "finite descendant failed to join"
        );
        let mut exit = 0;
        assert_ne!(
            unsafe { GetExitCodeProcess(handle.as_raw_handle(), &mut exit) },
            0
        );
        assert_eq!(exit, 0, "descendant exit");
        assert!(self.0.join("descendant.closed").exists(), "closed receipt");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove joined private fixture");
    }
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut std::ffi::c_void;
    fn WaitForSingleObject(handle: *mut std::ffi::c_void, millis: u32) -> u32;
    fn QueryFullProcessImageNameW(
        handle: *mut std::ffi::c_void,
        flags: u32,
        name: *mut u16,
        size: *mut u32,
    ) -> i32;
    fn GetExitCodeProcess(handle: *mut std::ffi::c_void, code: *mut u32) -> i32;
}

fn control(case: &str) {
    let fixture = Fixture::new();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "status_pipe_worker",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("STATUS_PIPE_CASE", case)
        .env("STATUS_PIPE_HOME", &fixture.0)
        .env("PATH", fixture.0.join("bin"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    // Join before checking the result or deadline, including the expected failing base.
    fixture.join_descendant(case.ends_with("held"));
    assert!(
        output.status.success(),
        "worker failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: Value =
        serde_json::from_slice(&fs::read(fixture.0.join("observation.json")).unwrap()).unwrap();
    let diagnostics = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/judge-diagnostics");
    fs::create_dir_all(&diagnostics).unwrap();
    fs::write(
        diagnostics.join(format!("status-{case}.json")),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    println!("STATUS_PIPE_RECEIPT {receipt}");
    if case == "silent-held" {
        assert_eq!(
            receipt["kind"], "unreadable",
            "silent pipes must not invent empty facts"
        );
        assert!(receipt["error"].as_str().unwrap().contains("unknown"));
    } else {
        assert_eq!(receipt["kind"], "known", "{receipt}");
        assert_eq!(receipt["head"], HEAD);
        assert_eq!(receipt["branch"], "review");
        match case {
            "clean" => {
                assert_eq!(receipt["commits"], 7);
                assert_eq!(receipt["dirty"], false);
            }
            "dirty" => assert_eq!(receipt["dirty"], true),
            "header-held" => {
                assert!(
                    receipt["dirty"].is_null(),
                    "incomplete working tree is unknown"
                );
                assert!(
                    receipt["commits"].is_null(),
                    "expired history stays unknown"
                );
            }
            "count-held" => {
                assert!(
                    receipt["commits"].is_null(),
                    "unterminated count is unknown, never zero"
                );
                assert_eq!(receipt["dirty"], false);
            }
            "stderr-held" => assert_eq!(receipt["dirty"], false),
            _ => panic!("unknown control"),
        }
    }
    assert!(
        receipt["elapsed_ms"].as_u64().unwrap() < 1800,
        "400 ms status deadline stretched by a retained pipe: {receipt}"
    );
}

#[test]
fn status_pipe_control_clean() {
    control("clean");
}
#[test]
fn status_pipe_control_dirty() {
    control("dirty");
}
#[test]
fn status_pipe_control_silent_held() {
    control("silent-held");
}
#[test]
fn status_pipe_control_header_held() {
    control("header-held");
}
#[test]
fn status_pipe_control_count_held() {
    control("count-held");
}
#[test]
fn status_pipe_control_stderr_held() {
    control("stderr-held");
}

#[test]
#[ignore]
fn status_pipe_worker() {
    let home = PathBuf::from(std::env::var_os("STATUS_PIPE_HOME").expect("worker only"));
    let start = Instant::now();
    let observed = git_state::observe_within(&home, start + Duration::from_millis(400));
    let elapsed_ms = start.elapsed().as_millis() as u64;
    let receipt = match observed {
        Ok(Some(view)) => json!({"kind":"known", "head":view.head, "branch":view.branch,
            "commits":view.commits, "dirty":view.uncommitted, "elapsed_ms":elapsed_ms}),
        Ok(None) => json!({"kind":"absent", "elapsed_ms":elapsed_ms}),
        Err(error) => {
            json!({"kind":"unreadable", "error":format!("{error:?}"), "elapsed_ms":elapsed_ms})
        }
    };
    fs::write(
        home.join("observation.json"),
        serde_json::to_vec(&receipt).unwrap(),
    )
    .unwrap();
}
