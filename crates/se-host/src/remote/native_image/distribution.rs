//! Native runtime discovery and hashing shared by staging and pairing.
use super::staging;
use crate::remote::{channel::unavailable, ssh::command::ssh};
use se_remote::ssh::validate_destination;
use se_types::{Detail, Result, SeError, details};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;

pub(in crate::remote) struct Image {
    pub file: tokio::fs::File,
    pub expected: u64,
    pub digest: String,
    pub windows: bool,
    pub apple: bool,
}
impl Image {
    pub fn directory(&self) -> String {
        format!(".stateengine-runtime/{}", self.digest)
    }
    pub fn remote(&self) -> String {
        format!(
            "{}/{}",
            self.directory(),
            if self.windows { "se.exe" } else { "se" }
        )
    }
}
pub(in crate::remote) async fn describe(destination: &str, distribution: &Path) -> Result<Image> {
    validate_destination(destination)?;
    // Probe fixed commands, not caller-controlled shell fragments. Neither probe
    // mutates the remote host or stops an incompatible incumbent.
    let probe = ssh(destination, "uname -sm".into()).await?;
    let (unix, platform) = (probe.success, probe.stdout);
    let platform = String::from_utf8(platform)
        .map_err(|_| unavailable("SSH platform response is not UTF-8"))?;
    let uname = platform.trim();
    let (target, windows) = match (unix, uname) {
        (true, "Linux x86_64") => ("x86_64-unknown-linux-gnu", false),
        (true, "Darwin arm64") => ("aarch64-apple-darwin", false),
        (true, "Darwin x86_64") => ("x86_64-apple-darwin", false),
        // A failed uname exit, or a compatibility responder that names no
        // supported Unix target (Git for Windows' uname answers
        // "MSYS_NT-10.0-26100 x86_64"), is verified through the Windows
        // architecture probe before it is rejected.
        _ => {
            let probe = ssh(
                destination,
                staging::powershell(
                    "[System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()",
                ),
            )
            .await?;
            if probe.success && String::from_utf8_lossy(&probe.stdout).trim() == "X64" {
                ("x86_64-pc-windows-msvc", true)
            } else if unix {
                // uname identified a system that is neither a supported Unix
                // target nor a Windows x64 host; reject it by name.
                let named: String = uname.chars().take(60).collect();
                return Err(unavailable(&format!(
                    "remote operating system or architecture is unsupported: {named}"
                )));
            } else {
                return Err(discovery_failure(destination, &probe.stderr_tail));
            }
        }
    };
    // A reused host may itself run from an uploaded single-platform cache.
    // Native Owner admission supplies the calling CLI's full distribution.
    let path = image(target, distribution)?;
    let mut file = tokio::fs::File::open(&path)
        .await
        .map_err(|_| unavailable("matching native distribution image is unreadable"))?;
    let expected = file
        .metadata()
        .await
        .map_err(|_| unavailable("native image size is unreadable"))?
        .len();
    if expected == 0 || expected > 4 * 1024 * 1024 * 1024 {
        return Err(unavailable(
            "native distribution image exceeds its release size bound",
        ));
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut total = 0u64;
    loop {
        let n = file
            .read(&mut buffer)
            .await
            .map_err(|_| unavailable("native image hash read failed"))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > expected {
            return Err(unavailable("native image changed during hash read"));
        }
        digest.update(&buffer[..n]);
    }
    if total != expected {
        return Err(unavailable("native image changed during hash read"));
    }
    let digest = se_types::hex_lower(&digest.finalize());
    let windows_image = windows;
    Ok(Image {
        file,
        expected,
        digest,
        windows: windows_image,
        apple: target.ends_with("apple-darwin"),
    })
}

/// A discovery refusal names the SSH client's own verdict when the client
/// said one; the uninformative fallback stays when stderr carried nothing.
fn discovery_failure(destination: &str, reported: &str) -> SeError {
    if reported.is_empty() {
        return unavailable(
            "remote platform discovery failed; check the SSH destination and supported native platform",
        );
    }
    SeError::new(Detail::ListenerUnavailable(details::ListenerUnavailable {
        subject: "remote machine connection".into(),
        reason: format!("remote platform discovery failed; the SSH client reported: {reported}"),
        next_step: format!(
            "Verify the destination login with `ssh {destination} true`, fix what it reports (key, account or network), then retry the pairing."
        ),
    }))
}

fn image(target: &str, executable: &Path) -> Result<PathBuf> {
    let local = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        _ => {
            return Err(unavailable(
                "this source platform has no native remote distribution",
            ));
        }
    };
    if target == local {
        return Ok(executable.to_path_buf());
    }
    let name = if target.ends_with("windows-msvc") {
        "se.exe"
    } else {
        "se"
    };
    let companion = executable
        .parent()
        .ok_or_else(|| unavailable("native image parent absent"))?
        .join("remote-images")
        .join(target)
        .join(name);
    match companion.try_exists() {
        Ok(true) => Ok(companion),
        Ok(false) => Err(unavailable(
            "the matching native remote image is absent from this distribution",
        )),
        Err(_) => Err(unavailable(
            "the matching native remote image cannot be inspected",
        )),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod review_399_discovery {
    use std::{fs, os::unix::fs::PermissionsExt};
    mod cli_renderer {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../se/src/render/error.rs"));
    }
    #[test]
    fn review_399_discovery_and_render_twins() {
        let root = std::path::PathBuf::from(std::env::var_os("REVIEW_SSH_ROOT").unwrap());
        fs::create_dir(&root).unwrap();
        let script = r#"#!/usr/bin/python3
import os,json,sys
from pathlib import Path
r=Path(os.environ['REVIEW_SSH_ROOT']);mode=(r/'mode').read_text()
with (r/'calls').open('a') as f:print(json.dumps({'argv':sys.argv,'pid':os.getpid(),'birth':Path('/proc/self/stat').read_text().rsplit(') ',1)[1].split()[19]}),file=f)
first=sys.argv[-1]=='uname -sm'
if mode=='both':sys.stderr.buffer.write(b'REVIEW_DENIED publickey\r\n')
elif mode=='first-only' and first:sys.stderr.buffer.write(b'REVIEW_FIRST_ONLY Permission denied (publickey).\n')
elif mode=='hostile':sys.stderr.buffer.write(b'\x1b]0;title\x07\x1b[31mREVIEW_DENIED\x1b[0m\x00\x7f\xff\n')
elif mode=='dns':sys.stderr.buffer.write(b'ssh: Could not resolve hostname review-destination: unavailable\n')
elif mode=='bound':sys.stderr.buffer.write(b'x'*4097)
sys.exit(255)
"#;
        fs::write(root.join("ssh"), script).unwrap();
        fs::set_permissions(root.join("ssh"), fs::Permissions::from_mode(0o700)).unwrap();
        // The outside driver supplies this process's private executable search
        // path before startup; this test never mutates process-global state.
        assert_eq!(std::env::split_paths(&std::env::var_os("PATH").unwrap()).next(), Some(root.clone()));
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let mut failures = Vec::new();
        for (mode, expected, count) in [("both", "REVIEW_DENIED publickey", 2), ("hostile", "REVIEW_DENIED", 2), ("first-only", "REVIEW_FIRST_ONLY", 2), ("empty", "check the SSH destination", 2), ("dns", "could not resolve the host name", 1), ("bound", "bounded bootstrap response", 1)] {
            fs::write(root.join("mode"), mode).unwrap();
            fs::write(root.join("calls"), "").unwrap();
            let error = match runtime.block_on(super::describe("review-destination", &root)) { Err(error) => error, Ok(_) => panic!("failed SSH discovery succeeded") };
            let calls: Vec<serde_json::Value> = fs::read_to_string(root.join("calls")).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect();
            let mut out = Vec::new(); let mut err = Vec::new();
            let code = cli_renderer::write(&error, &se_types::RenderCx::default(), true, &mut out, &mut err).unwrap();
            let cli: serde_json::Value = serde_json::from_slice(&out).unwrap();
            let mcp = crate::mcp::error_value(&error).unwrap();
            let message = error.body.message();
            let closed = calls.iter().all(|call| {
                let pid = call["pid"].as_u64().unwrap();
                match fs::read_to_string(format!("/proc/{pid}/stat")) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
                    Ok(stat) => stat.rsplit_once(") ").unwrap().1.split_whitespace().nth(19).unwrap() != call["birth"].as_str().unwrap(),
                    _ => false,
                }
            });
            let cause = message.contains(expected);
            let remedy = !matches!(mode, "both"|"hostile"|"first-only") || error.body.remedy(&se_types::RenderCx::default()).unwrap().text.contains("ssh review-destination true");
            let passed = cause && remedy && calls.len() == count && closed && code != 0 && cli == mcp && message.bytes().all(|b| b == b' ' || b.is_ascii_graphic());
            println!("REVIEW399 {}", serde_json::json!({"case":mode,"passed":passed,"cause_present":cause,"remedy_present":remedy,"calls":calls.len(),"closed":closed,"cli_mcp_envelopes_equal":cli==mcp,"cli_exit":code,"envelope":cli}));
            if !passed { failures.push(mode); }
        }
        drop(runtime);
        fs::remove_dir_all(&root).unwrap();
        assert!(failures.is_empty(), "discovery cases failed: {failures:?}");
    }
}
