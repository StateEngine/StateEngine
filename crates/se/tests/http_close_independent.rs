//! Public HTTP early-refusal control with a split body larger than read buffers.
use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    path::Path,
    process::{Command, Output},
    time::{Duration, Instant},
};
type Check = Result<(), Box<dyn std::error::Error>>;
#[path = "../../test-support/executable.rs"]
mod executable;
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
#[path = "support/runtime_host.rs"]
mod runtime_host;
use executable::ExecutableCommand;

fn command(image: &Path, home: &Path, json: bool) -> Command {
    let mut cmd = Command::new(image);
    cmd.arg("--home").arg(home);
    if json {
        cmd.arg("--json");
    }
    for (name, _) in std::env::vars_os() {
        let text = name.to_string_lossy();
        if text.starts_with("SE_")
            || text.starts_with("STATEENGINE_")
            || text.starts_with("SECODE_")
            || matches!(text.as_ref(), "CLAUDECODE" | "CODEX_THREAD_ID" | "CODEX_CI")
        {
            cmd.env_remove(name);
        }
    }
    cmd
}
fn checked(output: Output) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    if !output.status.success() {
        return Err(format!(
            "CLI failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn split_body(port: u16, iteration: usize) -> Check {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_secs(2),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    stream.set_nodelay(true)?;
    let body_size = 1024 * 1024;
    let prefix = 256 * 1024;
    let mut first = format!(
        "POST /mcp?access_token=synthetic-invalid HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {body_size}\r\n\r\n"
    ).into_bytes();
    first.resize(first.len() + prefix, b'x');
    let begin = Instant::now();
    stream
        .write_all(&first)
        .map_err(|e| format!("initial-prefix: {e:?}"))?;
    let mut response = Vec::new();
    Read::by_ref(&mut stream)
        .take(16 * 1024)
        .read_to_end(&mut response)
        .map_err(|e| format!("early-response: {e:?}; bytes={}", response.len()))?;
    if response.len() >= 16 * 1024 {
        return Err("response exceeds retained byte bound".into());
    }
    let response = std::str::from_utf8(&response)?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or("complete early response headers absent")?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1));
    if status != Some("400") {
        return Err(format!("early refusal was not 400: {headers}").into());
    }
    let length = headers
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-length")
                .then_some(value.trim())
        })
        .ok_or("early response content length absent")?
        .parse::<usize>()?;
    if length != body.len() {
        return Err("early refusal body was incomplete".into());
    }
    let value: serde_json::Value = serde_json::from_str(body)?;
    if value["error"] != "origin-form target without query required" {
        return Err(format!("early refusal changed reason: {value}").into());
    }
    stream
        .write_all(&vec![b'x'; body_size - prefix])
        .map_err(|e| format!("remaining-body-after-response: {e:?}"))?;
    stream.shutdown(Shutdown::Write)?;
    println!(
        "PUBLIC_CLOSE iteration={iteration} early-status=400 complete-body=true initial-bytes={prefix} remaining-bytes={} elapsed-ms={}",
        body_size - prefix,
        begin.elapsed().as_millis()
    );
    Ok(())
}

#[test]
fn public_early_refusal_survives_split_body_twenty_times() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let f = std::mem::ManuallyDrop::new(fixture::Fixture::new()?);
    let home = &f.options.state_directory;
    let repository = f.home.join("repository");
    std::fs::create_dir(&repository)?;
    let image = f.home.join(if cfg!(windows) {
        "judge-se.exe"
    } else {
        "judge-se"
    });
    std::fs::copy(env!("CARGO_BIN_EXE_se"), &image)?;
    checked(
        command(&image, home, true)
            .args(["init", "--repo"])
            .arg(&repository)
            .output_executable()?,
    )?;
    let config: toml::Value = toml::from_str(&std::fs::read_to_string(home.join("config.toml"))?)?;
    let port = u16::try_from(
        config["runtime"]["listen_port"]
            .as_integer()
            .ok_or("persisted port absent")?,
    )?;
    let host = runtime_host::RunningHost::start(&image, home)?;
    let mut failed = 0;
    for iteration in 1..=20 {
        if let Err(error) = split_body(port, iteration) {
            failed += 1;
            println!("PUBLIC_CLOSE iteration={iteration} failed={error}");
        }
    }
    host.stop()?;
    drop(host);
    drop(std::mem::ManuallyDrop::into_inner(f));
    println!(
        "PUBLIC_CLOSE summary attempted=20 passed={} failed={failed} outside-host-exit=true",
        20 - failed
    );
    if failed != 0 {
        return Err(format!("{failed} of 20 staged public refusals failed").into());
    }
    Ok(())
}
