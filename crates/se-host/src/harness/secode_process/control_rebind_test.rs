//! Exercise the verified connection against an independent loopback service.
use super::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    time::Duration,
};
#[path = "../../../../test-support/directory.rs"]
mod directory;
type Check = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;
const KEY: &[u8] = b"synthetic-capability-for-test-only";

fn decode_hex(value: &str) -> std::result::Result<Vec<u8>, String> {
    if value.len() != 64 {
        return Err("invalid hex length".into());
    }
    (0..32)
        .map(|i| u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
fn mac(parts: &[&[u8]]) -> std::result::Result<String, String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(KEY).map_err(|e| e.to_string())?;
    for part in parts {
        mac.update(part);
    }
    Ok(se_types::hex_lower(&mac.finalize().into_bytes()))
}
fn read_request(reader: &mut BufReader<TcpStream>) -> std::result::Result<(String, Value), String> {
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    let path = line
        .split_whitespace()
        .nth(1)
        .ok_or("missing request path")?
        .to_owned();
    let mut length = None;
    loop {
        line.clear();
        reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if line == "\r\n" {
            break;
        }
        if let Some((key, value)) = line.split_once(':')
            && key.eq_ignore_ascii_case("content-length")
        {
            length = Some(value.trim().parse::<usize>().map_err(|e| e.to_string())?);
        }
        if line.is_empty() {
            return Err("connection closed".into());
        }
    }
    let mut bytes = vec![0; length.ok_or("missing content length")?];
    reader.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    Ok((
        path,
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())?,
    ))
}
fn respond(reader: &mut BufReader<TcpStream>, body: Value) -> std::result::Result<(), String> {
    let body = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
    let stream = reader.get_mut();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .map_err(|e| e.to_string())?;
    stream.write_all(&body).map_err(|e| e.to_string())
}
fn fixture(
    listener: TcpListener,
    project: String,
    agent: String,
) -> std::result::Result<(), String> {
    let (stream, _) = listener.accept().map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream);
    let (path, challenge) = read_request(&mut reader)?;
    if path != "/api/stateengine/rebind/challenge" {
        return Err("challenge path differs".into());
    }
    let restart = decode_hex(challenge["restart_key"].as_str().ok_or("restart absent")?)?;
    let nonce = decode_hex(challenge["challenge"].as_str().ok_or("challenge absent")?)?;
    let signature = mac(&[b"stateengine.rebind.control/v1", &restart, &nonce])?;
    respond(&mut reader, serde_json::json!({"mac":signature}))?;
    let (path, release) = read_request(&mut reader)?;
    if path != "/api/stateengine/rebind/release"
        || release["project_id"] != project
        || release["agent_id"] != agent
    {
        return Err("release target differs".into());
    }
    let release_restart = decode_hex(release["restart_key"].as_str().ok_or("restart absent")?)?;
    if release_restart != restart {
        return Err("release restart differs".into());
    }
    let nonce = decode_hex(release["nonce"].as_str().ok_or("nonce absent")?)?;
    let expected = mac(&[
        b"stateengine.rebind.release/v1",
        &restart,
        &nonce,
        project.as_bytes(),
        &[0],
        agent.as_bytes(),
    ])?;
    if release["mac"] != expected {
        return Err("release signature differs".into());
    }
    let reply = mac(&[b"stateengine.rebind.released/v1", &restart, &nonce])?;
    respond(
        &mut reader,
        serde_json::json!({"released":true,"mac":reply}),
    )
}

#[tokio::test]
async fn challenge_and_release_share_one_verified_connection() -> Check {
    let root = directory::private_directory().map_err(|error| error.to_string())?;
    let profile = root.join("profile");
    #[cfg(unix)]
    drop(se_proc::NativeStateFiles::create(&profile)?);
    #[cfg(windows)]
    create_private_profile(&profile)?;
    let files = se_proc::NativeProfileFiles::open(&profile)?;
    let mut stage = files.create_staging(&profile)?;
    stage.file.write_all(b"fixture:synthetic-secret\n")?;
    drop(stage.file);
    files.publish_no_replace(&stage.path, &profile.join("basic.credential"))?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = format!("http://{}/", listener.local_addr()?);
    let project = se_types::ProjectId::from_parts(1_700_000_000_001, [1; 10])?;
    let agent = se_types::AgentId::from_parts(1_700_000_000_002, [2; 10])?;
    let task = {
        let project = project.to_string();
        let agent = agent.to_string();
        std::thread::spawn(move || fixture(listener, project, agent))
    };
    let control = super::super::control::Control::for_restart(
        &profile,
        &endpoint,
        Secret::new(KEY.to_vec())?,
        [7; 32],
    )?;
    let deadline = Deadline::from_options(&crate::client::ClientOptions {
        expected_generation: None,
        timeout: Duration::from_secs(10),
        cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    })?;
    let result = control.release_restart(&project, &agent, &deadline).await;
    task.join().map_err(|_| "fixture panicked")??;
    result?;
    Ok(())
}

#[cfg(windows)]
fn create_private_profile(path: &std::path::Path) -> Check {
    let output = std::process::Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command"]).arg(r#"$ErrorActionPreference = 'Stop'
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = [System.Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true, $false)
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.AddAccessRule($rule)
[System.IO.Directory]::CreateDirectory($env:SE_TEST_PROFILE_PATH, $acl) | Out-Null"#).env("SE_TEST_PROFILE_PATH", path).output()?;
    if !output.status.success() {
        return Err(format!(
            "private profile creation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}
