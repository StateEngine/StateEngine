//! An account-free native provider process, executed only by the product helper.
use super::*;
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    process::{Command, Stdio},
};
#[test]
#[ignore = "private native provider, invoked through ProcessRuntime only"]
fn controlled_provider() -> Check {
    let root = root()?;
    let pin = native::pin(ProcessId(std::process::id()))?;
    json(root.join("pin-provider.json"), &pin)?;
    let mut executions = OpenOptions::new()
        .append(true)
        .create(true)
        .open(root.join("executions"))?;
    writeln!(executions, "{}", std::process::id())?;
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let fd: i32 = std::env::var("SE_MACOS_SENTINEL")?.parse()?;
    // SAFETY: read-only query, no descriptor ownership is acquired.
    let inherited = unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0;
    json(
        root.join("provider.json"),
        &serde_json::json!({
            "input": input, "inherited_descriptor": inherited,
            "ambient_inherited": std::env::var_os("SE_MACOS_AMBIENT").is_some(),
            "cwd": std::env::current_dir()?,
        }),
    )?;
    println!("SELECTED-PROVIDER-OUTPUT");
    eprintln!("SELECTED-PROVIDER-ERROR");
    std::io::stdout().flush()?;
    std::io::stderr().flush()?;
    let child = if root.join("make-child").exists() {
        let child = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "fixture::provider::tracked_child",
                "--ignored",
                "--nocapture",
            ])
            .env_clear()
            .env("SE_MACOS_JUDGE_ROOT", &root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        Some(child)
    } else {
        None
    };
    while !root.join("exit-root").exists() {
        std::thread::sleep(Duration::from_millis(5));
    }
    // The cold-exited-root case deliberately leaves its observed child alive.
    drop(child);
    Ok(())
}
#[test]
#[ignore = "private descendant of the controlled native provider"]
fn tracked_child() -> Check {
    let root = root()?;
    json(
        root.join("pin-child.json"),
        &native::pin(ProcessId(std::process::id()))?,
    )?;
    let mut escaped = false;
    loop {
        if !escaped && root.join("escape").exists() {
            // SAFETY: this exact fixture child moves itself, never another process.
            if unsafe { libc::setsid() } < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            fs::write(root.join("escaped"), b"escaped")?;
            escaped = true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
