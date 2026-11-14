//! A native executable fixture, compiled by the independent consumer tests.
use std::{
    fs,
    io::{Read, Write},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::PathBuf::from(std::env::var_os("METADATA_FIXTURE_ROOT").ok_or("root")?);
    let args: Vec<String> = std::env::args().skip(1).collect();
    let retain = args.first().is_some_and(|a| a == "--retain");
    let kind = std::env::var("METADATA_FIXTURE_KIND")?;
    let label = if retain { "retainer" } else { "git" };
    fs::write(
        root.join(format!("{label}.pid")),
        std::process::id().to_string(),
    )?;
    if retain || kind == "hang" {
        let end = Instant::now() + Duration::from_secs(45);
        while !root.join("release").exists() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(10));
        }
        return Ok(());
    }
    match kind.as_str() {
        "pipes" => {
            let child = Command::new(std::env::current_exe()?)
                .arg("--retain")
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()?;
            // Deliberately relinquish the child while it retains both output pipes.
            drop(child);
            println!("false");
        }
        "policy" => {
            let mut byte = [0];
            let closed_input = std::io::stdin().read(&mut byte)? == 0;
            let setting = |name: &str, value: &str| std::env::var(name).as_deref() == Ok(value);
            let parameter = |value: &str| args.windows(2).any(|p| p[0] == "-c" && p[1] == value);
            let safe = closed_input
                && setting("GIT_TERMINAL_PROMPT", "0")
                && setting("GIT_ASKPASS", "")
                && setting("SSH_ASKPASS", "")
                && setting("GCM_INTERACTIVE", "false")
                && setting("GIT_OPTIONAL_LOCKS", "0")
                && parameter("core.fsmonitor=false")
                && parameter("core.askPass=")
                && parameter("credential.interactive=false");
            fs::write(root.join("policy"), if safe { "safe" } else { "unsafe" })?;
            if !safe {
                std::process::exit(73);
            }
            println!("true");
        }
        "stdout" | "stderr" => {
            let bytes = vec![b'x'; 65536];
            if kind == "stdout" {
                let _ = std::io::stdout().write_all(&bytes);
            } else {
                let _ = std::io::stderr().write_all(&bytes);
            }
            std::process::exit(128);
        }
        _ => return Err("unknown fixture".into()),
    }
    Ok(())
}
