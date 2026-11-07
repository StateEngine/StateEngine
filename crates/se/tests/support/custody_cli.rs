//! Execute the actual CLI; uninstall receives a real PTY, never injected admission.
use super::*;
use crate::executable::ExecutableCommand;
use std::{
    process::{Command, Output},
    time::{Duration, Instant},
};

fn command(image: &Path, f: &Fixture) -> Command {
    let mut command = Command::new(image);
    command
        .args(["--json", "--home"])
        .arg(&f.options.state_directory)
        .env("HOME", f.home.join("user-home"))
        .env("USERPROFILE", f.home.join("user-home"))
        .current_dir(f.home.join("repository"));
    for (name, _) in std::env::vars_os() {
        let key = name.to_string_lossy();
        if key.starts_with("SE_")
            || key.starts_with("STATEENGINE_")
            || key.starts_with("CODEX_")
            || key == "CLAUDECODE"
        {
            command.env_remove(name);
        }
    }
    command
}
pub fn printed(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
pub fn json(output: &Output) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    printed(output)
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str(line).ok())
        .ok_or_else(|| format!("missing CLI JSON: {}", printed(output)).into())
}
pub fn checked(
    image: &Path,
    f: &Fixture,
    label: &str,
    args: &[&str],
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let output = command(image, f).args(args).output_executable()?;
    save(f, label, &output)?;
    assert!(output.status.success(), "{label}: {}", printed(&output));
    json(&output)
}
fn save(f: &Fixture, label: &str, output: &Output) -> Check {
    std::fs::write(f.home.join(format!("{label}.stdout")), &output.stdout)?;
    std::fs::write(f.home.join(format!("{label}.stderr")), &output.stderr)?;
    Ok(())
}
pub fn uninstall(image: &Path, f: &Fixture) -> Result<Output, Box<dyn std::error::Error>> {
    let until = Instant::now() + Duration::from_secs(30);
    let mut attempt = 0;
    let output = loop {
        attempt += 1;
        let output = Command::new("/usr/bin/python3")
            .arg("-c")
            .arg(include_str!("custody_terminal.py"))
            .arg(image)
            .arg(&f.options.state_directory)
            .arg(
                until
                    .saturating_duration_since(Instant::now())
                    .as_millis()
                    .to_string(),
            )
            .env("HOME", f.home.join("user-home"))
            .env("USERPROFILE", f.home.join("user-home"))
            .current_dir(f.home.join("repository"))
            .output_executable()?;
        save(f, &format!("uninstall-attempt-{attempt}"), &output)?;
        // The native claim is account-wide even with a private HOME. Only its
        // pre-write contention refusal permits another attempt; all custody
        // and filesystem refusals remain the test's original result.
        let busy = output.status.code() == Some(1)
            && json(&output).is_ok_and(|row| {
                row["code"] == "state-conflict"
                    && row["detail"]["subject"]
                        .as_str()
                        .is_some_and(|subject| subject.starts_with("installation lock "))
                    && row["detail"]["reason"]
                        == "Native installation custody is contended by another operation"
            });
        if !busy || Instant::now() >= until {
            break output;
        }
        std::thread::sleep(
            Duration::from_millis(25).min(until.saturating_duration_since(Instant::now())),
        );
        if Instant::now() >= until {
            break output;
        }
    };
    save(f, "uninstall", &output)?;
    Ok(output)
}
pub fn agent_row<'a>(value: &'a serde_json::Value, agent: &str) -> Option<&'a serde_json::Value> {
    match value {
        serde_json::Value::Object(fields) => {
            if fields.get("id").and_then(serde_json::Value::as_str) == Some(agent)
                && fields.contains_key("session")
            {
                return Some(value);
            }
            fields.values().find_map(|value| agent_row(value, agent))
        }
        serde_json::Value::Array(values) => values.iter().find_map(|value| agent_row(value, agent)),
        _ => None,
    }
}
