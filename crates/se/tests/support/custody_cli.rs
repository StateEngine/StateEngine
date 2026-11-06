//! Execute the actual CLI; uninstall receives a real PTY, never injected admission.
use super::*;
use crate::executable::ExecutableCommand;
use std::process::{Command, Output};

fn command(image: &Path, f: &Fixture) -> Command {
    let mut command = Command::new(image);
    command
        .args(["--json", "--home"])
        .arg(&f.options.state_directory)
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
    let output = Command::new("/usr/bin/python3")
        .arg("-c")
        .arg(include_str!("custody_terminal.py"))
        .arg(image)
        .arg(&f.options.state_directory)
        .current_dir(f.home.join("repository"))
        .output_executable()?;
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
