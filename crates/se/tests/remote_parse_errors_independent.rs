//! Public CLI regression; no store, listener, credential or private-function seam.
use std::process::Command;

/// Bug: malformed remote send selectors bypass the keyed structured stderr channel.
#[test]
fn remote_parse_refusal_retains_key_and_structured_stderr() -> Result<(), Box<dyn std::error::Error>>
{
    let mut failures = Vec::new();
    for (name, target, session, unknown) in [
        ("invalid session", "example/agent-a", "session-review", 0),
        (
            "invalid target",
            "not-a-project-and-agent",
            "00000000-0000-4000-8000-000000000001",
            0,
        ),
        (
            "unknown option before supplied key",
            "example/agent-a",
            "00000000-0000-4000-8000-000000000001",
            1,
        ),
        (
            "unknown option after supplied key",
            "example/agent-a",
            "00000000-0000-4000-8000-000000000001",
            2,
        ),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_se"));
        for (key, _) in std::env::vars_os() {
            if key
                .to_str()
                .is_some_and(|k| k.starts_with("SE_") || k.starts_with("STATEENGINE_"))
            {
                command.env_remove(key);
            }
        }
        command.args([
            "--json",
            "remote",
            "send",
            "--host",
            "box",
            "--target",
            target,
            "--session",
            session,
        ]);
        if unknown == 1 {
            command.arg("--not-an-option");
        }
        command.args(["--key", "original-review-key"]);
        if unknown == 2 {
            command.arg("--not-an-option");
        }
        let output = command.arg("body").output()?;
        let lines = output
            .stderr
            .split(|b| *b == b'\n')
            .filter(|b| !b.is_empty())
            .collect::<Vec<_>>();
        let row = if lines.len() == 1 {
            serde_json::from_slice::<serde_json::Value>(lines[0]).ok()
        } else {
            None
        };
        let correct = output.status.code() == Some(1)
            && output.stdout.is_empty()
            && row.as_ref().is_some_and(|v| {
                v["schema"] == "stateengine.remote-send-status/v1"
                    && v["status"] == "failed"
                    && v["idempotency_key"] == "original-review-key"
            });
        if !correct {
            failures.push(format!(
                "{name}: exit={:?}, stdout={}, stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "remote parse errors must preserve the keyed failure channel: {}",
        failures.join("; ")
    );
    Ok(())
}
