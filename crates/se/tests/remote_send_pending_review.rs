//! Public CLI: a provisional echo must leave the later setup refusal visible.
use std::{
    io::Write,
    process::{Command, Stdio},
};
#[path = "../../test-support/directory.rs"]
mod directory;

#[test]
fn remote_pending_preserves_refusal_for_json_plain_quiet_and_stdin()
-> Result<(), Box<dyn std::error::Error>> {
    let root = directory::private_directory()?;
    for (json, quiet, stdin) in [
        (true, false, false),
        (true, true, false),
        (false, false, false),
        (true, false, true),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_se"));
        for (key, _) in std::env::vars_os() {
            if key
                .to_str()
                .is_some_and(|s| s.starts_with("SE_") || s.starts_with("STATEENGINE_"))
            {
                command.env_remove(key);
            }
        }
        command
            .current_dir(&root)
            .args(["--home"])
            .arg(root.join("uninitialized"));
        if json {
            command.arg("--json");
        }
        if quiet {
            command.arg("--quiet");
        }
        command.args([
            "remote",
            "send",
            "--host",
            "example",
            "--target",
            "prj_01920e00-7f00-7000-8000-000000000000/ag_01920e00-7f00-7000-8000-000000000000",
            "--session",
            "ses_01920e00-7f00-7000-8000-000000000000",
            "--key",
            "synthetic-review-key",
            if stdin { "-" } else { "synthetic private body" },
        ]);
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::piped());
        let mut child = command.spawn()?;
        if stdin {
            child
                .stdin
                .take()
                .ok_or("stdin missing")?
                .write_all(b"synthetic private body")?;
        }
        let output = child.wait_with_output()?;
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let text = String::from_utf8(output.stderr)?;
        assert!(!text.contains("synthetic private body"));
        if json {
            let rows = text
                .lines()
                .map(serde_json::from_str::<serde_json::Value>)
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[0]["status"], "local_pending");
            assert_eq!(rows[0]["body_bytes"], 22);
            assert_eq!(rows[0]["host_selector"], "example");
            assert_eq!(rows[1]["status"], "failed");
            assert_eq!(rows[1]["error"]["code"], "setup-required");
            assert_eq!(rows[0]["idempotency_key"], "synthetic-review-key");
            assert_eq!(rows[1]["idempotency_key"], rows[0]["idempotency_key"]);
        } else {
            assert!(text.contains("Pending remote send synthetic-review-key"));
            assert!(text.contains("no durable receipt yet"));
            assert!(text.contains("not initialized"));
        }
    }
    Ok(())
}
