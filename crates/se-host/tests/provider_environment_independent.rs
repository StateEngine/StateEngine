//! All provider environment readers discard another session's authority.
#![cfg(feature = "listener")]
use std::{ffi::OsString, process::Command};

const MARKERS: &[&str] = &[
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "CLAUDE_CODE_SESSION_ID",
    "CODEX_THREAD_ID",
    "CODEX_CI",
    "SECODE_SESSION_ID",
    "STATEENGINE_AGENT_ID",
    "STATEENGINE_PROJECT_ID",
    "STATEENGINE_SESSION_ID",
    "STATEENGINE_SEAT_ID",
    "STATEENGINE_SEAT_SURFACE",
    "SE_SESSION",
    "SE_AGENT_ID",
    "SE_PROJECT_ID",
];

/// Protects: no ambient marker becomes a child's provider environment, while
/// ordinary user paths survive. A subprocess avoids process-global env writes.
#[test]
fn every_provider_discards_inherited_identity_and_provider_markers()
-> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--ignored", "--exact", "environment_probe", "--nocapture"])
        .env_clear()
        .env("LAUNCH_JUDGE_CHILD", "synthetic-probe")
        .env("HOME", "synthetic-user-home")
        .env("PATH", "synthetic-user-path");
    #[cfg(windows)]
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    for name in MARKERS {
        command.env(name, format!("synthetic-parent-{name}"));
    }
    // Windows environment names are case-insensitive; Linux also admits the
    // allowlist's case variants, so neither may carry lower-case identities.
    for name in [
        "claudecode",
        "codex_thread_id",
        "stateengine_agent_id",
        "se_session",
    ] {
        command.env(name, "synthetic-parent-lower-case");
    }
    let output = command.output()?;
    assert!(
        output.status.success(),
        "provider environment subprocess: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    Ok(())
}

#[test]
#[ignore = "executed only by the isolated environment subprocess"]
fn environment_probe() {
    assert_eq!(
        std::env::var("LAUNCH_JUDGE_CHILD").as_deref(),
        Ok("synthetic-probe")
    );
    for (provider, environment) in [
        ("Claude", se_host::provider_environment()),
        ("Codex", se_host::codex_input::provider_environment()),
        ("SE Code", se_host::secode_process::provider_environment()),
    ] {
        for marker in MARKERS {
            assert!(
                !environment
                    .iter()
                    .any(|(name, _)| name.to_string_lossy().eq_ignore_ascii_case(marker)),
                "{provider} inherited {marker}"
            );
        }
        for (key, value) in [
            ("HOME", "synthetic-user-home"),
            ("PATH", "synthetic-user-path"),
        ] {
            assert!(environment.contains(&(OsString::from(key), OsString::from(value))));
        }
    }
}
