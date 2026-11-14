use std::process::Command;

/// Protects: a valid completion endpoint is output-only and cannot let an agent
/// invoke uninstall, create the selected home, or obtain a deferred-success code.
#[test]
fn completion_channel_does_not_bypass_public_human_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let home = std::env::temp_dir().join(format!("se-refused-uninstall-{}", uuid::Uuid::new_v4()));
    assert!(!home.try_exists()?);
    let output = Command::new(env!("CARGO_BIN_EXE_se"))
        .args(["--json", "--home"])
        .arg(&home)
        .arg("uninstall")
        .env("SE_SESSION", "uninstall-completion-agent")
        .env(
            "SE_UNINSTALL_COMPLETION_PIPE",
            format!("stateengine-uninstall-{}", "a".repeat(32)),
        )
        .env("SE_UNINSTALL_COMPLETION_TOKEN", "b".repeat(64))
        .env_remove("SE_CONFIG")
        .env_remove("SE_PROJECT")
        .output()?;
    let reply: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(reply["code"], "owner-required", "{output:?}");
    assert!(!output.status.success());
    assert_ne!(output.status.code(), Some(75));
    assert!(
        !home.try_exists()?,
        "refused output-channel request created fixture home {}",
        home.display()
    );
    Ok(())
}
