//! The setup receipt describes the policy of its literal first-launch command.
#![allow(
    dead_code,
    reason = "The production grammar shares compatibility helpers."
)]
#[path = "../src/compat.rs"]
mod compat;
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
#[path = "../src/grammar.rs"]
mod grammar;
use fixture::*;
use se_core::{config_policy::*, ops::AnyOp};
use serde_json::Value;
use std::{fs, io::Write, process::Command};

#[test]
fn init_policy_matches_its_first_launch_for_both_providers_and_explicit_approvals() -> Check {
    for provider in [Provider::Claude, Provider::Codex] {
        for approval in [
            None,
            Some(Approval::OnRequest),
            Some(Approval::Never),
            Some(Approval::Untrusted),
        ] {
            let f = Fixture::new()?;
            let mut config = ConfigFile::default();
            config
                .profiles
                .get_mut("default")
                .ok_or("default profile")?
                .approval = approval;
            let files = se_proc::NativeStateFiles::open(&f.options.state_directory)?;
            let mut staged = files.create_staging(&f.options.state_directory)?;
            staged
                .file
                .write_all(toml::to_string(&config)?.as_bytes())?;
            drop(staged.file);
            files
                .publish_no_replace(&staged.path, &f.options.state_directory.join("config.toml"))?;
            let repo = f.home.join("repo");
            fs::create_dir(&repo)?;
            let provider_name = match provider {
                Provider::Claude => "claude",
                Provider::Codex => "codex",
                Provider::SeCode => "secode",
            };
            let args = [
                "--home",
                f.options.state_directory.to_str().ok_or("home")?,
                "init",
                "--repo",
                repo.to_str().ok_or("repo")?,
                "--provider",
                provider_name,
            ];
            for json in [true, false] {
                let mut command = Command::new(env!("CARGO_BIN_EXE_se"));
                command
                    .args(args)
                    .env_clear()
                    .env("HOME", &f.home)
                    .env("USERPROFILE", &f.home);
                // Winsock needs the system directory even in an isolated test home.
                #[cfg(windows)]
                if let Some(system_root) = std::env::var_os("SystemRoot") {
                    command.env("SystemRoot", system_root);
                }
                if json {
                    command.arg("--json");
                }
                let result = command.current_dir(&repo).output()?;
                assert!(
                    result.status.success(),
                    "init failed: {} {}",
                    String::from_utf8_lossy(&result.stdout),
                    String::from_utf8_lossy(&result.stderr)
                );
                // The command is independently decoded by the real CLI grammar.
                if json {
                    let receipt: Value = serde_json::from_slice(&result.stdout)?;
                    let words = receipt["next"]["argv"]
                        .as_array()
                        .ok_or("first-launch argv")?;
                    let parsed = grammar::parse(
                        words
                            .iter()
                            .map(|word| word.as_str().map(Into::into).ok_or("word"))
                            .collect::<Result<Vec<_>, _>>()?,
                    )
                    .map_err(|e| e.error.to_string())?;
                    let AnyOp::AgentLaunch(launch) = parsed.operation else {
                        return Err("not a launch".into());
                    };
                    assert!(
                        launch.detach,
                        "the first-launch command must support headless setup"
                    );
                    let expected = config.resolve_profile("default", provider, launch.detach)?;
                    assert_eq!(
                        receipt["agent"]["permission_profile"],
                        serde_json::to_value(expected)?,
                        "{provider_name}, {approval:?}"
                    );
                } else {
                    let expected = config.resolve_profile("default", provider, true)?;
                    let label = match expected.approval {
                        Approval::OnRequest => "on-request",
                        Approval::Never => "never",
                        Approval::Untrusted => "untrusted",
                    };
                    assert!(String::from_utf8(result.stdout)?.contains(&format!(
                        "workspace-write, approval {label}, network false, bypass false"
                    )));
                }
            }
        }
    }
    Ok(())
}
