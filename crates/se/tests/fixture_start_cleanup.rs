//! A failed test observation must not orphan the real detached runtime it started.
#![cfg(target_os = "linux")]
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};
type Check = Result<(), Box<dyn std::error::Error>>;
#[path = "../../test-support/executable.rs"]
mod executable;
#[path = "support/runtime_host.rs"]
mod runtime_host;
use executable::ExecutableCommand;

fn command(image: &Path, home: &Path, json: bool) -> Command {
    let mut command = Command::new(image);
    command.arg("--home").arg(home);
    if json {
        command.arg("--json");
    }
    for (name, _) in std::env::vars_os() {
        let text = name.to_string_lossy();
        if text.starts_with("SE_")
            || text.starts_with("STATEENGINE_")
            || text.starts_with("CODEX")
            || text.starts_with("CLAUDE")
        {
            command.env_remove(name);
        }
    }
    command
}
fn checked(output: std::process::Output) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    assert!(output.status.success(), "CLI: {output:?}");
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[test]
/// Protects: failed reply parsing and a panicked native observation close the published fixture host while retaining its state for diagnosis.
/// Bug: a detached host could be committed before RunningHost existed to clean up a failed startup observation.
fn failed_reply_and_panicked_observation_close_the_published_host_but_keep_its_home() -> Check {
    let root = std::env::temp_dir().join(format!(
        "se-start-cleanup-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let image = root.join("se");
    fs::copy(env!("CARGO_BIN_EXE_se"), &image)?;
    for corrupt_reply in [true, false] {
        let case = root.join(if corrupt_reply {
            "reply"
        } else {
            "observation"
        });
        fs::create_dir(&case)?;
        let repo = case.join("repo");
        fs::create_dir(&repo)?;
        let home = case.join("state");
        checked(
            command(&image, &home, true)
                .args(["init", "--repo"])
                .arg(&repo)
                .output_executable()?,
        )?;
        let wrapper = case.join("reply-wrapper");
        let observed_endpoint = case.join("published.json");
        fs::write(
            &wrapper,
            format!(
                "#!/usr/bin/python3\nimport pathlib,subprocess,sys\na=sys.argv[1:]\nr=subprocess.run([{},*a],capture_output=True)\nif a[-1]=='up' and r.returncode==0:\n pathlib.Path({}).write_bytes(pathlib.Path({}).read_bytes())\n sys.stdout.buffer.write(b'broken reply\\n' if {} else r.stdout)\nelse: sys.stdout.buffer.write(r.stdout)\nsys.stderr.buffer.write(r.stderr)\nsys.exit(r.returncode)\n",
                serde_json::to_string(&image)?,
                serde_json::to_string(&observed_endpoint)?,
                serde_json::to_string(&home.join("endpoint.json"))?,
                if corrupt_reply { "True" } else { "False" }
            ),
        )?;
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))?;
        // The normal reply deliberately names a different executable from the
        // wrapper, so the existing outside-observer assertion must panic.
        let failure =
            std::panic::catch_unwind(|| runtime_host::RunningHost::start(&wrapper, &home));
        let refused = match failure {
            Ok(result) => result.is_err(),
            Err(_) => true,
        };
        let endpoint = se_host::client::endpoint::decode_endpoint(&fs::read(&observed_endpoint)?)?;
        let expected = endpoint.epoch.owner.fields();
        let se_types::StartIdentity::Linux { start_ticks } = expected.started else {
            return Err("fixture runtime has a foreign native start".into());
        };
        let closed = !home.join("endpoint.json").try_exists()?;
        // Always close even the before-fix counterexample before asserting.
        if !closed {
            checked(
                command(&image, &home, true)
                    .arg("down")
                    .output_executable()?,
            )?;
        }
        let observed = se_proc::NativeProcessRuntime::read_process_until(
            expected.machine.clone(),
            se_proc::ProcessId(expected.pid.get()),
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .map_err(|error| format!("outside cleanup observation: {error:?}"))?;
        assert!(
            !matches!(observed, se_proc::ProcessRead::Present(ref p)
                if p.identity.start == (se_proc::StartIdentity::Linux { start_ticks }) && !matches!(p.state,
                    se_proc::NativeState::Exited | se_proc::NativeState::ExitedAwaitingReap)),
            "fixture birth remains live: {observed:?}"
        );
        let lease = fs::File::open(home.join("runtime.lock"))?;
        lease.try_lock()?;
        drop(lease);
        assert!(
            home.join("state.db").try_exists()?,
            "failure home was removed"
        );
        assert!(
            refused,
            "fixture accepted the deliberately invalid observation"
        );
        assert!(
            closed,
            "failed startup left a detached host without a cleanup owner"
        );
    }
    fs::remove_dir_all(root)?;
    Ok(())
}
