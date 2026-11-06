#![allow(
    dead_code,
    reason = "Shared real native fixture serves other store consumers."
)]
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
#[path = "../src/render/error.rs"]
mod render_error;
use fixture::*;
use se_core::scope;
use se_types::{Read, RenderCx};
static CLI_FIXTURES: std::sync::Mutex<()> = std::sync::Mutex::new(());
use std::{
    path::Path,
    process::{Command, Output},
};

/// Protects: required reads preserve source-specific recovery, checked absence and unknown facts in the real JSON/human error renderer, including after an acknowledged commit.
#[test]
fn read_variants_keep_source_recovery_and_never_claim_rollback() -> Check {
    let remedies = [
        ("committed receipt event", scope::COMMITTED_READ_RECOVERY),
        (
            "runtime endpoint",
            "Run se up for this same home; preserve the original request identity.",
        ),
        (
            "protected credential",
            "Restore the original credential; never generate a replacement.",
        ),
    ];
    for (subject, remedy) in remedies {
        for read in [
            Read::<u8>::Absent {
                checked: "finite outside snapshot checked through sequence 19".into(),
            },
            Read::Unknown {
                what: "the source did not establish presence or absence".into(),
            },
            Read::Unreadable {
                source: "exact native source".into(),
                reason: "access failed".into(),
                error: None,
            },
        ] {
            let absent = matches!(read, Read::Absent { .. });
            let unreadable = matches!(read, Read::Unreadable { .. });
            let error = scope::require_present(read, subject, remedy)
                .err()
                .ok_or("unavailable source became present")?;
            for json in [true, false] {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                let code = render_error::write(
                    &error,
                    &RenderCx::default(),
                    json,
                    &mut stdout,
                    &mut stderr,
                )?;
                assert_ne!(code, 0);
                let human = String::from_utf8(stderr)?;
                assert!(human.contains(remedy), "source remedy lost: {human}");
                assert!(
                    !human.contains("no state was changed")
                        && !human.contains("Select an existing project principal"),
                    "read asserted rollback or the unrelated selector remedy: {human}"
                );
                if absent {
                    assert!(
                        human.contains("checked through sequence 19"),
                        "checked absence was lost: {human}"
                    );
                }
                if unreadable {
                    assert!(
                        human.contains("exact native source") && human.contains("access failed")
                    );
                }
                if json {
                    let value: serde_json::Value = serde_json::from_slice(&stdout)?;
                    assert_eq!(value["detail"]["next_step"], remedy);
                    assert_eq!(
                        value["code"],
                        if unreadable {
                            "source-unreadable"
                        } else {
                            "target-unknown"
                        }
                    );
                    if subject == "committed receipt event" {
                        assert!(
                            value["remedy"]["text"]
                                .as_str()
                                .ok_or("structured remedy")?
                                .contains("The write is committed")
                        );
                    }
                } else {
                    assert!(stdout.is_empty());
                }
            }
        }
    }
    assert_eq!(
        scope::require_present(
            Read::Present { value: 7 },
            "available source",
            "unused remedy"
        )?,
        7
    );
    Ok(())
}
fn command(image: &Path, home: &Path, json: bool) -> Command {
    let mut command = Command::new(image);
    if json {
        command.arg("--json");
    }
    command.arg("--home").arg(home);
    for name in [
        "SE_HOME",
        "SE_PROJECT",
        "SE_CONFIG",
        "SE_LOG",
        "SE_SESSION",
        "CLAUDECODE",
        "CODEX_THREAD_ID",
        "CODEX_CI",
    ] {
        command.env_remove(name);
    }
    command
}
fn checked(output: Output) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    assert!(
        output.status.success(),
        "CLI failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

/// Protects: down on an initialized, unowned home witnesses the absent endpoint without claiming a stop or changing initialized state.
#[test]
fn absent_down_endpoint_names_status_and_preserves_initialized_state() -> Check {
    // The roots are independent; a failed case does not invalidate this
    // serialization primitive or prevent the remaining case from running.
    let _serial = match CLI_FIXTURES.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    use se_store::{ReadStore, StoreFactory};
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let home = &f.options.state_directory;
    let image = f.home.join(if cfg!(windows) { "se.exe" } else { "se" });
    std::fs::copy(env!("CARGO_BIN_EXE_se"), &image)?;
    let root = f.home.join("read-recovery-project");
    std::fs::create_dir(&root)?;
    checked(
        command(&image, home, true)
            .arg("init")
            .arg("--repo")
            .arg(root)
            .output_executable()?,
    )?;
    let reader = present(se_store::SqliteFactory::open_reader(&f.options)?)?;
    let before = reader.info()?.head;
    let identity = std::fs::read(home.join("machine.json"))?;
    let credential = std::fs::read(home.join("credential"))?;
    for json in [true, false] {
        let output = command(&image, home, json)
            .arg("down")
            .output_executable()?;
        assert!(output.status.success(), "{output:?}");
        let diagnostic = String::from_utf8_lossy(&output.stdout);
        assert!(
            diagnostic.contains("absent endpoint"),
            "missing endpoint observation: {diagnostic}"
        );
        assert!(!diagnostic.contains("Select an existing project principal"));
        if json {
            let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            assert_eq!(value["complete"], true);
            assert_eq!(value["already_down"], true);
            assert_eq!(value["stops"], serde_json::json!([]));
            assert_eq!(value["witness"]["state"], "witnessed");
            assert_eq!(
                value["witness"]["detail"],
                "Already down; no host was running. No process was stopped."
            );
        } else {
            assert!(diagnostic.contains("Already down; no host was running."));
            assert!(diagnostic.contains("No process was stopped."));
        }
        assert_eq!(reader.info()?.head, before);
        assert_eq!(std::fs::read(home.join("machine.json"))?, identity);
        assert_eq!(std::fs::read(home.join("credential"))?, credential);
        assert!(!home.join("endpoint.json").try_exists()?);
    }
    Ok(())
}

#[cfg(unix)]
#[path = "support/runtime_host.rs"]
mod runtime_host;

/// Protects: mismatched stale endpoint recovery reaches the actual se up user, preserves the foreign live socket, and permits restart after moving only the record under the same home lease.
#[cfg(unix)]
#[test]
fn stale_address_cli_names_lease_safe_recovery_and_preserves_foreign_socket() -> Check {
    // The roots are independent; a failed case does not invalidate this
    // serialization primitive or prevent the remaining case from running.
    let _serial = match CLI_FIXTURES.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    use std::{io::Write, os::unix::fs::MetadataExt};
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let home = &f.options.state_directory;
    let image = f.home.join("endpoint-se");
    std::fs::copy(env!("CARGO_BIN_EXE_se"), &image)?;
    let repository = f.home.join("repository");
    std::fs::create_dir(&repository)?;
    checked(
        command(&image, home, true)
            .arg("init")
            .arg("--repo")
            .arg(repository)
            .output_executable()?,
    )?;
    let first = runtime_host::RunningHost::start(&image, home)?;
    let mut record =
        se_host::client::endpoint::decode_endpoint(&std::fs::read(home.join("endpoint.json"))?)?;
    first.stop()?;
    assert!(!home.join("endpoint.json").try_exists()?);
    let foreign_directory = f.home.join("foreign-runtime");
    drop(se_proc::NativeStateFiles::create(&foreign_directory)?);
    let foreign_path = foreign_directory.join("foreign.sock");
    let foreign = se_proc::native_ipc::NativeUnixEndpoint::bind(&foreign_path)?;
    foreign.listener().set_nonblocking(true)?;
    let before = std::fs::symlink_metadata(&foreign_path)?;
    record.address =
        se_host::IpcEndpoint::UnixSocket(se_types::NativePath::from_local(foreign_path.clone())?);
    let bytes = se_host::client::endpoint::encode_endpoint(&record)?;
    let files = se_proc::NativeStateFiles::open(home)?;
    let machine = std::fs::read(home.join("machine.json"))?;
    let credential = std::fs::read(home.join("credential"))?;
    for json in [true, false] {
        let mut staged = files.create_staging(home)?;
        staged.file.write_all(bytes.as_bytes())?;
        staged.file.sync_all()?;
        drop(staged.file);
        files.publish_no_replace(&staged.path, &home.join("endpoint.json"))?;
        let output = command(&image, home, json).arg("up").output_executable()?;
        let after = std::fs::symlink_metadata(&foreign_path)?;
        assert_eq!(
            (after.dev(), after.ino(), after.mode()),
            (before.dev(), before.ino(), before.mode())
        );
        match foreign.listener().accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
            Ok((mut stream, _)) => {
                stream.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
                assert_eq!(
                    std::io::Read::read(&mut stream, &mut [0; 1])?,
                    0,
                    "refusal sent application data to the wrong native peer"
                );
            }
            Err(error) => return Err(error.into()),
        }
        assert_eq!(std::fs::read(home.join("machine.json"))?, machine);
        assert_eq!(std::fs::read(home.join("credential"))?, credential);
        if output.status.success() {
            // Safe automatic recovery under the lease is also a legal outcome.
            runtime_host::RunningHost::start(&image, home)?.stop()?;
        } else {
            assert_eq!(std::fs::read(home.join("endpoint.json"))?, bytes.as_bytes());
            let printed = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                printed.contains("move only")
                    && printed.contains("runtime.lock")
                    && printed.contains("endpoint.json")
                    && printed.contains("mismatched address"),
                "actual se up lost lease-safe endpoint recovery: {printed}"
            );
            let lock = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(home.join("runtime.lock"))?;
            lock.try_lock()?;
            std::fs::rename(
                home.join("endpoint.json"),
                home.join(if json {
                    "json-endpoint.saved"
                } else {
                    "human-endpoint.saved"
                }),
            )?;
            drop(lock);
            runtime_host::RunningHost::start(&image, home)?.stop()?;
        }
        assert!(home.join("state.db").try_exists()?);
        assert!(!home.join("endpoint.json").try_exists()?);
        assert_eq!(
            std::fs::symlink_metadata(&foreign_path)?.ino(),
            before.ino()
        );
    }
    foreign.close()?;
    Ok(())
}

#[path = "../../test-support/executable.rs"]
mod executable;
use executable::ExecutableCommand;
