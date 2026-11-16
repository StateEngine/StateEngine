//! Public command judges for native executable-copy cleanup and crash recovery.
use super::*;

fn run_case(mode: &str) -> Check {
    installation_account::require()?;
    let _serial = RUNTIME
        .lock()
        .map_err(|_| "runtime fixture mutex poisoned")?;
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let home = &f.options.state_directory;
    let repo = f.home.join("repository");
    std::fs::create_dir(&repo)?;
    std::fs::write(repo.join("user-work.txt"), b"retained user work")?;
    let host = f.home.join("outside-se.exe");
    let installed = f.home.join("installed-se.exe");
    std::fs::copy(env!("CARGO_BIN_EXE_se"), &host)?;
    std::fs::copy(&host, &installed)?;
    checked(
        command(&host, home, true)
            .arg("init")
            .arg("--repo")
            .arg(&repo)
            .args(["--name", "uninstall-finalizer"])
            .output_executable()?,
    )?;
    let owner = se_proc::observe_owner_self(&[])?;
    let se_proc::NativeOwner::Windows { sid } = owner.owner() else {
        return Err("native Windows owner absent".into());
    };
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schema":"stateengine-install/v1", "owner":sid,
        "files":[{"path":installed,"sha256":format!("{:x}", Sha256::digest(std::fs::read(&installed)?))}],
        "created_directories":[],"path_edits":[]
    }))?;
    let files = se_proc::NativeStateFiles::open(home)?;
    let mut stage = files.create_staging(home)?;
    stage.file.write_all(&manifest)?;
    stage.file.sync_all()?;
    drop(stage.file);
    files.publish_no_replace(&stage.path, &home.join("standalone-install.json"))?;
    let script = f.home.join("uninstall_finalizer.py");
    std::fs::write(&script, include_str!("uninstall_finalizer.py"))?;
    std::fs::write(
        f.home.join("uninstall_debugger.py"),
        include_str!("uninstall_debugger.py"),
    )?;
    let mut run = Command::new("python");
    run.arg("-I")
        .arg(script)
        .arg(mode)
        .arg(&f.home)
        .arg(home)
        .arg(host)
        .arg(installed);
    for name in [
        "SE_SESSION",
        "SE_CONFIG",
        "SE_PROJECT",
        "SE_LOG",
        "SE_HOME",
        "CLAUDECODE",
        "CODEX_THREAD_ID",
        "CODEX_CI",
    ] {
        run.env_remove(name);
    }
    let output = run.output_executable()?;
    eprintln!(
        "native uninstall judge report: {}",
        String::from_utf8_lossy(&output.stdout).trim()
    );
    if !output.status.success() {
        // Return normally so a witnessed product failure does not poison the
        // fixture mutex and suppress the remaining independent cases.
        return Err(format!(
            "native uninstall {mode} judge failed: {}; {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(
        f.home.join("uninstall-finalizer-report.json"),
    )?)?;
    if report["qualified"] != true {
        return Err(format!("native uninstall judge did not qualify: {report}").into());
    }
    Ok(())
}

/// Protects: READONLY on the real original and actual private child image must
/// not leave executable staging or its durable cleanup debt after native exit.
#[test]
fn readonly_original_and_private_copy_reach_final_absence() -> Check {
    run_case("readonly")
}

/// Protects: an interrupted native carrier leaves discoverable exact-object
/// custody, and the next ordinary status command retires its read-only copy.
#[test]
fn killed_carrier_is_recovered_by_the_next_ordinary_status() -> Check {
    run_case("killed-recovery")
}

/// Protects: replacing the original installation during handoff preserves the
/// new executable and ownership record byte-for-byte while staging is retired.
#[test]
fn replacement_install_survives_the_original_carrier() -> Check {
    run_case("replacement-install")
}

/// Protects: ordinary recovery cannot use an old staging pathname as authority
/// to delete a replacement; both replacement bytes and cleanup debt remain.
#[test]
fn replacement_private_copy_preserves_bytes_and_recovery_debt() -> Check {
    run_case("killed-replacement")
}

pub(super) fn wait_for_final_absence(home: &Path, image: &Path, record: &Path) -> Check {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        let mut remaining = Vec::new();
        for path in [
            image.to_owned(),
            record.to_owned(),
            home.join("uninstall-helper-cleanup.json"),
        ] {
            match std::fs::symlink_metadata(&path) {
                Ok(_) => remaining.push(path),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
        }
        copies(home, true, &mut remaining)?;
        if remaining.is_empty() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("final uninstall artifacts remain: {remaining:?}").into());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn copies(
    root: &Path,
    elevated_directories: bool,
    remaining: &mut Vec<std::path::PathBuf>,
) -> Check {
    use std::os::windows::fs::MetadataExt;
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with(".se-stage-") && name.ends_with(".exe") {
            remaining.push(entry.path());
        } else if elevated_directories && name.starts_with(".se-uninstall-") {
            remaining.push(entry.path());
            let metadata = match std::fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            if metadata.file_attributes() & 0x400 != 0 || !metadata.is_dir() {
                return Err("uninstall staging directory was replaced; preserve it".into());
            }
            copies(&entry.path(), false, remaining)?;
        }
    }
    Ok(())
}
