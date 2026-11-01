//! Public CLI output after the kernel refuses escape from an actual strict job.
#![cfg(windows)]
use std::{
    error::Error,
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
fn clear(command: &mut Command) {
    for key in [
        "SE_HOME",
        "SE_CONFIG",
        "SE_PROJECT",
        "SE_SESSION",
        "CLAUDECODE",
        "CODEX_THREAD_ID",
        "CODEX_CI",
    ] {
        command.env_remove(key);
    }
}
#[test]
fn strict_job_reports_named_refusal_and_legal_alternatives_in_json_and_plain_output() -> Result {
    se_proc::initialize_file_creation_owner()?;
    let root = std::env::temp_dir().join(format!(
        "se-job-refusal-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    drop(se_proc::NativeStateFiles::create(&root)?);
    // Cargo hard-links its binary into deps; native runtime pinning requires
    // the same single-link executable layout as an installed archive.
    let executable = root.join("se.exe");
    fs::copy(env!("CARGO_BIN_EXE_se"), &executable)?;
    let home = root.join("state");
    let repo = root.join("repo");
    fs::create_dir(&repo)?;
    let mut init = Command::new(&executable);
    clear(&mut init);
    let initialized = init
        .arg("--home")
        .arg(&home)
        .args(["--json", "init", "--repo"])
        .arg(&repo)
        .output()?;
    assert!(
        initialized.status.success(),
        "real init failed; retained fixture {}: stdout={} stderr={}",
        root.display(),
        String::from_utf8_lossy(&initialized.stdout),
        String::from_utf8_lossy(&initialized.stderr)
    );
    let script = root.join("strict-job.ps1");
    fs::write(&script, include_str!("support/strict_job.ps1"))?;
    let powershell = se_proc::windows_directory()
        .map_err(|error| format!("native Windows directory: {error:?}"))?
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let mut run = Command::new(powershell);
    clear(&mut run);
    let result = run
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(script)
        .arg("-Se")
        .arg(&executable)
        .arg("-HomePath")
        .arg(&home)
        .arg("-Out")
        .arg(&root)
        .output()?;
    assert!(
        result.status.success(),
        "strict-job fixture failed; retained {}: {} {}",
        root.display(),
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    for mode in ["json", "plain"] {
        assert_eq!(
            fs::read_to_string(root.join(format!("{mode}.exit")))?.trim(),
            "1",
            "refusal must use Refused exit status"
        );
        let stdout = fs::read(root.join(format!("{mode}.stdout")))?;
        let stderr = fs::read_to_string(root.join(format!("{mode}.stderr")))?;
        assert!(
            stderr.contains("job-breakaway-refused") && stderr.contains("caller process PID"),
            "lost actual native refusal: {stderr}"
        );
        assert!(
            stderr.contains("outside") && stderr.contains("JOB_OBJECT_LIMIT_BREAKAWAY_OK"),
            "lost legal alternatives: {stderr}"
        );
        assert!(
            !stderr.contains("restore access"),
            "native refusal was misreported as unreadable storage"
        );
        if mode == "json" {
            let value: serde_json::Value = serde_json::from_slice(&stdout)?;
            assert_eq!(value["code"], "job-breakaway-refused", "{value}");
            assert!(value.to_string().contains("caller process PID"));
        } else {
            assert!(stdout.is_empty(), "human refusal contaminated stdout");
        }
        println!("PASS {mode}: actual strict job, named native refusal, legal alternative");
    }
    assert!(
        !home.join("endpoint.json").try_exists()?,
        "refusal published a live host endpoint"
    );
    fs::remove_dir_all(root)?;
    Ok(())
}
