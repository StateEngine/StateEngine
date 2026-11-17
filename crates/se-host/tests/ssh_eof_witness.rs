//! Independent pipe reader for the disposable native client fixture.
#![cfg(all(windows, feature = "remote"))]
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
};
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
#[derive(Default, Clone, serde::Serialize)]
struct Pipe {
    bytes: usize,
    eof: bool,
    error: Option<String>,
}
async fn read_pipe(mut reader: impl AsyncRead + Unpin, state: Arc<Mutex<Pipe>>) {
    let mut buffer = [0; 64];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => {
                if let Ok(mut value) = state.lock() {
                    value.eof = true;
                }
                return;
            }
            Ok(n) => {
                if let Ok(mut value) = state.lock() {
                    value.bytes += n;
                }
            }
            Err(error) => {
                if let Ok(mut value) = state.lock() {
                    value.error = Some(error.to_string());
                }
                return;
            }
        }
    }
}
#[tokio::test]
async fn independent_native_reader_witnesses_pipe_state_before_child_exit() -> Check {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/judge-diagnostics")
        .join(format!("ssh-eof-witness-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root)?;
    let normalized = root.canonicalize()?.to_string_lossy().into_owned();
    let root = PathBuf::from(normalized.strip_prefix(r"\\?\").unwrap_or(&normalized));
    let source = root.join("CaptureClient.cs");
    let image = root.join("ssh.exe");
    fs::write(&source, include_bytes!("support/ssh_capture_client.cs"))?;
    let compiler = PathBuf::from(std::env::var_os("SystemRoot").ok_or("SystemRoot absent")?)
        .join("Microsoft.NET/Framework64/v4.0.30319/csc.exe");
    let compiled = std::process::Command::new(compiler)
        .args(["/nologo", "/target:exe"])
        .arg(format!("/out:{}", image.display()))
        .arg(&source)
        .output()?;
    fs::write(root.join("compiler.stdout"), &compiled.stdout)?;
    fs::write(root.join("compiler.stderr"), &compiled.stderr)?;
    if !compiled.status.success() {
        return Err("fixture compilation failed".into());
    }
    let mut child = Command::new(&image)
        .args(["-T", "-o", "BatchMode=yes", "localhost", "closed"])
        .env("SE_SSH_CAPTURE_REVIEW_PIDS", root.join("helper-pids.txt"))
        .env_remove("c28fc6f98a2c44abbbd89d6a3037d0d9_POSIX_FD_STATE")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let pid = child.id().ok_or("child pid absent")?;
    let stdout = child.stdout.take().ok_or("stdout absent")?;
    let stderr = child.stderr.take().ok_or("stderr absent")?;
    let out = Arc::new(Mutex::new(Pipe::default()));
    let err = Arc::new(Mutex::new(Pipe::default()));
    let out_task = tokio::spawn(read_pipe(stdout, out.clone()));
    let err_task = tokio::spawn(read_pipe(stderr, err.clone()));
    tokio::time::sleep(Duration::from_secs(3)).await;
    let alive = child.try_wait()?.is_none();
    let before_out = out.lock().map_err(|_| "stdout lock poisoned")?.clone();
    let before_err = err.lock().map_err(|_| "stderr lock poisoned")?.clone();
    if alive {
        child.start_kill()?;
    }
    let status = child.wait().await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        out_task.await?;
        err_task.await?;
        Ok::<(), tokio::task::JoinError>(())
    })
    .await??;
    let pids = fs::read_to_string(root.join("helper-pids.txt"))?;
    let fields = pids.trim().splitn(3, '|').collect::<Vec<_>>();
    if fields.len() != 3 || fields[0].parse::<u32>()? != pid {
        return Err("helper identity mismatch".into());
    }
    let birth = fields[1].parse::<u64>()?;
    if !fields[2].eq_ignore_ascii_case(&image.to_string_lossy()) {
        return Err("helper image mismatch".into());
    }
    let script = format!(
        "try {{$p=Get-Process -Id {pid} -ErrorAction Stop; @{{state='present';birth=$p.StartTime.ToUniversalTime().ToFileTimeUtc();image=$p.Path}}|ConvertTo-Json -Compress}} catch {{if ($_.FullyQualifiedErrorId -like 'NoProcessFoundForGivenId*') {{@{{state='absent'}}|ConvertTo-Json -Compress}} else {{@{{state='unreadable';error=$_.Exception.Message}}|ConvertTo-Json -Compress}}}}"
    );
    let census = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()?;
    fs::write(root.join("census.stdout"), &census.stdout)?;
    fs::write(root.join("census.stderr"), &census.stderr)?;
    if !census.status.success() {
        return Err("census failed".into());
    }
    let census: Value = serde_json::from_slice(&census.stdout)?;
    let absent = census["state"] == "absent"
        || (census["state"] == "present"
            && census["birth"].as_u64().is_some_and(|value| value != birth));
    let revision = std::process::Command::new("git")
        .args(["-C", env!("CARGO_MANIFEST_DIR"), "rev-parse", "HEAD"])
        .output()?;
    if !revision.status.success() {
        return Err("source revision unreadable".into());
    }
    let receipt = json!({"source":String::from_utf8(revision.stdout)?.trim(),"platform":std::env::consts::OS,"pid":pid,"birth":birth,"helper_image_path":fields[2],"alive_before_cleanup":alive,"stdout_before_cleanup":before_out,"stderr_before_cleanup":before_err,"cleanup_status":status.code(),"outside_census":census,"helper_absent":absent,"test_source_sha256":format!("{:x}",Sha256::digest(include_bytes!("ssh_eof_witness.rs"))),"helper_source_sha256":format!("{:x}",Sha256::digest(include_bytes!("support/ssh_capture_client.cs"))),"helper_image_sha256":format!("{:x}",Sha256::digest(fs::read(&image)?))});
    fs::write(
        root.join("witness.json"),
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    println!("{receipt}");
    if !absent
        || !alive
        || before_out.bytes != 5
        || before_err.bytes != 4
        || before_out.error.is_some()
        || before_err.error.is_some()
    {
        return Err("independent pipe witness did not establish its control".into());
    }
    Ok(())
}
