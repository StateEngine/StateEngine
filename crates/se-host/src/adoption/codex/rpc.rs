//! Bounded short-lived provider RPC with exact replies and joined children.
use super::*;
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{ChildStderr, ChildStdin, ChildStdout, Command},
};
const MAX: usize = crate::client::wire::MAX_FRAME_BYTES;
// Cold discovery measured up to eight seconds under load. Keep its independent
// startup allowance separate from the five-second, non-replayable mail offer.
const DISCOVERY_SECONDS: u64 = 30;
const DISCOVERY_SHUTDOWN_SECONDS: u64 = 10;
const DIAGNOSTIC_BYTES: u64 = 8192;

async fn request(writer: &mut ChildStdin, value: Value) -> Result<()> {
    let mut bytes =
        serde_json::to_vec(&value).map_err(|_| invalid("serializable native provider input"))?;
    if bytes.len() > MAX {
        return Err(invalid("native provider input within one MiB"));
    }
    bytes.push(b'\n');
    writer.write_all(&bytes).await.map_err(io)?;
    writer.flush().await.map_err(io)
}
async fn response(reader: &mut BufReader<ChildStdout>, id: u64) -> Result<Value> {
    let mut total = 0;
    for _ in 0..256 {
        let mut line = Vec::new();
        loop {
            let available = reader.fill_buf().await.map_err(io)?;
            if available.is_empty() {
                return Err(invalid("a complete native provider response"));
            }
            let end = available.iter().position(|b| *b == b'\n');
            let count = end.map_or(available.len(), |at| at + 1);
            total += count;
            if total > MAX {
                return Err(invalid("bounded native provider output"));
            }
            line.extend_from_slice(&available[..count]);
            reader.consume(count);
            if end.is_some() {
                break;
            }
        }
        let row: Value = crate::client::wire::decode_json(&line, MAX)?;
        if row.get("id").and_then(Value::as_u64) == Some(id) {
            return row.get("result").cloned().ok_or_else(|| {
                invalid("a successful native provider request; Codex refused the request")
            });
        }
        if row.get("id").is_some() || row.get("method").and_then(Value::as_str).is_none() {
            return Err(invalid("the matching native provider reply"));
        }
    }
    Err(invalid("a bounded native provider exchange"))
}

pub(super) fn call(
    executable: std::path::PathBuf,
    config_home: std::path::PathBuf,
    cwd: std::path::PathBuf,
    method: &'static str,
    params: Value,
) -> Result<Value> {
    run(async move {
        let discovery = method == "hooks/list";
        let settings = config_home.join("config.toml");
        let mut command = Command::new(executable);
        command.args(["app-server", "--stdio"]);
        if discovery {
            command.arg("--strict-config");
        }
        let mut child = command
            .current_dir(cwd)
            .env_clear()
            .envs(
                crate::harness::codex_input::provider_environment()
                    .into_iter()
                    .filter(|(name, _)| {
                        !name
                            .to_string_lossy()
                            .to_ascii_uppercase()
                            .starts_with("OPENAI_")
                    }),
            )
            .env("CODEX_HOME", config_home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(io)?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| invalid("the native helper diagnostic pipe"))?;
        let diagnostic = tokio::spawn(collect_diagnostics(stderr));
        let mut writer = child
            .stdin
            .take()
            .ok_or_else(|| invalid("the native helper input pipe"))?;
        let mut reader = BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| invalid("the native helper output pipe"))?,
        );
        let exchange = async {
            request(&mut writer, json!({"id":1,"method":"initialize","params":crate::harness::codex_input::initialize()})).await?;
            response(&mut reader, 1).await?;
            request(&mut writer, json!({"method":"initialized"})).await?;
            request(&mut writer, json!({"id":2,"method":method,"params":params})).await?;
            response(&mut reader, 2).await
        };
        let seconds = if discovery { DISCOVERY_SECONDS } else { 5 };
        let mut outcome = tokio::time::timeout(Duration::from_secs(seconds), exchange).await
            .unwrap_or_else(|_| Err(invalid(if discovery {
                "Codex hook discovery within 30 seconds; capture and mail remain unconfirmed"
            } else {
                "a completed native queue exchange; acceptance is unconfirmed and must not be replayed"
            })));
        drop(writer);
        let shutdown = if discovery {
            DISCOVERY_SHUTDOWN_SECONDS
        } else {
            3
        };
        if !matches!(tokio::time::timeout(Duration::from_secs(shutdown), child.wait()).await, Ok(Ok(status)) if status.success())
        {
            let _ = child.start_kill();
            let joined = matches!(
                tokio::time::timeout(Duration::from_secs(1), child.wait()).await,
                Ok(Ok(_))
            );
            if !joined || outcome.is_ok() {
                outcome = Err(invalid(if joined {
                    "successful native helper shutdown"
                } else {
                    "confirmed native helper exit; reconcile the helper process before retrying"
                }));
            }
        }
        let diagnostics = finish_diagnostics(diagnostic).await;
        outcome.map_err(|error| {
            let (subject, next_step) = if discovery {
                ("Codex hook discovery", "Retry se init --adopt --provider codex in this project with the same CODEX_HOME. If Codex rejects configuration or an unknown key, run codex app-server --stdio --strict-config with that CODEX_HOME, correct the reported setting, and retry init.")
            } else {
                ("Codex mail queue", "Acceptance is unconfirmed: preserve the mail offer and read the StateEngine inbox before another offer; do not replay it automatically.")
            };
            SeError::new(se_types::Detail::SourceUnreadable(se_types::details::SourceUnreadable {
                subject: subject.into(), reason: format!("{}: {error}; {diagnostics}", settings.display()), next_step: next_step.into(),
            }))
        })
    })
}

async fn collect_diagnostics(mut stderr: ChildStderr) -> std::io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    let mut block = [0; 4096];
    let mut exceeded = false;
    loop {
        let count = stderr.read(&mut block).await?;
        if count == 0 {
            break;
        }
        if bytes.len() + count <= DIAGNOSTIC_BYTES as usize && !exceeded {
            bytes.extend_from_slice(&block[..count]);
        } else {
            exceeded = true;
        }
    }
    Ok((!exceeded).then_some(bytes))
}
async fn finish_diagnostics(
    mut task: tokio::task::JoinHandle<std::io::Result<Option<Vec<u8>>>>,
) -> String {
    match tokio::time::timeout(Duration::from_secs(1), &mut task).await {
        Ok(Ok(Ok(Some(bytes)))) => String::from_utf8_lossy(&bytes).escape_debug().to_string(),
        Ok(Ok(Ok(None))) => {
            "Provider diagnostics exceeded the 8 KiB bound; inspect the configuration directly."
                .into()
        }
        Err(_) => {
            task.abort();
            let _ = task.await;
            "Provider diagnostics could not be read completely.".into()
        }
        _ => "Provider diagnostics could not be read completely.".into(),
    }
}
