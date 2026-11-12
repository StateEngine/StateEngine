//! Bounded short-lived provider RPC with exact replies and joined children.
use super::*;
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{ChildStdin, ChildStdout, Command},
};
const MAX: usize = crate::client::wire::MAX_FRAME_BYTES;

async fn request(writer: &mut ChildStdin, value: Value) -> Result<()> {
    let mut bytes =
        serde_json::to_vec(&value).map_err(|_| invalid("serializable native queue input"))?;
    if bytes.len() > MAX {
        return Err(invalid("native queue input within one MiB"));
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
                return Err(invalid(
                    "a complete native queue response; acceptance is unconfirmed",
                ));
            }
            let end = available.iter().position(|b| *b == b'\n');
            let count = end.map_or(available.len(), |at| at + 1);
            total += count;
            if total > MAX {
                return Err(invalid(
                    "bounded native queue output; acceptance is unconfirmed",
                ));
            }
            line.extend_from_slice(&available[..count]);
            reader.consume(count);
            if end.is_some() {
                break;
            }
        }
        let row: Value = crate::client::wire::decode_json(&line, MAX)?;
        if row.get("id").and_then(Value::as_u64) == Some(id) {
            return row.get("result").cloned().ok_or_else(|| invalid("native queue acceptance; Codex refused the request, so read the StateEngine inbox before another offer"));
        }
        if row.get("id").is_some() || row.get("method").and_then(Value::as_str).is_none() {
            return Err(invalid(
                "the matching native queue reply; acceptance is unconfirmed",
            ));
        }
    }
    Err(invalid(
        "a bounded native queue exchange; acceptance is unconfirmed",
    ))
}

pub(super) fn call(
    executable: std::path::PathBuf,
    config_home: std::path::PathBuf,
    cwd: std::path::PathBuf,
    method: &'static str,
    params: Value,
) -> Result<Value> {
    run(async move {
        let mut command = Command::new(executable);
        command.args(["app-server", "--stdio"]);
        if method == "hooks/list" {
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
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(io)?;
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
        let outcome = tokio::time::timeout(Duration::from_secs(5), exchange).await
            .unwrap_or_else(|_| Err(invalid("a completed native queue exchange; acceptance is unconfirmed and must not be replayed")));
        drop(writer);
        let exit = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
        match exit {
            Ok(Ok(status)) if status.success() => outcome,
            _ => {
                let _ = child.start_kill();
                if !matches!(
                    tokio::time::timeout(Duration::from_secs(1), child.wait()).await,
                    Ok(Ok(_))
                ) {
                    return Err(invalid(
                        "confirmed native helper exit; preserve the mail offer and reconcile its process",
                    ));
                }
                Err(invalid(
                    "successful native helper shutdown; queue acceptance remains unconfirmed",
                ))
            }
        }
    })
}
