//! A short-lived native stdio client offers mail without putting bodies or
//! credentials in process arguments. Queue acceptance is never recipient read.
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

pub fn offer(
    registration: &Registration,
    conversation: &se_types::ProviderSessionId,
    frame: &Value,
) -> Result<()> {
    let executable = registration.provider.to_local()?;
    let config_home = registration.config_home.to_local()?;
    let text =
        serde_json::to_string(frame).map_err(|_| invalid("serializable native mail offer"))?;
    let conversation = conversation.to_string();
    // The outer protected offer journal is committed before this call. The
    // provider does not deduplicate client IDs: unknown acceptance must never
    // cause automatic replay, even with an unchanged client message identity.
    let mut hash = Sha256::new();
    hash.update(b"codex-observed-mail/v1");
    hash.update(&conversation);
    hash.update(&text);
    let client_id = format!("se-mail-{}", se_types::hex_lower(&hash.finalize()));
    run(async move {
        let mut child = Command::new(executable)
            .args(["app-server", "--stdio"])
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
            let input = json!([{"type":"text","text":text,"text_elements":[]}]);
            request(
                &mut writer,
                json!({"id":2,"method":"thread/queue/add","params":{
                    "threadId":conversation,"clientUserMessageId":client_id,"input":input
                }}),
            )
            .await?;
            let result = response(&mut reader, 2).await?;
            let queued = result
                .get("queuedSubmission")
                .ok_or_else(|| invalid("a native queue receipt; acceptance is unconfirmed"))?;
            if queued.get("clientUserMessageId").and_then(Value::as_str) != Some(&client_id)
                || queued.get("input") != Some(&input)
                || !queued.get("id").and_then(Value::as_str).is_some_and(|id| {
                    !id.is_empty() && id.len() <= 512 && !id.chars().any(char::is_control)
                })
            {
                return Err(invalid(
                    "an exact native queue receipt; acceptance is unconfirmed",
                ));
            }
            Ok(())
        };
        let outcome = tokio::time::timeout(Duration::from_secs(5), exchange).await
            .unwrap_or_else(|_| Err(invalid("a completed native queue exchange; acceptance is unconfirmed and must not be replayed")));
        drop(writer);
        let exit = tokio::time::timeout(Duration::from_millis(500), child.wait()).await;
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
