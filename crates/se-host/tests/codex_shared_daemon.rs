//! The stock app-server daemon serves several agents as threads on one login.
//!
//! This drives the real provider daemon, not a stand-in: the shared process is
//! the thing under test, so a fake would only restate our assumptions about it.
//! It is opt-in through `SE_CODEX_DAEMON_SOCKET`, set by a runner that has
//! started a daemon for a disposable login, and names its absence honestly.
#![cfg(unix)]
use se_host::{CallContext, Daemon};
use se_types::Generation;
use std::{error::Error, path::PathBuf, time::Duration};

type Check = Result<(), Box<dyn Error>>;

fn cx() -> Result<CallContext, Box<dyn Error>> {
    Ok(CallContext::new(
        Generation::new(1)?,
        Duration::from_secs(30),
    ))
}

/// An unset variable and an empty one both mean no daemon was named: a runner
/// that clears the variable to say "none" must not be graded as a bad path.
fn socket() -> Option<PathBuf> {
    std::env::var_os("SE_CODEX_DAEMON_SOCKET")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn thread_id(value: &serde_json::Value) -> Result<String, Box<dyn Error>> {
    value["thread"]["id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "a thread id in the provider's answer".into())
}

/// Two agents on one login are two threads in one process, and stopping one
/// never stops the other or the daemon.
#[tokio::test]
async fn two_agents_share_one_daemon_and_stop_independently() -> Check {
    let Some(socket) = socket() else {
        eprintln!("NOT RUN: SE_CODEX_DAEMON_SOCKET names no stock daemon control socket");
        return Ok(());
    };
    let mut first = Daemon::connect(&socket, cx()?).await?;
    let mut second = Daemon::connect(&socket, cx()?).await?;

    let a = thread_id(
        &first
            .request("thread/start", serde_json::json!({ "cwd": "/tmp" }), &cx()?)
            .await?,
    )?;
    let b = thread_id(
        &second
            .request("thread/start", serde_json::json!({ "cwd": "/tmp" }), &cx()?)
            .await?,
    )?;
    assert_ne!(a, b, "two agents must not share one thread");

    // Stop only the first agent's thread; the daemon and the other thread stay.
    first
        .request(
            "thread/archive",
            serde_json::json!({ "threadId": a }),
            &cx()?,
        )
        .await?;
    // The untouched agent keeps working: a fresh thread and a turn on the thread
    // it already owns both still succeed while the first is archived.
    second
        .request("thread/start", serde_json::json!({ "cwd": "/tmp" }), &cx()?)
        .await?;
    second
        .request(
            "turn/start",
            serde_json::json!({
                "threadId": b,
                "input": [{ "type": "text", "text": "reply with the word ok" }],
            }),
            &cx()?,
        )
        .await?;
    Ok(())
}
