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

/// A request must be refused at its own deadline even while the peer keeps
/// sending frames; a shared daemon serves other agents, so their traffic must not
/// refresh this caller's clock. The peer here is deliberately silent after the
/// greeting: that is the one behaviour under test, and the real daemon cannot be
/// made to hang on demand.
#[cfg(unix)]
#[tokio::test]
async fn a_silent_daemon_cannot_extend_one_callers_deadline() -> Check {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let directory = std::env::temp_dir().join(format!(
        "se-daemon-deadline-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory)?;
    let path = directory.join("control.sock");
    let listener = tokio::net::UnixListener::bind(&path)?;
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut socket = tokio_tungstenite::accept_async(stream).await?;
        // Answer the greeting, then never answer the next request while keeping
        // unrelated frames arriving for far longer than its deadline. This is the
        // shape that used to re-arm the caller's clock on every frame.
        while let Some(message) = socket.next().await {
            let Ok(Message::Text(text)) = message else {
                continue;
            };
            let value: serde_json::Value = serde_json::from_str(&text)?;
            if value.get("method").and_then(|m| m.as_str()) == Some("initialize") {
                let reply = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": value["id"].clone(),
                    "result": { "userAgent": "silent-peer/1" },
                });
                socket.send(Message::text(reply.to_string())).await?;
                continue;
            }
            // Any other request is never answered; only traffic keeps arriving.
            if value.get("method").is_some() {
                // An unanswered request: sustain traffic for about six seconds.
                for index in 0..60 {
                    let note = serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "item/agentMessage/delta",
                        "params": { "delta": index.to_string() },
                    });
                    socket.send(Message::text(note.to_string())).await?;
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                return Ok::<_, Box<dyn Error + Send + Sync>>(());
            }
        }
        Ok(())
    });

    let mut daemon = Daemon::connect(&path, cx()?).await?;
    let tight = CallContext::new(Generation::new(1)?, Duration::from_millis(400));
    let started = std::time::Instant::now();
    let outcome = daemon
        .request("stateengine/never-answered", serde_json::json!({}), &tight)
        .await;
    let elapsed = started.elapsed();
    assert!(outcome.is_err(), "an unanswered request must be refused");
    assert!(
        elapsed < Duration::from_secs(2),
        "one call took {elapsed:?}; a busy peer must not extend its deadline"
    );
    peer.abort();
    let _ = std::fs::remove_dir_all(&directory);
    Ok(())
}

/// A daemon that ends mid-call is a named stopped state with a relaunch step,
/// not a usage mistake: the person using the agent needs to know the login's
/// process is gone, and that the conversation was not silently moved.
#[cfg(unix)]
#[tokio::test]
async fn daemon_death_is_a_named_state_with_a_relaunch_step() -> Check {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let directory = std::env::temp_dir().join(format!(
        "se-daemon-ended-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory)?;
    let path = directory.join("control.sock");
    let listener = tokio::net::UnixListener::bind(&path)?;
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut socket = tokio_tungstenite::accept_async(stream).await?;
        while let Some(message) = socket.next().await {
            let Ok(Message::Text(text)) = message else {
                continue;
            };
            let value: serde_json::Value = serde_json::from_str(&text)?;
            if value.get("method").and_then(|m| m.as_str()) == Some("initialize") {
                let reply = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": value["id"].clone(),
                    "result": { "userAgent": "ending-peer/1" },
                });
                socket.send(Message::text(reply.to_string())).await?;
            } else if value.get("method").is_some() {
                // The process ends while this request is still outstanding.
                socket.close(None).await?;
                return Ok::<_, Box<dyn Error + Send + Sync>>(());
            }
        }
        Ok(())
    });

    let mut daemon = Daemon::connect(&path, cx()?).await?;
    let error = match daemon
        .request("thread/start", serde_json::json!({ "cwd": "/tmp" }), &cx()?)
        .await
    {
        Ok(_) => return Err("a request to an ended daemon must be refused".into()),
        Err(error) => error,
    };
    let se_types::Detail::ProviderIncompatible(failure) = error.body.detail() else {
        return Err(format!(
            "expected a named provider state, got {:?}",
            error.body.detail()
        )
        .into());
    };
    assert!(
        failure.reason.contains("app-server stopped"),
        "the reason names what happened: {}",
        failure.reason
    );
    assert!(
        failure.next_step.to_lowercase().contains("relaunch"),
        "the step says what a person can do: {}",
        failure.next_step
    );
    peer.abort();
    let _ = std::fs::remove_dir_all(&directory);
    Ok(())
}

/// Ownership is decided by the socket, and absent, refused and live are three
/// different answers: only a live daemon makes the login someone else's.
#[cfg(unix)]
#[tokio::test]
async fn ownership_separates_absent_refused_and_live() -> Check {
    let directory = std::env::temp_dir().join(format!(
        "se-daemon-owner-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory)?;
    let socket = directory.join("control.sock");

    // Absent: no path at all is not a served login, and may be claimed.
    assert!(!se_host::socket_is_served(&socket, &cx()?).await?);
    se_host::require_unserved(&socket, &cx()?).await?;

    // Refused: a stale socket file left by a dead daemon is also not served.
    std::fs::write(&socket, b"stale")?;
    assert!(!se_host::socket_is_served(&socket, &cx()?).await?);
    se_host::require_unserved(&socket, &cx()?).await?;
    std::fs::remove_file(&socket)?;

    // Live: a listening socket is a daemon we did not start, so it is refused
    // with the step a person can take rather than attached to.
    let listener = tokio::net::UnixListener::bind(&socket)?;
    assert!(se_host::socket_is_served(&socket, &cx()?).await?);
    let refused = se_host::require_unserved(&socket, &cx()?).await;
    let error = match refused {
        Ok(()) => return Err("a live daemon we did not start must be refused".into()),
        Err(error) => error,
    };
    let se_types::Detail::ProviderIncompatible(failure) = error.body.detail() else {
        return Err(format!("expected a named refusal, got {:?}", error.body.detail()).into());
    };
    assert!(
        failure.reason.contains("did not start"),
        "{}",
        failure.reason
    );
    assert!(
        failure.next_step.to_lowercase().contains("cod_home")
            || failure
                .next_step
                .to_lowercase()
                .contains("close that daemon"),
        "{}",
        failure.next_step
    );
    drop(listener);
    let _ = std::fs::remove_dir_all(&directory);
    Ok(())
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
