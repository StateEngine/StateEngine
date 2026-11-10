//! Independent process-boundary controls through the public ACP connection.
//! Scripted I/O models bounded reads, accepted byte counts and native EOF;
//! these controls make no claim about native process or model qualification.
#![cfg(feature = "listener")]
use crate::{
    CallContext, HostFuture, ProviderIo, ProviderIoPlatform, ProviderStream, ProviderTransport,
    SessionIdentity, StreamRead, StreamWrite,
    acp::{Connection, Incoming, Message},
};
use se_types::{Generation, Result, SeError};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    num::NonZeroU32,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Semaphore, mpsc};
type Check<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

enum WritePlan {
    Complete,
    Partial(u32),
    Held(Arc<Semaphore>),
}
struct Io {
    output: mpsc::UnboundedSender<StreamRead>,
    error: mpsc::UnboundedSender<StreamRead>,
    output_read: tokio::sync::Mutex<mpsc::UnboundedReceiver<StreamRead>>,
    error_read: tokio::sync::Mutex<mpsc::UnboundedReceiver<StreamRead>>,
    plans: Mutex<VecDeque<WritePlan>>,
    attempts: Mutex<Vec<Vec<u8>>>,
    completed: AtomicUsize,
    closes: AtomicUsize,
    finishes: AtomicUsize,
}
fn fault(reason: &str) -> SeError {
    se_core::scope::unreadable("synthetic I/O", reason)
}
impl ProviderIoPlatform for Io {
    fn open(&self, _: &se_proc::OwnedProcess, _: &SessionIdentity) -> Result<ProviderIo> {
        Err(fault("fixture has no native process"))
    }
    fn read<'a>(
        &'a self,
        _: &'a ProviderTransport,
        stream: ProviderStream,
        maximum: NonZeroU32,
        _: CallContext,
    ) -> HostFuture<'a, StreamRead> {
        Box::pin(async move {
            let source = match stream {
                ProviderStream::Output => &self.output_read,
                ProviderStream::Error => &self.error_read,
                ProviderStream::Input => return Err(fault("input is not readable")),
            };
            let read = source
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| fault("fixture input closed without EOF"))?;
            let count = match &read {
                StreamRead::Bytes(bytes) | StreamRead::Failed { bytes, .. } => bytes.len(),
                StreamRead::Eof => 0,
            };
            if count > maximum.get() as usize {
                return Err(fault("script exceeds the native read bound"));
            }
            Ok(read)
        })
    }
    fn write<'a>(
        &'a self,
        _: &'a ProviderTransport,
        bytes: Vec<u8>,
        cx: CallContext,
    ) -> HostFuture<'a, StreamWrite> {
        Box::pin(async move {
            let expected = u32::try_from(bytes.len()).map_err(|_| fault("byte count overflow"))?;
            self.attempts
                .lock()
                .map_err(|_| fault("poisoned fixture"))?
                .push(bytes);
            let plan = self
                .plans
                .lock()
                .map_err(|_| fault("poisoned fixture"))?
                .pop_front()
                .unwrap_or(WritePlan::Complete);
            let outcome = match plan {
                WritePlan::Complete => StreamWrite {
                    completed_bytes: expected,
                    failure: None,
                },
                WritePlan::Partial(count) => StreamWrite {
                    completed_bytes: count,
                    failure: Some(fault("synthetic partial write").body),
                },
                WritePlan::Held(gate) => {
                    match tokio::time::timeout(cx.timeout, gate.acquire()).await {
                        Ok(Ok(_permit)) => StreamWrite {
                            completed_bytes: expected,
                            failure: None,
                        },
                        _ => StreamWrite {
                            completed_bytes: 0,
                            failure: Some(fault("synthetic native write deadline").body),
                        },
                    }
                }
            };
            self.completed.fetch_add(1, Ordering::AcqRel);
            Ok(outcome)
        })
    }
    fn finish_input<'a>(&'a self, _: &'a ProviderTransport, _: CallContext) -> HostFuture<'a, ()> {
        Box::pin(async move {
            self.finishes.fetch_add(1, Ordering::AcqRel);
            Ok(())
        })
    }
    fn close<'a>(&'a self, _: &'a ProviderTransport, _: CallContext) -> HostFuture<'a, ()> {
        Box::pin(async move {
            self.closes.fetch_add(1, Ordering::AcqRel);
            Ok(())
        })
    }
}
struct Fixture {
    connection: Arc<Connection>,
    events: mpsc::Receiver<Incoming>,
    io: Arc<Io>,
}
fn cx(timeout: Duration) -> Check<CallContext> {
    Ok(CallContext::new(Generation::new(1)?, timeout))
}
fn second() -> Check<CallContext> {
    cx(Duration::from_secs(2))
}
async fn ready(mut check: impl FnMut() -> bool) -> Check {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !check() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    Ok(())
}
impl Fixture {
    async fn new(plans: Vec<WritePlan>) -> Check<Self> {
        let (output, output_read) = mpsc::unbounded_channel();
        let (error, error_read) = mpsc::unbounded_channel();
        let io = Arc::new(Io {
            output,
            error,
            output_read: tokio::sync::Mutex::new(output_read),
            error_read: tokio::sync::Mutex::new(error_read),
            plans: Mutex::new(plans.into()),
            attempts: Mutex::new(Vec::new()),
            completed: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
            finishes: AtomicUsize::new(0),
        });
        let (connection, events) = Connection::open(
            io.clone(),
            ProviderTransport::console(),
            Generation::new(1)?,
        )
        .await;
        Ok(Self {
            connection,
            events,
            io,
        })
    }
    fn stdout(&self, bytes: Vec<u8>) -> Check {
        self.io
            .output
            .send(StreamRead::Bytes(bytes))
            .map_err(|_| "stdout fixture closed")?;
        Ok(())
    }
    fn frame(&self, value: Value) -> Check {
        let mut bytes = serde_json::to_vec(&value)?;
        bytes.push(b'\n');
        self.stdout(bytes)
    }
    fn attempts(&self) -> Check<Vec<Vec<u8>>> {
        Ok(self
            .io
            .attempts
            .lock()
            .map_err(|_| "fixture poisoned")?
            .clone())
    }
    async fn next(&mut self) -> Check<Incoming> {
        Ok(
            tokio::time::timeout(Duration::from_secs(2), self.events.recv())
                .await?
                .ok_or("events closed")?,
        )
    }
    async fn failed(&self) -> Check {
        ready(|| {
            self.connection
                .diagnostics()
                .is_ok_and(|d| d.failure.is_some())
        })
        .await
    }
    fn eof(&self) -> Check {
        let _ = self.io.output.send(StreamRead::Eof);
        self.io
            .error
            .send(StreamRead::Eof)
            .map_err(|_| "stderr fixture closed")?;
        Ok(())
    }
    async fn stop(&mut self) -> Check {
        self.events.close();
        self.eof()?;
        self.connection.close(second()?).await?;
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fragments_and_peer_requests_preserve_identity_and_stream_order() -> Check {
    let mut f = Fixture::new(vec![]).await?;
    let id = f
        .connection
        .offer("initialize", json!({"protocolVersion":1}), second()?)
        .await?;
    let bytes = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":{"text":"λ"}}))?;
    let split = bytes
        .iter()
        .position(|byte| *byte == 0xce)
        .ok_or("UTF-8 fixture missing")?
        + 1;
    f.stdout(bytes[..split].to_vec())?;
    assert!(f.events.try_recv().is_err());
    let mut tail = bytes[split..].to_vec();
    tail.extend_from_slice(b"\r\n");
    f.stdout(tail)?;
    let event = f.next().await?;
    assert_eq!(event.sequence, 1);
    assert!(
        matches!(event.message, Message::Response { id: observed, method:"initialize", outcome:Ok(ref value) } if observed == id && value["text"] == "λ")
    );
    f.frame(json!({"jsonrpc":"2.0","id":"peer-string","method":"session/request_permission","params":{"sessionId":"synthetic"}}))?;
    let event = f.next().await?;
    assert_eq!(event.sequence, 2);
    let Message::Request { id, method, .. } = event.message else {
        return Err("peer request lost".into());
    };
    assert_eq!(method, "session/request_permission");
    f.connection.unsupported(id, second()?).await?;
    let writes = f.attempts()?;
    let answer: Value = serde_json::from_slice(&writes[1])?;
    assert_eq!(answer["id"], "peer-string");
    assert_eq!(answer["error"]["code"], -32601);
    f.stop().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caller_timeout_keeps_the_original_reply_observable_without_resending() -> Check {
    let mut f = Fixture::new(vec![]).await?;
    let result = f
        .connection
        .request(
            "session/prompt",
            json!({"text":"synthetic"}),
            cx(Duration::from_millis(25))?,
        )
        .await;
    assert!(result.is_err());
    let writes = f.attempts()?;
    assert_eq!(writes.len(), 1);
    let offered: Value = serde_json::from_slice(&writes[0])?;
    f.frame(json!({"jsonrpc":"2.0","id":offered["id"],"result":{"stopReason":"end_turn"}}))?;
    let reply = f.next().await?;
    assert!(matches!(
        reply.message,
        Message::Response {
            method: "session/prompt",
            outcome: Ok(_),
            ..
        }
    ));
    assert_eq!(f.attempts()?.len(), 1);
    f.stop().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caller_cancellation_and_short_close_retain_the_original_native_write() -> Check {
    let gate = Arc::new(Semaphore::new(0));
    let mut f = Fixture::new(vec![WritePlan::Held(gate.clone())]).await?;
    let owned = f.connection.clone();
    let caller = tokio::spawn(async move {
        owned
            .notify(
                "session/cancel",
                json!({}),
                second().map_err(|e| fault(&e.to_string()))?,
            )
            .await
    });
    ready(|| f.attempts().is_ok_and(|writes| writes.len() == 1)).await?;
    caller.abort();
    let _ = caller.await;
    let closed = f.connection.close(cx(Duration::from_millis(20))?).await;
    assert!(
        closed.is_err(),
        "a pending native write cannot be reported joined"
    );
    assert_eq!(f.io.closes.load(Ordering::Acquire), 0);
    gate.add_permits(1);
    ready(|| f.io.completed.load(Ordering::Acquire) == 1).await?;
    assert_eq!(f.attempts()?.len(), 1);
    f.stop().await?;
    assert_eq!(f.io.closes.load(Ordering::Acquire), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_partial_native_write_fences_future_input_without_replay() -> Check {
    let mut f = Fixture::new(vec![WritePlan::Partial(7)]).await?;
    assert!(
        f.connection
            .offer("session/prompt", json!({"text":"synthetic"}), second()?)
            .await
            .is_err()
    );
    assert!(
        f.connection
            .notify("session/cancel", json!({}), second()?)
            .await
            .is_err()
    );
    assert_eq!(f.attempts()?.len(), 1);
    assert!(f.connection.diagnostics()?.failure.is_some());
    f.stop().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_or_duplicate_reply_identity_never_settles_another_request() -> Check {
    for bad in [
        json!({"jsonrpc":"2.0","id":999,"result":{}}),
        json!({"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-1}}),
        json!({"jsonrpc":"1.0","id":1,"result":{}}),
    ] {
        let mut f = Fixture::new(vec![]).await?;
        f.connection
            .offer("initialize", json!({}), second()?)
            .await?;
        f.frame(bad)?;
        f.failed().await?;
        let delivered = f.events.try_recv().ok();
        f.stop().await?;
        assert!(
            delivered.is_none(),
            "malformed/unknown reply cannot become an original response"
        );
    }
    let mut f = Fixture::new(vec![]).await?;
    let id = f
        .connection
        .offer("initialize", json!({}), second()?)
        .await?;
    let reply = json!({"jsonrpc":"2.0","id":id,"result":{}});
    f.frame(reply.clone())?;
    let first = f.next().await?;
    f.frame(reply)?;
    f.failed().await?;
    assert_eq!(first.sequence, 1);
    assert!(f.events.try_recv().is_err());
    f.stop().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stderr_preserves_count_prefix_and_failure_completeness() -> Check {
    for failed in [false, true] {
        let mut f = Fixture::new(vec![]).await?;
        f.io.error
            .send(StreamRead::Bytes(vec![b'x'; 60000]))
            .map_err(|_| "stderr closed")?;
        f.io.error
            .send(if failed {
                StreamRead::Failed {
                    bytes: vec![b'y'; 10000],
                    error: fault("synthetic read failure").body,
                }
            } else {
                StreamRead::Bytes(vec![b'y'; 10000])
            })
            .map_err(|_| "stderr closed")?;
        if !failed {
            f.io.error
                .send(StreamRead::Eof)
                .map_err(|_| "stderr closed")?;
        }
        ready(|| {
            f.connection
                .diagnostics()
                .is_ok_and(|d| d.stderr_bytes == 70000 && (failed || d.stderr_complete))
        })
        .await?;
        if failed {
            f.failed().await?;
        }
        let diagnostics = f.connection.diagnostics()?;
        assert_eq!(diagnostics.stderr_prefix.len(), 65536);
        assert!(diagnostics.stderr_truncated);
        assert_eq!(diagnostics.stderr_complete, !failed);
        f.stop().await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protocol_errors_redact_provider_message_and_data() -> Check {
    let mut f = Fixture::new(vec![]).await?;
    let id = f
        .connection
        .offer("initialize", json!({}), second()?)
        .await?;
    f.frame(json!({"jsonrpc":"2.0","id":id,"error":{"code":-123,"message":"synthetic-private-marker","data":{"token":"synthetic-private-marker"}}}))?;
    let event = f.next().await?;
    let Message::Response {
        outcome: Err(error),
        ..
    } = event.message
    else {
        return Err("protocol failure missing".into());
    };
    let public = serde_json::to_string(&error.body)?;
    assert!(public.contains("-123"));
    assert!(!public.contains("synthetic-private-marker"));
    f.stop().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_complete_reply_before_bad_stdout_is_retained_at_the_read_boundary() -> Check {
    let mut f = Fixture::new(vec![]).await?;
    let id = f
        .connection
        .offer("session/prompt", json!({}), second()?)
        .await?;
    let mut bytes =
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":{"stopReason":"end_turn"}}))?;
    bytes.extend_from_slice(b"\ninvalid protocol output\n");
    f.stdout(bytes)?;
    f.failed().await?;
    let reply = f.events.try_recv().ok();
    f.stop().await?;
    assert!(
        matches!(reply.map(|r|r.message), Some(Message::Response { id:seen, method:"session/prompt", outcome:Ok(_)} ) if seen == id),
        "a later malformed line discarded the already complete original reply from the same native read"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_complete_reply_in_an_earlier_read_survives_bad_stdout() -> Check {
    let mut f = Fixture::new(vec![]).await?;
    let id = f
        .connection
        .offer("session/prompt", json!({}), second()?)
        .await?;
    f.frame(json!({"jsonrpc":"2.0","id":id,"result":{"stopReason":"end_turn"}}))?;
    let reply = f.next().await?;
    f.stdout(b"invalid protocol output\n".to_vec())?;
    f.failed().await?;
    f.stop().await?;
    assert!(
        matches!(reply.message, Message::Response { id:seen, outcome:Ok(_), .. } if seen == id)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_or_invalid_envelopes_keep_the_preceding_complete_reply() -> Check {
    for suffix in [
        b"\n".as_slice(),
        b"{\"jsonrpc\":\"1.0\",\"id\":1,\"result\":{}}\n",
        b"{\"jsonrpc\":\"2.0\",\"id\":999,\"result\":{}}\n",
    ] {
        let mut f = Fixture::new(vec![]).await?;
        let id = f
            .connection
            .offer("initialize", json!({}), second()?)
            .await?;
        let mut bytes = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":{}}))?;
        bytes.push(b'\n');
        bytes.extend_from_slice(suffix);
        f.stdout(bytes)?;
        f.failed().await?;
        let reply = f.events.try_recv().ok();
        f.stop().await?;
        assert!(
            matches!(reply.map(|r|r.message), Some(Message::Response {id:seen,outcome:Ok(_),..}) if seen==id)
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_input_and_output_are_refused_without_write_or_replay() -> Check {
    let mut f = Fixture::new(vec![]).await?;
    let outgoing = f
        .connection
        .offer(
            "initialize",
            json!({"data":"x".repeat(1024*1024)}),
            second()?,
        )
        .await;
    assert!(outgoing.is_err());
    assert!(f.attempts()?.is_empty());
    for _ in 0..16 {
        f.stdout(vec![b'x'; 65536])?;
    }
    f.stdout(vec![b'x'])?;
    f.failed().await?;
    let diagnostics = f.connection.diagnostics()?;
    assert!(!diagnostics.stdout_complete);
    assert!(f.events.try_recv().is_err());
    assert!(
        f.connection
            .notify("session/cancel", json!({}), second()?)
            .await
            .is_err()
    );
    assert!(f.attempts()?.is_empty());
    f.stop().await
}
