//! Reviewer judge: an ACP session's turn phase starts only on a published
//! offer, moves on completion or failure, and a witnessed zero-byte offer
//! restores the exact prior phase. Synthetic stdio drives the production
//! connection and session; no provider process or sandbox is qualified.
#![cfg(feature = "listener")]
use se_harness::{
    CallContext, HostFuture, ProviderIo, ProviderIoPlatform, ProviderStream, ProviderTransport,
    SessionIdentity, StreamRead, StreamWrite,
    acp::{Connection, PermissionPolicy, Session},
};
use se_types::{Generation, Result};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    num::NonZeroU32,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::mpsc;
type Check<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

/// How the next host write ends.
#[derive(Clone, Copy)]
enum Write {
    Complete,
    /// Some bytes reached the provider, so the input is uncertain.
    Partial,
}
struct Io {
    output: mpsc::UnboundedSender<StreamRead>,
    error: mpsc::UnboundedSender<StreamRead>,
    output_read: tokio::sync::Mutex<mpsc::UnboundedReceiver<StreamRead>>,
    error_read: tokio::sync::Mutex<mpsc::UnboundedReceiver<StreamRead>>,
    writes: Mutex<Vec<Value>>,
    plans: Mutex<VecDeque<Write>>,
}
fn fault(reason: &str) -> se_types::SeError {
    se_core::scope::unreadable("synthetic phase I/O", reason)
}
impl ProviderIoPlatform for Io {
    fn open(&self, _: &se_proc::OwnedProcess, _: &SessionIdentity) -> Result<ProviderIo> {
        Err(fault("no native process in protocol control"))
    }
    fn read<'a>(
        &'a self,
        _: &'a ProviderTransport,
        stream: ProviderStream,
        maximum: NonZeroU32,
        _: CallContext,
    ) -> HostFuture<'a, StreamRead> {
        Box::pin(async move {
            let receiver = match stream {
                ProviderStream::Output => &self.output_read,
                ProviderStream::Error => &self.error_read,
                ProviderStream::Input => return Err(fault("input cannot be read")),
            };
            let result = receiver
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| fault("missing EOF"))?;
            if let StreamRead::Bytes(bytes) = &result
                && bytes.len() > maximum.get() as usize
            {
                return Err(fault("native read bound exceeded"));
            }
            Ok(result)
        })
    }
    fn write<'a>(
        &'a self,
        _: &'a ProviderTransport,
        bytes: Vec<u8>,
        _: CallContext,
    ) -> HostFuture<'a, StreamWrite> {
        Box::pin(async move {
            let plan = self
                .plans
                .lock()
                .map_err(|_| fault("poisoned fixture"))?
                .pop_front()
                .unwrap_or(Write::Complete);
            let length = u32::try_from(bytes.len()).map_err(|_| fault("frame too large"))?;
            let value =
                serde_json::from_slice(&bytes).map_err(|_| fault("invalid outgoing frame"))?;
            self.writes
                .lock()
                .map_err(|_| fault("poisoned fixture"))?
                .push(value);
            Ok(match plan {
                Write::Complete => StreamWrite {
                    completed_bytes: length,
                    failure: None,
                },
                Write::Partial => StreamWrite {
                    completed_bytes: 1,
                    failure: Some(fault("synthetic incomplete write").body),
                },
            })
        })
    }
    fn finish_input<'a>(&'a self, _: &'a ProviderTransport, _: CallContext) -> HostFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn close<'a>(&'a self, _: &'a ProviderTransport, _: CallContext) -> HostFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}
fn cx() -> Check<CallContext> {
    Ok(CallContext::new(
        Generation::new(1)?,
        Duration::from_secs(3),
    ))
}
async fn eventually(mut condition: impl FnMut() -> bool) -> Check {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    Ok(())
}
struct Fixture {
    io: Arc<Io>,
    session: Arc<Session>,
    emitted: u64,
}
impl Fixture {
    async fn ready() -> Check<Self> {
        let (output, output_read) = mpsc::unbounded_channel();
        let (error, error_read) = mpsc::unbounded_channel();
        let io = Arc::new(Io {
            output,
            error,
            output_read: tokio::sync::Mutex::new(output_read),
            error_read: tokio::sync::Mutex::new(error_read),
            writes: Mutex::default(),
            plans: Mutex::default(),
        });
        let (connection, receiver) = Connection::open(
            io.clone(),
            ProviderTransport::console(),
            Generation::new(1)?,
        )
        .await;
        let session = Session::retain(
            connection,
            receiver,
            PermissionPolicy::Refuse,
            Arc::new(
                || -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>> {
                    Box::pin(async { false })
                },
            ),
        )
        .await;
        let mut f = Self {
            io,
            session,
            emitted: 0,
        };
        let session = f.session.clone();
        let context = cx()?;
        let operation = tokio::spawn(async move { session.initialize(context).await });
        let request = f.write(0).await?;
        f.emit(json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":1,"agentCapabilities":{"loadSession":true}}}))?;
        operation.await??;
        let session = f.session.clone();
        let context = cx()?;
        let operation = tokio::spawn(async move {
            session
                .open("/synthetic/workspace", vec![], None, "safe", false, context)
                .await
        });
        let request = f.write(1).await?;
        f.emit(json!({"jsonrpc":"2.0","id":request["id"],"result":{"sessionId":"conversation","modes":{"currentModeId":"safe"}}}))?;
        operation.await??;
        Ok(f)
    }
    fn writes(&self) -> Check<Vec<Value>> {
        Ok(self
            .io
            .writes
            .lock()
            .map_err(|_| "poisoned fixture")?
            .clone())
    }
    async fn write(&self, index: usize) -> Check<Value> {
        eventually(|| self.writes().is_ok_and(|v| v.len() > index)).await?;
        self.writes()?
            .get(index)
            .cloned()
            .ok_or_else(|| "write absent".into())
    }
    fn emit(&mut self, value: Value) -> Check {
        let mut bytes = serde_json::to_vec(&value)?;
        bytes.push(b'\n');
        self.io
            .output
            .send(StreamRead::Bytes(bytes))
            .map_err(|_| "stdout closed")?;
        self.emitted += 1;
        Ok(())
    }
    fn plan(&self, write: Write) -> Check {
        self.io
            .plans
            .lock()
            .map_err(|_| "fixture poisoned")?
            .push_back(write);
        Ok(())
    }
    async fn prompt(&self, key: &str) -> std::result::Result<u64, se_types::SeError> {
        self.session
            .prompt(
                key.into(),
                "original input".into(),
                cx().map_err(|e| fault(&e.to_string()))?,
            )
            .await
    }
    async fn complete(&mut self, request: u64) -> Check {
        self.emit(json!({"jsonrpc":"2.0","id":request,"result":{"stopReason":"end_turn"}}))?;
        eventually(|| {
            self.session
                .observe()
                .is_ok_and(|s| s.processed >= self.emitted && s.active_input.is_none())
        })
        .await
    }
    fn phase(&self) -> Check<Option<std::time::Instant>> {
        Ok(self.session.observe()?.phase_started)
    }
    fn prompts(&self) -> Check<usize> {
        Ok(self
            .writes()?
            .iter()
            .filter(|v| v["method"] == "session/prompt")
            .count())
    }
    /// Offer with a deadline that has already passed when the session reaches
    /// the writer: refused before any native byte, a witnessed zero-byte outcome.
    async fn expired_prompt(&self, key: &str) -> Check<se_types::SeError> {
        let expired = CallContext::new(Generation::new(1)?, Duration::ZERO);
        match self
            .session
            .prompt(key.into(), "original input".into(), expired)
            .await
        {
            Ok(_) => Err("an expired offer was published".into()),
            Err(error) => Ok(error),
        }
    }
    async fn stop(self) -> Check {
        let _ = self.io.output.send(StreamRead::Eof);
        let _ = self.io.error.send(StreamRead::Eof);
        self.session.close(cx()?).await?;
        Ok(())
    }
}

/// A ready connection has observed no turn: there is no phase to report.
/// An offer refused before any byte reached the provider leaves it that way.
#[tokio::test]
async fn a_refused_first_offer_leaves_no_invented_phase() -> Check {
    let f = Fixture::ready().await?;
    assert_eq!(f.phase()?, None, "a ready connection invented a turn phase");
    f.expired_prompt("refused").await?;
    let observed = f.session.observe()?;
    assert_eq!(
        observed.phase_started, None,
        "a refused offer started a phase"
    );
    assert_eq!(observed.active_input, None, "a refused offer stayed active");
    assert!(
        observed.failure.is_none(),
        "a witnessed zero-byte offer is not a failure"
    );
    assert_eq!(f.prompts()?, 0);
    f.stop().await
}

/// The phase starts with a published offer, moves to the completion, and a
/// later offer refused before any byte restores that completion phase, not a
/// new one. The
/// released key can then be offered again.
#[tokio::test]
async fn a_refused_offer_restores_the_prior_phase_and_releases_its_key() -> Check {
    let mut f = Fixture::ready().await?;
    let id = f.prompt("first").await?;
    let offered = f
        .phase()?
        .ok_or("a published offer did not start a phase")?;
    assert_eq!(f.session.observe()?.active_input.as_deref(), Some("first"));
    f.complete(id).await?;
    let completed = f.phase()?.ok_or("completion cleared the phase")?;
    assert!(completed >= offered, "completion moved the phase backwards");

    f.expired_prompt("second").await?;
    let observed = f.session.observe()?;
    assert_eq!(
        observed.phase_started,
        Some(completed),
        "a refused offer must restore the exact prior phase"
    );
    assert_eq!(observed.active_input, None);
    assert!(observed.failure.is_none());

    let retry = f.prompt("second").await?;
    let retried = f
        .phase()?
        .ok_or("the retried offer did not start a phase")?;
    assert!(retried >= completed);
    assert_eq!(
        f.prompts()?,
        2,
        "only the two published offers were written"
    );
    f.complete(retry).await?;
    f.stop().await
}

/// Bytes that reached the provider make the input uncertain: the session
/// fails, keeps the original input, and the phase marks when it failed.
#[tokio::test]
async fn a_partial_offer_fails_and_dates_the_failure() -> Check {
    let mut f = Fixture::ready().await?;
    let id = f.prompt("first").await?;
    f.complete(id).await?;
    let completed = f.phase()?.ok_or("completion cleared the phase")?;
    f.plan(Write::Partial)?;
    assert!(f.prompt("uncertain").await.is_err());
    let observed = f.session.observe()?;
    assert!(
        observed.failure.is_some(),
        "a partial offer must fail the session"
    );
    assert_eq!(observed.active_input.as_deref(), Some("uncertain"));
    let failed = observed.phase_started.ok_or("failure cleared the phase")?;
    assert!(
        failed >= completed,
        "the failure phase predates the completion"
    );
    assert!(
        f.prompt("another").await.is_err(),
        "a failed session accepted input"
    );
    f.stop().await
}
