use super::connection::{Guard, QueuedBatch};
use super::*;
use se_types::{Omission, OmissionReason};
use tokio::sync::mpsc;

pub(super) struct Watch {
    client: Client,
    call: Arc<RemoteCallContext>,
    request: RemoteWatch,
    attached: Option<(Arc<Connection>, Guard, mpsc::Receiver<Result<QueuedBatch>>)>,
    reconnect_gap: bool,
    prefetched: Option<QueuedBatch>,
    retry_step: u8,
    retry_at: tokio::time::Instant,
    terminal: Option<se_types::ErrorBody>,
}
impl Watch {
    pub fn new(client: Client, call: Arc<RemoteCallContext>, request: RemoteWatch) -> Self {
        Self {
            client,
            call,
            request,
            attached: None,
            reconnect_gap: false,
            prefetched: None,
            retry_step: 0,
            retry_at: tokio::time::Instant::now(),
            terminal: None,
        }
    }
    pub async fn attach(&mut self) -> Result<()> {
        self.call.check_current()?;
        let invocation = self
            .client
            .invocation(&self.call, RemoteRequest::Watch(self.request.clone()))?;
        let connection = self.client.connection().await?;
        let (guard, mut rx) = connection.subscribe(self.call.clone(), invocation)?;
        // Opening a subscription includes its first bounded response. Otherwise
        // a zero-wait reader can race the initial manifest and return no view.
        let first = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .map_err(|_| unavailable("initial watch response deadline exceeded"))?
            .ok_or_else(|| unavailable("watch closed before its initial response"))??;
        self.call.check_current()?;
        self.prefetched = Some(first);
        self.attached = Some((connection, guard, rx));
        Ok(())
    }
    fn empty(&self) -> RemoteWatchBatch {
        RemoteWatchBatch {
            schema: RemoteWatchBatch::SCHEMA.into(),
            body: RemoteWatchBody {
                observation_clock: None,
                records: vec![],
                cursors: self.request.cursors.clone(),
                complete: false,
                omitted_records: Omission::None,
                reset_required: false,
            },
        }
    }
    fn gap(&self) -> RemoteWatchBatch {
        let targets = if self.request.targets.is_empty() {
            &self.client.device.scope.targets
        } else {
            &self.request.targets
        };
        RemoteWatchBatch {schema:RemoteWatchBatch::SCHEMA.into(), body: RemoteWatchBody {observation_clock:None,records:targets.iter().cloned().map(|target| RemoteWatchRecord::Gap {target,
            reason:"connection interrupted; reconnecting from consumed scoped cursors; provisional continuity requires host confirmation".into(),reset_required:false}).collect(),
            cursors:self.request.cursors.clone(),complete:false,omitted_records:Omission::Unknown {reason:OmissionReason::SourceIncomplete},reset_required:false}}
    }
    fn defer_retry(&mut self) -> Result<()> {
        let base = match self.retry_step {
            0 => 250,
            1 => 1000,
            2 => 2000,
            _ => 5000,
        };
        self.retry_step = self.retry_step.saturating_add(1);
        let jitter = u64::from(u16::from_le_bytes(session::entropy::<2>()?)) % 41 + 80;
        let delay = Duration::from_millis((base * jitter / 100).min(5000));
        self.retry_at = tokio::time::Instant::now() + delay;
        Ok(())
    }
    async fn reattach(&mut self, until: tokio::time::Instant) -> Result<bool> {
        while tokio::time::Instant::now() < until {
            if self.retry_at >= until {
                tokio::time::sleep_until(until).await;
                self.call.check_current()?;
                return Ok(false);
            }
            tokio::time::sleep_until(self.retry_at).await;
            self.call.check_current()?;
            match tokio::time::timeout_at(until, self.attach()).await {
                Ok(Ok(())) => return Ok(true),
                Ok(Err(error)) if error.code() != se_types::Code::ListenerUnavailable => {
                    self.terminal = Some(error.body.clone());
                    return Err(error);
                }
                Ok(Err(_)) => self.defer_retry()?,
                Err(_) => {
                    self.defer_retry()?;
                    return Ok(false);
                }
            }
        }
        Ok(false)
    }
    async fn poll(&mut self, wait: Duration) -> Result<RemoteWatchBatch> {
        self.call.check_current()?;
        if let Some(error) = &self.terminal {
            return Err(error.clone().into());
        }
        if wait > Duration::from_secs(30) {
            return Err(SeError::invalid("remote watch wait", "at most30000ms"));
        }
        if self.attached.as_ref().is_some_and(|(c, _, _)| c.closed()) {
            // Drop queued private records before reconnect, never release stale output.
            self.attached = None;
            self.prefetched = None;
            self.reconnect_gap = true;
        }
        if self.reconnect_gap {
            self.reconnect_gap = false;
            return Ok(self.gap());
        }
        // Reconnection consumes this same wait window, rather than adding its
        // handshake clock to the caller's requested bounded read.
        let until = tokio::time::Instant::now() + wait;
        if self.attached.is_none() {
            if wait.is_zero() {
                return Err(unavailable(
                    "watch reconnect requires a positive bounded wait; retry the same scoped cursors",
                ));
            }
            if !self.reattach(until).await? {
                return Ok(self.empty());
            }
        }
        let received = if let Some(first) = self.prefetched.take() {
            Some(Ok(first))
        } else {
            match &mut self.attached {
                Some((_, _, rx)) if wait.is_zero() => match rx.try_recv() {
                    Ok(value) => Some(value),
                    Err(mpsc::error::TryRecvError::Empty) => return Ok(self.empty()),
                    Err(mpsc::error::TryRecvError::Disconnected) => None,
                },
                Some((_, _, rx)) => match tokio::time::timeout_at(until, rx.recv()).await {
                    Ok(value) => value,
                    Err(_) => {
                        self.call.check_current()?;
                        return Ok(self.empty());
                    }
                },
                None => return Err(unavailable("watch subscription absent after attach")),
            }
        };
        self.call.check_current()?;
        match received {
            Some(Ok(value)) => {
                self.retry_step = 0;
                self.retry_at = tokio::time::Instant::now();
                if value.batch.reset_required {
                    self.request.cursors.clear();
                }
                if !value.batch.cursors.is_empty() {
                    for cursor in &value.batch.cursors {
                        if let Some(saved) = self
                            .request
                            .cursors
                            .iter_mut()
                            .find(|saved| saved.target == cursor.target)
                        {
                            *saved = cursor.clone();
                        } else {
                            self.request.cursors.push(cursor.clone());
                        }
                    }
                }
                Ok(value.batch)
            }
            Some(Err(error)) => {
                self.attached = None;
                if error.code() == se_types::Code::ListenerUnavailable {
                    Ok(self.gap())
                } else {
                    self.terminal = Some(error.body.clone());
                    Err(error)
                }
            }
            None => {
                self.attached = None;
                Ok(self.gap())
            }
        }
    }
}
impl RemoteWatchStream for Watch {
    fn next(&mut self, wait: Duration) -> RemoteFuture<'_, RemoteWatchBatch> {
        Box::pin(self.poll(wait))
    }
}
