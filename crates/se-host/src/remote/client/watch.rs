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
    retry_error: Option<se_types::ErrorBody>,
    initial_retry_deadline: Option<tokio::time::Instant>,
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
            retry_error: None,
            initial_retry_deadline: None,
        }
    }
    pub async fn start(&mut self) -> Result<()> {
        match self.attach().await {
            Ok(()) => Ok(()),
            Err(error) if retryable(&error) => {
                self.defer_retry(error.body.retry())?;
                self.retry_error = Some(error.body);
                // A first connection must eventually state why it could not
                // start. Established streams instead report reconnect gaps.
                self.initial_retry_deadline =
                    Some(tokio::time::Instant::now() + Duration::from_secs(10));
                Ok(())
            }
            Err(error) => Err(error),
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
        self.initial_retry_deadline = None;
        Ok(())
    }
    fn check_initial_retry_budget(&mut self) -> Result<()> {
        if self
            .initial_retry_deadline
            .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
        {
            let error = self.retry_error.clone().unwrap_or_else(|| {
                unavailable("initial watch connection did not recover within ten seconds").body
            });
            self.terminal = Some(error.clone());
            return Err(error.into());
        }
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
    fn defer_retry(&mut self, hint: &se_types::Retry) -> Result<()> {
        let base = match self.retry_step {
            0 => 250,
            1 => 1000,
            2 => 2000,
            _ => 5000,
        };
        self.retry_step = self.retry_step.saturating_add(1);
        let jitter = u64::from(u16::from_le_bytes(session::entropy::<2>()?)) % 41 + 80;
        let delay = Duration::from_millis((base * jitter / 100).min(5000));
        let delay = match hint {
            se_types::Retry::After(minimum) => delay.max(*minimum),
            _ => delay,
        };
        self.retry_at = tokio::time::Instant::now()
            .checked_add(delay)
            .ok_or_else(|| {
                SeError::invalid("watch retry delay", "a representable retry interval")
            })?;
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
                Ok(Ok(())) => {
                    self.retry_error = None;
                    return Ok(true);
                }
                Ok(Err(error)) if !retryable(&error) => {
                    self.terminal = Some(error.body.clone());
                    return Err(error);
                }
                Ok(Err(error)) => {
                    self.defer_retry(error.body.retry())?;
                    self.retry_error = Some(error.body);
                }
                Err(_) => {
                    self.defer_retry(&se_types::Retry::Never)?;
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
        self.check_initial_retry_budget()?;
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
        let until = self
            .initial_retry_deadline
            .map_or(until, |deadline| until.min(deadline));
        if self.attached.is_none() {
            if wait.is_zero() {
                return Err(self.retry_error.clone().map(SeError::from).unwrap_or_else(|| unavailable(
                    "watch reconnect requires a positive bounded wait; retry the same scoped cursors",
                )));
            }
            if !self.reattach(until).await? {
                self.check_initial_retry_budget()?;
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
                if retryable(&error) {
                    self.defer_retry(error.body.retry())?;
                    self.retry_error = Some(error.body);
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

fn retryable(error: &SeError) -> bool {
    matches!(
        error.body.retry(),
        se_types::Retry::After(_) | se_types::Retry::WhenRuntimeReady
    ) || matches!(
        error.code(),
        se_types::Code::ListenerUnavailable
            | se_types::Code::IpcUnavailable
            | se_types::Code::DeadlineExceeded
            | se_types::Code::StoreBusy
            | se_types::Code::RuntimeHandoverInProgress
            | se_types::Code::RuntimeNotRunning
            | se_types::Code::RuntimeStartFailed
            | se_types::Code::RuntimeStartPending
            | se_types::Code::RemoteBusy
    )
}
