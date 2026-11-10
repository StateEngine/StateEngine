//! One receiver under the existing host generation and store lease.
use super::{service::*, *};
use crate::client::lease::Deadline;
use se_core::store_error::store_error;
use se_store::{ReadStore, Snapshot};
use se_types::Result;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::watch;

impl crate::HostedRuntime {
    /// Trusted native Owner ABI, never a tool capability for hosted agents.
    pub fn channels(&self) -> Result<Arc<Channels>> {
        if let Some(service) = self.channels.get() {
            return Ok(service.clone());
        }
        let credentials = Arc::new(
            NativeChannelCredentials::open(
                &self.state_directory,
                self.execution
                    .reader
                    .info()
                    .map_err(|e| store_error(&e))?
                    .id,
                self.owner.clone(),
            )
            .map_err(channel_error)?,
        );
        let service = Arc::new(Channels::new(
            self.execution.clone(),
            vec![match &self.channel_transport {
                Some(transport) => transport.clone(),
                None => Arc::new(Telegram::new().map_err(channel_error)?),
            }],
            self.configuration.clone(),
            self.owner.clone(),
            credentials,
            self.admission_context().machine_key()?,
            self.fenced.clone(),
        )?);
        if self.channels.set(service.clone()).is_ok() {
            return Ok(service);
        }
        self.channels
            .get()
            .cloned()
            .ok_or_else(|| channel_error(ChannelError::ReceiverNotRunning))
    }
}
struct Receiver {
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<()>>,
}
impl Channels {
    async fn maintain(&self, id: ChannelId) -> Result<()> {
        let bound = super::service::deadline(Duration::from_secs(30))?;
        for result in [
            self.queue_delays(id.clone(), &bound).await,
            self.run_resumes(id.clone(), &bound).await,
            self.flush_output(id.clone(), &bound).await,
        ] {
            if let Err(error) = result {
                self.set_health(
                    id.clone(),
                    ConnectionHealth::Unavailable {
                        code: error.code().as_str().into(),
                    },
                )?;
            }
        }
        Ok(())
    }
    pub(crate) async fn has_active(&self, deadline: &Deadline) -> Result<bool> {
        self.read(None, deadline, |cx| {
            cx.read
                .channel_active()
                .map(|v| !v.is_empty())
                .map_err(|e| store_error(&e))
        })
        .await
    }
    pub(crate) async fn run(
        self: Arc<Self>,
        mut stopped: watch::Receiver<Option<Deadline>>,
    ) -> Result<()> {
        self.receiver_running
            .store(true, std::sync::atomic::Ordering::Release);
        struct Running(Arc<Channels>);
        impl Drop for Running {
            fn drop(&mut self) {
                self.0
                    .receiver_running
                    .store(false, std::sync::atomic::Ordering::Release);
                self.0.changed.notify_waiters();
            }
        }
        let _running = Running(self.clone());
        let mut workers: HashMap<ChannelId, Receiver> = HashMap::new();
        let rescan_period = Duration::from_secs(5);
        let mut timer = Some(tokio::time::interval(rescan_period));
        let changed = self.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let mut failure = None;
        loop {
            tokio::select! {
                changed=stopped.changed()=>{if changed.is_err() || stopped.borrow().is_some() {break;}},
                _=async {
                    match timer.as_mut() {
                        Some(timer) => { timer.tick().await; },
                        None => std::future::pending::<()>().await,
                    }
                }=>{},
                _=&mut changed=>{},
            }
            // Register before reading: a connection committed during the scan
            // must wake us even after an empty scan disarms the timer.
            changed.set(self.changed.notified());
            changed.as_mut().enable();
            let deadline = super::service::deadline(Duration::from_secs(5))?;
            let scan = self.read(None, &deadline, |cx| {
                cx.read.channel_active().map_err(|e| store_error(&e))
            });
            let states = tokio::select! {
                biased;
                changed = stopped.changed() => {
                    if changed.is_err() || stopped.borrow().is_some() {
                        break;
                    }
                    continue;
                }
                result = scan => match result {
                    Ok(states) => states,
                    Err(error) if matches!(error.body.detail(), se_types::Detail::DeadlineExceeded(_)) => {
                        // A read timeout delays discovery while existing receivers retain custody.
                        eprintln!("Channel connection scan delayed: {error}");
                        timer.get_or_insert_with(|| tokio::time::interval(rescan_period)).reset();
                        continue;
                    }
                    Err(error)
                        if self.fenced.load(std::sync::atomic::Ordering::Acquire)
                        && matches!(error.body.detail(),
                            se_types::Detail::MessagingChannelRefused(detail)
                                if detail.reason == ChannelError::ReceiverNotRunning) => {
                        // The host fences new reads before waking its shutdown waiters.
                        break;
                    }
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                },
            };
            let retired: Vec<_> = workers
                .keys()
                .filter(|id| {
                    !states.iter().any(|s| s.id == **id)
                        || workers
                            .get(*id)
                            .is_some_and(|worker| worker.task.is_finished())
                })
                .cloned()
                .collect();
            // Join the retired poller before another connection can use its bot.
            for id in retired {
                if let Some(receiver) = workers.remove(&id) {
                    receiver.stop.send_replace(true);
                    if let Err(error) = joined(receiver.task.await) {
                        failure = Some(error);
                    }
                    self.health
                        .lock()
                        .map_err(|_| channel_error(ChannelError::ReceiverNotRunning))?
                        .remove(&id);
                    self.health_version
                        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    self.changed.notify_waiters();
                }
            }
            for state in states {
                if workers.contains_key(&state.id) {
                    continue;
                }
                let (stop, mut signal) = watch::channel(false);
                let service = self.clone();
                let id = state.id.clone();
                let task = tokio::spawn(async move {
                    let mut backoff = Duration::from_secs(1);
                    let mut receiver = None;
                    let mut output_timer = tokio::time::interval(Duration::from_secs(1));
                    output_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        let deadline = super::service::deadline(Duration::from_secs(30))?;
                        let result = {
                            let poll = service.receive_once(id.clone(), &mut receiver, &deadline);
                            tokio::pin!(poll);
                            loop {
                                tokio::select! {
                                    result=&mut poll=>break result,
                                    _=signal.changed()=>return Ok(()),
                                    _=output_timer.tick()=>{service.maintain(id.clone()).await?;},
                                }
                            }
                        };
                        if let Ok(received) = result {
                            if *signal.borrow() {
                                break;
                            }
                            service.maintain(id.clone()).await?;
                            backoff = Duration::from_secs(1);
                            if !received {
                                tokio::select! {_=tokio::time::sleep(Duration::from_secs(1))=>{},_=signal.changed()=>break};
                            }
                            continue;
                        }
                        receiver = None;
                        let retry_at = service
                            .health
                            .lock()
                            .map_err(|_| channel_error(ChannelError::ReceiverNotRunning))?
                            .get(&id)
                            .map(|observation| observation.health.clone());
                        let delay = match retry_at {
                            Some(ConnectionHealth::Retrying { retry_at_us, .. }) => now()
                                .ok()
                                .map(|now| {
                                    Duration::from_micros(
                                        retry_at_us.saturating_sub(now).max(0) as u64
                                    )
                                })
                                .unwrap_or(backoff)
                                .max(backoff),
                            _ => backoff,
                        };
                        if !matches!(retry_at, Some(ConnectionHealth::Retrying { .. })) {
                            let error = result
                                .err()
                                .map(|e| e.code().as_str())
                                .unwrap_or("receiver_unavailable");
                            service.set_health(
                                id.clone(),
                                ConnectionHealth::Unavailable { code: error.into() },
                            )?;
                        }
                        let jitter = se_proc::random_secret()
                            .map_err(|_| channel_error(ChannelError::ReceiverNotRunning))?;
                        let delay = delay
                            .saturating_add(Duration::from_millis(u64::from(jitter.expose()[0])));
                        tokio::select! {_=tokio::time::sleep(delay)=>{},_=signal.changed()=>break};
                        backoff = (backoff * 2).min(Duration::from_secs(60));
                    }
                    Ok(())
                });
                workers.insert(state.id, Receiver { stop, task });
            }
            if workers.is_empty() {
                timer = None;
            } else if timer.is_none() {
                timer = Some(tokio::time::interval_at(
                    tokio::time::Instant::now() + rescan_period,
                    rescan_period,
                ));
            }
        }
        for receiver in workers.values() {
            receiver.stop.send_replace(true);
        }
        for (_, receiver) in workers {
            if let Err(error) = joined(receiver.task.await) {
                failure = Some(error);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
/// Channels prevent the normal auto-start idle exit. They do not create a
/// second OS service or install login persistence behind the Owner's back.
pub(crate) async fn idle(activity: &mut watch::Receiver<u32>, channels: Arc<Channels>) {
    loop {
        crate::runtime::serve::idle_expiry(activity).await;
        let Ok(deadline) = super::service::deadline(Duration::from_secs(5)) else {
            return;
        };
        let changed = channels.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        match channels.has_active(&deadline).await {
            Ok(false) => return,
            Ok(true) => changed.await,
            // Unreadable is not idle. Retry a finite point read, preserving the
            // receiver instead of silently stopping a potentially active channel.
            Err(_) => tokio::time::sleep(Duration::from_secs(5)).await,
        }
    }
}

fn joined(result: std::result::Result<Result<()>, tokio::task::JoinError>) -> Result<()> {
    result
        .map_err(|error| se_core::scope::unreadable("channel receiver join", &error.to_string()))?
}
