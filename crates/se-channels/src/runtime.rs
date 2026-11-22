//! One receiver under the existing host generation and store lease.
use super::{service::*, *};
use crate::host::AsChannelDeadline;
use se_core::store_error::store_error;
use se_store::{Snapshot, channel::Connection};
use se_types::Result;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::watch;

struct Receiver {
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<()>>,
}
struct Running(Arc<Channels>);
impl Drop for Running {
    fn drop(&mut self) {
        self.0
            .receiver_running
            .store(false, std::sync::atomic::Ordering::Release);
        self.0.changed.notify_waiters();
    }
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
                self.unavailable(id.clone(), error.code().as_str())?;
            }
        }
        Ok(())
    }
    pub async fn has_active(&self, deadline: &impl AsChannelDeadline) -> Result<bool> {
        let deadline = &deadline.as_channel_deadline();
        self.read(None, deadline, |cx| {
            cx.read
                .channel_active()
                .map(|v| !v.is_empty())
                .map_err(|e| store_error(&e))
        })
        .await
    }
    async fn active_scan(&self) -> Result<Vec<Connection>> {
        let deadline = super::service::deadline(Duration::from_secs(5))?;
        self.read(None, &deadline, |cx| {
            cx.read.channel_active().map_err(|e| store_error(&e))
        })
        .await
    }
    async fn retire_worker(
        &self,
        id: ChannelId,
        receiver: Receiver,
    ) -> Result<Option<se_types::SeError>> {
        receiver.stop.send_replace(true);
        let join = joined(receiver.task.await);
        self.health
            .lock()
            .map_err(|_| channel_error(ChannelError::ReceiverNotRunning))?
            .remove(&id);
        self.health_version
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.changed.notify_waiters();
        Ok(join.err())
    }
    pub async fn run<T: Send + Sync + 'static>(
        self: Arc<Self>,
        mut stopped: watch::Receiver<Option<T>>,
        intervals: ReceiverIntervals,
    ) -> Result<()> {
        self.receiver_running
            .store(true, std::sync::atomic::Ordering::Release);
        let _running = Running(self.clone());
        let mut workers: HashMap<ChannelId, Receiver> = HashMap::new();
        let rescan_period = intervals.rescan;
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
            let scan = self.active_scan();
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
            let retired = retired_workers(&workers, &states);
            // Join the retired poller before another connection can use its bot.
            for id in retired {
                if let Some(receiver) = workers.remove(&id)
                    && let Some(error) = self.retire_worker(id, receiver).await?
                {
                    failure = Some(error);
                }
            }
            for state in states {
                if workers.contains_key(&state.id) {
                    continue;
                }
                let (stop, signal) = watch::channel(false);
                let service = self.clone();
                let id = state.id.clone();
                let task = receiver_task(service, id, intervals.poll, signal);
                workers.insert(state.id, Receiver { stop, task });
            }
            update_rescan_timer(workers.is_empty(), &mut timer, rescan_period);
        }
        if let Some(error) = drain_failure(workers).await {
            failure = Some(error);
        }
        failure.map_or(Ok(()), Err)
    }
}
fn joined(result: std::result::Result<Result<()>, tokio::task::JoinError>) -> Result<()> {
    result
        .map_err(|error| se_core::scope::unreadable("channel receiver join", &error.to_string()))?
}

fn retired_workers(
    workers: &HashMap<ChannelId, Receiver>,
    states: &[Connection],
) -> Vec<ChannelId> {
    workers
        .keys()
        .filter(|id| {
            !states.iter().any(|s| s.id == **id)
                || workers
                    .get(*id)
                    .is_some_and(|worker| worker.task.is_finished())
        })
        .cloned()
        .collect()
}
fn receiver_task(
    service: Arc<Channels>,
    id: ChannelId,
    poll: Duration,
    mut signal: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        let mut receiver = None;
        let mut output_timer = tokio::time::interval(poll);
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
                    tokio::select! {_=tokio::time::sleep(poll)=>{},_=signal.changed()=>break};
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
                    .map(|now| Duration::from_micros(retry_at_us.saturating_sub(now).max(0) as u64))
                    .unwrap_or(backoff)
                    .max(backoff),
                _ => backoff,
            };
            if !matches!(retry_at, Some(ConnectionHealth::Retrying { .. }))
                && let Err(error) = result
            {
                service.unavailable(id.clone(), error.code().as_str())?;
            }
            let jitter = se_proc::random_secret()
                .map_err(|_| channel_error(ChannelError::ReceiverNotRunning))?;
            let delay = delay.saturating_add(Duration::from_millis(u64::from(jitter.expose()[0])));
            tokio::select! {_=tokio::time::sleep(delay)=>{},_=signal.changed()=>break};
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
        Ok(())
    })
}
async fn drain_failure(workers: HashMap<ChannelId, Receiver>) -> Option<se_types::SeError> {
    for receiver in workers.values() {
        receiver.stop.send_replace(true);
    }
    let mut failure = None;
    for (_, receiver) in workers {
        if let Err(error) = joined(receiver.task.await) {
            failure = Some(error);
        }
    }
    failure
}
fn update_rescan_timer(
    workers_empty: bool,
    timer: &mut Option<tokio::time::Interval>,
    rescan: Duration,
) {
    if workers_empty {
        *timer = None;
    } else if timer.is_none() {
        *timer = Some(tokio::time::interval_at(
            tokio::time::Instant::now() + rescan,
            rescan,
        ));
    }
}
