//! A bounded retained request/result registry for stop and removal. A client
//! disconnect never detaches a native effect or accepted transaction.
use super::*;
use crate::client::lease::Deadline;
use se_core::ops::AnyOutput;
use se_types::{ErrorBody, Result, SeError};
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::watch;
#[derive(Default)]
pub(super) struct Controls(Mutex<BTreeMap<String, Arc<Control>>>);
type Retry =
    dyn Fn(Deadline) -> Pin<Box<dyn Future<Output = Result<AnyOutput>> + Send>> + Send + Sync;
struct Control {
    intent: [u8; 32],
    execute: Arc<Retry>,
    retryable: AtomicBool,
    ready: watch::Sender<Option<std::result::Result<AnyOutput, ErrorBody>>>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}
impl LaunchCoordinator {
    pub(super) async fn join_controls(
        &self,
        deadline: &Deadline,
        pending: &mut Vec<String>,
    ) -> Result<()> {
        let controls = self
            .controls
            .0
            .lock()
            .map_err(|_| error("process request shutdown", "poisoned registry"))?
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        for (key, control) in controls {
            let task = control
                .task
                .lock()
                .map_err(|_| error("process request shutdown", "poisoned task slot"))?
                .take();
            if let Some(mut task) = task {
                match tokio::time::timeout_at(
                    tokio::time::Instant::from_std(deadline.at()),
                    &mut task,
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => pending.push(format!("{key}: request join failed: {error}")),
                    Err(_) => {
                        *control.task.lock().map_err(|_| {
                            error("process request shutdown", "poisoned task slot")
                        })? = Some(task);
                        pending.push(format!("{key}: request join remains retained"));
                    }
                }
            }
        }
        Ok(())
    }
    pub(super) async fn supervise_control<
        F: Future<Output = Result<AnyOutput>> + Send + 'static,
    >(
        &self,
        key: String,
        intent: [u8; 32],
        deadline: &Deadline,
        execute: impl Fn(Deadline) -> F + Send + Sync + 'static,
    ) -> Result<AnyOutput> {
        let (control, new) = {
            let mut controls = self.controls.0.lock().map_err(|_| {
                SeError::invalid("process request registry", "an unpoisoned registry")
            })?;
            if self.stopping.load(Ordering::Acquire) {
                return Err(error(
                    "process request admission",
                    "shutdown is joining retained cleanup; reconnect after it completes",
                ));
            }
            if let Some(control) = controls.get(&key) {
                if control.intent != intent {
                    return Err(SeError::invalid(
                        "process request key",
                        "the original operation, target and options",
                    ));
                }
                let retry =
                    control.ready.borrow().is_some() && control.retryable.load(Ordering::Acquire);
                if retry {
                    // Clear under the registry lock: another caller joins this
                    // attempt instead of starting a second cleanup concurrently.
                    control.ready.send_replace(None);
                    control.retryable.store(false, Ordering::Release);
                }
                (control.clone(), retry)
            } else {
                if controls.len() >= 128
                    && let Some(old) = controls
                        .iter()
                        .find(|(_, c)| {
                            c.ready.borrow().is_some() && !c.retryable.load(Ordering::Acquire)
                        })
                        .map(|(k, _)| k.clone())
                {
                    controls.remove(&old);
                }
                if controls.len() >= 128 {
                    return Err(SeError::invalid(
                        "process request capacity",
                        "finish retained requests before submitting more",
                    ));
                }
                let control = Arc::new(Control {
                    intent,
                    execute: Arc::new(move |deadline| Box::pin(execute(deadline))),
                    retryable: AtomicBool::new(false),
                    ready: watch::channel(None).0,
                    task: Mutex::new(None),
                });
                controls.insert(key, control.clone());
                (control, true)
            }
        };
        if new {
            let owned = control.clone();
            let previous = control
                .task
                .lock()
                .map_err(|_| error("process request retry", "poisoned task slot"))?
                .take();
            let job = (control.execute)(deadline.retained());
            let task = self.store.pool.handle().spawn(async move {
                if let Some(previous) = previous
                    && let Err(failure) = previous.await
                {
                    owned.retryable.store(true, Ordering::Release);
                    owned
                        .ready
                        .send_replace(Some(Err(error("retained request join", failure).body)));
                    return;
                }
                let result = job.await;
                let retry = match &result {
                    Ok(AnyOutput::AgentStop(output)) => !output.value.complete,
                    // Rejoin the original successor job, retaining any achieved stop report.
                    Ok(AnyOutput::AgentLaunch(output)) => {
                        matches!(&output.value, se_core::ops::LaunchReply::Pending(_))
                    }
                    Err(_) => true,
                    _ => false,
                };
                owned.retryable.store(retry, Ordering::Release);
                owned.ready.send_replace(Some(result.map_err(|e| e.body)));
            });
            *control
                .task
                .lock()
                .map_err(|_| SeError::invalid("process request task", "a retained task slot"))? =
                Some(task);
        }
        let mut ready = control.ready.subscribe();
        loop {
            if let Some(result) = ready.borrow().clone() {
                return result.map_err(|body| SeError { body, cause: None });
            }
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline.at()),ready.changed()).await.map_err(|_|se_core::scope::unreadable("process request wait","the retained request continues under its original deadline; retry its original key"))?.map_err(|e|error("process request supervisor",e))?;
        }
    }
}
