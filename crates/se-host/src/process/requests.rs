//! A bounded retained request/result registry for stop and removal. A client
//! disconnect never detaches a native effect or accepted transaction.
use super::*;
use crate::client::lease::Deadline;
use se_core::ops::AnyOutput;
use se_types::{ErrorBody, Result, SeError};
use std::{collections::BTreeMap, future::Future, sync::Mutex};
use tokio::sync::watch;
#[derive(Default)]
pub(super) struct Controls(Mutex<BTreeMap<String, Arc<Control>>>);
struct Control {
    intent: [u8; 32],
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
        execute: impl FnOnce(Deadline) -> F,
    ) -> Result<AnyOutput> {
        let (control, new) = {
            let mut controls = self.controls.0.lock().map_err(|_| {
                SeError::invalid("process request registry", "an unpoisoned registry")
            })?;
            if let Some(control) = controls.get(&key) {
                if control.intent != intent {
                    return Err(SeError::invalid(
                        "process request key",
                        "the original operation, target and options",
                    ));
                }
                (control.clone(), false)
            } else {
                if controls.len() >= 128
                    && let Some(old) = controls
                        .iter()
                        .find(|(_, c)| c.ready.borrow().is_some())
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
                    ready: watch::channel(None).0,
                    task: Mutex::new(None),
                });
                controls.insert(key, control.clone());
                (control, true)
            }
        };
        if new {
            let owned = control.clone();
            let job = execute(deadline.retained());
            let task = self.store.pool.handle().spawn(async move {
                owned
                    .ready
                    .send_replace(Some(job.await.map_err(|e| e.body)));
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
