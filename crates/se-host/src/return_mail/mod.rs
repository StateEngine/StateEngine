//! Optional source couriers retain only bounded native-admitted active routes.
use crate::remote::{
    broker::{RemoteBroker, VerifiedSourceSession},
    session, *,
};
use crate::runtime::ExecutionContext;
use se_core::store_error::store_error;
use se_core::{admission::HumanTerminal, ops::remote::*};
use se_remote::broker::Binding;
use se_store::remote::{MailContact, MailRoute as Route, MailboxChange, PendingContact};
use se_store::{Actor, Admission, RecordIdentity, Scope};
use se_types::{IdempotencyKey, Receipt};
use se_types::{Result, SeError};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
mod contact;
mod push;
mod receive;
mod scheduler;
mod worker;
mod write;

struct MailTask {
    source: RemoteAgentAddress,
    task: tokio::task::JoinHandle<Result<()>>,
    error: Arc<Mutex<Option<se_types::ErrorBody>>>,
}
#[derive(Default)]
pub(crate) struct Mailboxes {
    pub(crate) writes: tokio::sync::Mutex<()>,
    tasks: Mutex<HashMap<String, MailTask>>,
}
impl Mailboxes {
    pub(crate) async fn close(&self) -> Result<()> {
        let tasks: Vec<_> = self
            .tasks
            .lock()
            .map_err(|_| poisoned())?
            .drain()
            .map(|(_, v)| v)
            .collect();
        for task in &tasks {
            task.task.abort();
        }
        let mut failure = None;
        for task in tasks {
            match task.task.await {
                Ok(Ok(())) => (),
                Err(error) if error.is_cancelled() => (),
                Ok(Err(error)) => {
                    failure.get_or_insert(error);
                }
                Err(_) => {
                    failure.get_or_insert_with(|| {
                        refused("return-mail courier did not close cleanly")
                    });
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

impl RemoteBroker {
    pub(crate) async fn start_mail(
        self: &Arc<Self>,
        context: &ExecutionContext,
        source: VerifiedSourceSession,
    ) -> Result<Option<se_types::ErrorBody>> {
        self.check_open()?;
        source.context().check_current()?;
        let address = source.source().address();
        let finished: Vec<_> = {
            let mut tasks = self.mailbox.tasks.lock().map_err(|_| poisoned())?;
            let keys: Vec<_> = tasks
                .iter()
                .filter(|(_, t)| t.task.is_finished())
                .map(|(key, _)| key.clone())
                .collect();
            keys.into_iter()
                .filter_map(|key| tasks.remove(&key))
                .collect()
        };
        let mut failure = None;
        for task in finished {
            let same_source = task.source == address;
            match task.task.await {
                Ok(Ok(())) => (),
                Ok(Err(error)) => {
                    if failure.is_none() {
                        failure = Some(if same_source {
                            error
                        } else {
                            refused(
                                "a source courier ended unexpectedly; retry to restore the current source courier",
                            )
                        });
                    }
                }
                Err(_) => {
                    if failure.is_none() {
                        failure = Some(refused(
                            "return-mail courier ended without a completion witness; retry through the current source session",
                        ));
                    }
                }
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        let key = serde_json::to_string(&(source.source(), source.credential().as_bytes()))
            .map_err(|_| poisoned())?;
        {
            let tasks = self.mailbox.tasks.lock().map_err(|_| poisoned())?;
            if let Some(task) = tasks.get(&key) {
                return Ok(task.error.lock().map_err(|_| poisoned())?.clone());
            }
        }
        let lookup = address.clone();
        if !read(context, move |p| p.has_remote_mail_for(&lookup)).await? {
            return Ok(None);
        }
        let mut tasks = self.mailbox.tasks.lock().map_err(|_| poisoned())?;
        if let Some(task) = tasks.get(&key) {
            return Ok(task.error.lock().map_err(|_| poisoned())?.clone());
        }
        if tasks.len() >= MAX_SOURCES {
            return Err(refused(
                "return-mail source capacity reached; finish an older source session before starting another",
            ));
        }
        let broker = self.clone();
        let context = context.clone();
        let error = Arc::new(Mutex::new(None));
        let state = error.clone();
        let task = tokio::spawn(async move { broker.courier(context, source, state).await });
        tasks.insert(
            key,
            MailTask {
                source: address,
                task,
                error,
            },
        );
        Ok(None)
    }
}

fn source_admission(source: &VerifiedSourceSession) -> Admission {
    Admission {
        scope: Scope::Project(source.source().project.clone()),
        actor: Actor::Agent(source.source().agent.clone()),
        session: Some(source.source().session.clone()),
        generation: source.source().generation.get(),
    }
}

async fn read<T: Send + 'static>(
    context: &ExecutionContext,
    work: impl FnOnce(&se_store::ReadPhase) -> se_store::StoreResult<T> + Send + 'static,
) -> Result<T> {
    let reads = context.reads.clone();
    let generation = context.generation;
    context
        .blocking
        .run_owned(&session::control::deadline()?, move || {
            let phase = crate::runtime::executor::checked_pooled_phase(&reads, generation)?;
            let result = work(&phase).map_err(|e| store_error(&e));
            crate::runtime::executor::close_read(result, phase.close())
        })
        .await
}

async fn background_read<T: Send + 'static>(
    context: &ExecutionContext,
    work: impl FnOnce(&se_store::ReadPhase) -> se_store::StoreResult<T> + Send + 'static,
) -> Result<T> {
    let reads = context.reads.clone();
    let generation = context.generation;
    context
        .blocking
        .run(
            crate::runtime::BlockingClass::Background,
            &session::control::deadline()?,
            move || {
                let phase = crate::runtime::executor::checked_pooled_phase(&reads, generation)?;
                let result = work(&phase).map_err(|e| store_error(&e));
                crate::runtime::executor::close_read(result, phase.close())
            },
        )
        .await
}

const MAX_SOURCES: usize = 64;
fn poisoned() -> SeError {
    refused("return-mail state is unreadable")
}
fn refused(reason: &str) -> SeError {
    se_remote::authority_refused(reason)
}
fn check_size(value: &impl serde::Serialize, budget: u32) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| poisoned())?;
    if bytes.len() > budget as usize {
        return Err(SeError::too_large(
            "remote response",
            budget as usize,
            bytes.len(),
        ));
    }
    Ok(())
}
mod destination;
