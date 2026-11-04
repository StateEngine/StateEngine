//! Finite planning/submission jobs. A transaction never crosses an await and
//! an accepted FULL commit is observed before the native supervisor proceeds.
use super::*;
use crate::{BlockingClass, client::lease::Deadline};
use se_core::{admission::read_scope, commit::Cx, dispatch::Kernel, store_error::store_error};
use se_store::{Admission, AtomicBatch, CommitReceipt, Snapshot, SqliteSnapshot, WriterClient};
use se_types::{Generation, Read, Result};

pub(super) struct Store {
    pub reader: Arc<se_store::SqliteReader>,
    pub writer: se_store::SqliteClient,
    pub pool: BlockingPool,
    pub generation: Generation,
    pub pending: crate::runtime::PendingWrites,
    pub mail_waits: Arc<crate::http::mail::Waits>,
}
impl Store {
    pub async fn read<T: Send + 'static>(
        &self,
        admission: Admission,
        deadline: &Deadline,
        work: impl FnOnce(&mut Cx<'_, SqliteSnapshot>) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let reader = self.reader.clone();
        let generation = self.generation;
        self.pool
            .run(BlockingClass::Foreground, deadline, move || {
                let phase = reader.read_phase().map_err(|e| store_error(&e))?;
                let owner = phase.runtime_owner().map_err(|e| store_error(&e));
                let owner = match owner {
                    Ok(Read::Present { value }) if value.generation == generation => Ok(()),
                    Ok(_) => Err(se_core::scope::unreadable(
                        "process generation",
                        "owner generation differs or is unavailable",
                    )),
                    Err(e) => Err(e),
                };
                if let Err(e) = owner {
                    return crate::runtime::executor::close_read(Err(e), phase.close());
                }
                let mut read = phase
                    .into_snapshot(read_scope(&admission))
                    .map_err(|e| store_error(&e))?;
                let result = work(&mut Cx {
                    read: &mut read,
                    admission: &admission,
                });
                crate::runtime::executor::close_read(result, read.close())
            })
            .await
    }
    pub async fn commit(
        &self,
        admission: Admission,
        deadline: &Deadline,
        seed: Option<se_types::EventId>,
        work: impl FnOnce(&Kernel, &mut Cx<'_, SqliteSnapshot>) -> Result<AtomicBatch> + Send + 'static,
    ) -> Result<CommitReceipt> {
        let batch = self
            .read(admission, deadline, move |cx| {
                let mut facts = crate::runtime::start::allocate_facts()?;
                if let Some(seed) = seed {
                    facts.event = seed;
                }
                work(&Kernel::new(facts)?, cx)
            })
            .await?;
        let request = batch.request.as_ref().ok_or_else(|| {
            se_core::scope::unreadable(
                "lifecycle commit",
                "a retained phase request key is required",
            )
        })?;
        let identity = crate::runtime::WriteIdentity {
            operation: request.intent.operation,
            natural_key: None,
            key: Some(request.key.clone()),
            natural_events: Vec::new(),
        };
        let submitted = identity.clone();
        let recipients = crate::runtime::mail::recipients(&batch);
        let revocations = crate::runtime::mail::revocations(&batch);
        let writer = self.writer.clone();
        let pending = self.pending.clone();
        let mail_waits = self.mail_waits.clone();
        let runtime = self.pool.handle();
        let completion = self
            .pool
            .run_owned(deadline, move || {
                pending.register(&submitted)?;
                match writer.submit(batch) {
                    Ok(completion) => Ok(runtime.spawn(async move {
                        let receipt = completion.await;
                        let settled = match &receipt {
                            Ok(_) => pending.resolve(&submitted),
                            Err(error)
                                if error.code == se_store::StoreErrorCode::CommitOutcomeUnknown =>
                            {
                                Ok(())
                            }
                            Err(_) => pending.failed_attempt(&submitted),
                        };
                        let notified = if receipt.is_ok() {
                            mail_waits
                                .committed(&recipients)
                                .and_then(|()| mail_waits.revoked(&revocations))
                        } else {
                            Ok(())
                        };
                        (receipt, settled.and(notified))
                    })),
                    Err(error) => {
                        pending.failed_attempt(&submitted)?;
                        Err(submitted.store_error(&error))
                    }
                }
            })
            .await?;
        // The retained supervisor awaits an accepted transaction even beyond
        // the client's clock. The independent observer also survives a panic
        // or dropped supervisor and keeps uncertain outcomes in PendingWrites.
        let (receipt, settled) = completion
            .await
            .map_err(|cause| identity.wait_error(error("lifecycle completion observer", cause)))?;
        match receipt {
            Ok(receipt) => {
                settled.map_err(|cause| {
                    crate::runtime::CommittedWrite {
                        operation: identity.operation.into(),
                        key: identity.key.clone(),
                        natural_events: Vec::new(),
                        committed_events: receipt.events.clone(),
                    }
                    .response_error(cause)
                })?;
                Ok(receipt)
            }
            Err(error) => {
                let error = identity.store_error(&error);
                Err(match settled {
                    Ok(()) => error,
                    Err(cause) => error.with_cause(cause),
                })
            }
        }
    }
}
