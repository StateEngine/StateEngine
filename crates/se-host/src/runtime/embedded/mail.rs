//! A bounded registry and coalesced hints for SE Code's sole native queue.
//! Reservations and offer receipts remain in the shared store/core planner.
#![allow(
    clippy::result_large_err,
    reason = "Preserve API 2 callback errors by value."
)]
mod delivery;
mod status;
mod step;
use super::{Generation, binding, store, support};
use crate::{
    HostedRouter,
    linked::{FromLinked, ToLinked},
    runtime::mail::NativeSignal,
};
use se_core::{scope, store_error::store_error};
use se_types::{Result, SeError};
use secode_stateengine_api as api;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
mod worker;
pub(super) use worker::drive;

#[derive(Clone)]
struct Registration {
    target: api::HostSessionTarget,
    signal: Arc<NativeSignal>,
    error: Option<api::ApiError>,
    retry_at: Option<tokio::time::Instant>,
    backoff: Duration,
}
pub(super) struct Registry {
    entries: Mutex<BTreeMap<String, Registration>>,
    changed: Arc<Notify>,
    closed: AtomicBool,
}
impl Registry {
    pub(super) fn new() -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
            changed: Arc::new(Notify::new()),
            closed: AtomicBool::new(false),
        }
    }
    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.changed.notify_one();
    }
}
fn registry_error() -> SeError {
    scope::unreadable("native mail registrations", "registry poisoned")
}
fn revision() -> api::Revision {
    api::Revision(std::num::NonZeroU64::MIN.saturating_add(1))
}
fn recipient(target: &api::HostSessionTarget) -> Result<crate::MailRecipient> {
    Ok(crate::MailRecipient {
        project: se_types::ProjectId::from_linked(target.binding.project.clone())?,
        agent: se_types::AgentId::from_linked(target.binding.agent.clone())?,
    })
}
fn scope(
    target: &api::HostSessionTarget,
    generation: api::Generation,
) -> Result<se_store::ReadScope> {
    let who = recipient(target)?;
    Ok(se_store::ReadScope {
        admission: se_store::Admission {
            scope: se_store::Scope::Project(who.project),
            actor: se_store::Actor::Agent(who.agent.clone()),
            session: Some(se_types::SessionId::from_linked(
                target.binding.session.clone(),
            )?),
            generation: generation.0,
        },
        visibility: se_store::Visibility::SelfOnly(who.agent),
    })
}
impl Generation {
    pub(super) async fn revoke_native(
        &self,
        id: &se_types::SessionId,
        key: &api::IdempotencyKey,
        options: &api::CallOptions,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};
        let registered = self
            .mail
            .entries
            .lock()
            .map_err(|_| registry_error())?
            .get(id.as_str())
            .cloned();
        let Some(registered) = registered else {
            return Ok(());
        };
        let (_, services) = self.services().map_err(native_error)?;
        let digest = se_types::hex_lower(&Sha256::digest(
            format!("{}:{}", id.as_str(), key.0).as_bytes(),
        ));
        services
            .hold(
                &registered.target,
                api::HoldReason::Revocation,
                api::IdempotencyKey(format!("native.hold.{digest}")),
                self.service_options(options, deadline)
                    .map_err(native_error)?,
            )
            .await
            .map_err(native_error)?;
        services
            .update_mail_target(
                api::TargetTransition::Revoke {
                    target: registered.target.clone(),
                },
                api::IdempotencyKey(format!("native.revoke.{digest}")),
                self.service_options(options, deadline)
                    .map_err(native_error)?,
            )
            .await
            .map_err(native_error)?;
        Ok(())
    }
    fn services(&self) -> api::Result<(api::HostEpoch, Arc<dyn api::HostServices>)> {
        self.native
            .lock()
            .map_err(|_| support::unavailable("native registration"))?
            .clone()
            .ok_or_else(|| support::unavailable("activated native services"))
    }
    fn service_options(
        &self,
        options: &api::CallOptions,
        deadline: &crate::client::lease::Deadline,
    ) -> api::Result<api::ServiceOptions> {
        Ok(api::ServiceOptions {
            generation: options.generation,
            timeout: deadline
                .remaining()
                .map_err(|e| support::api_error(&e))?
                .min(Duration::from_secs(3)),
            cancellation: options.cancellation.clone(),
        })
    }
    pub(super) async fn register_native(
        &self,
        target: &api::HostSessionTarget,
        options: api::CallOptions,
    ) -> api::Result<()> {
        if !self.negotiated.features.contains(&api::Feature::NativeMail) {
            return Err(support::unavailable("NativeMail was not negotiated"));
        }
        let (router, deadline, _cancel) = self
            .ready(&options)
            .await
            .map_err(|e| support::api_error(&e))?;
        let (epoch, services) = self.services()?;
        if target.epoch != epoch {
            return Err(support::refused(
                "native mail epoch",
                "this exact native registration",
            ));
        }
        self.bindings
            .current(&target.binding)
            .map_err(|e| support::api_error(&e))?;
        let admitted = scope(target, options.generation).map_err(|e| support::api_error(&e))?;
        let checked = admitted.clone();
        store::read(&router, admitted, &deadline, move |read| {
            binding::check(read, &checked, revision())
        })
        .await
        .map_err(|e| support::api_error(&e))?;
        // A nudge contains no ACK or authority to select/unhold a target.
        match services
            .binding_state(target, self.service_options(&options, &deadline)?)
            .await?
        {
            api::Read::Present { .. } => (),
            other => return Err(read_error("native binding registration", other)),
        }
        let signal = {
            let mut entries = self
                .mail
                .entries
                .lock()
                .map_err(|_| support::api_error(&registry_error()))?;
            if self.mail.closed.load(Ordering::Acquire) {
                return Err(support::refused(
                    "native mail",
                    "a live generation before drain",
                ));
            }
            if let Some(entry) = entries.get(&target.binding.session.0) {
                if entry.target != *target {
                    return Err(support::refused(
                        "native mail target",
                        "the immutable registered target for this issued session",
                    ));
                }
                entry.signal.clone()
            } else {
                if entries.len() >= 128 {
                    return Err(support::refused(
                        "native mail capacity",
                        "at most 128 issued bindings per generation",
                    ));
                }
                let signal = Arc::new(NativeSignal::new(self.mail.changed.clone()));
                entries.insert(
                    target.binding.session.0.clone(),
                    Registration {
                        target: target.clone(),
                        signal: signal.clone(),
                        error: None,
                        retry_at: None,
                        backoff: Duration::from_secs(1),
                    },
                );
                signal
            }
        };
        router
            .execution
            .mail_waits
            .register_native(
                recipient(target).map_err(|e| support::api_error(&e))?,
                &signal,
            )
            .map_err(|e| support::api_error(&e))?;
        signal.wake();
        Ok(())
    }
}
fn native_error(error: api::ApiError) -> SeError {
    scope::unreadable(
        "native target revocation",
        &format!(
            "{}: {}; {}. Native holds or revocation may already be committed; retry the same request key",
            error.code, error.message, error.remedy.text
        ),
    )
}
fn read_error<T>(subject: &str, value: api::Read<T>) -> api::ApiError {
    match value {
        api::Read::Unreadable {
            error: Some(error), ..
        } => error,
        api::Read::Unreadable { source, reason, .. } => {
            support::api_error(&scope::unreadable(&source, &reason))
        }
        api::Read::Unknown { what } => support::api_error(&scope::unreadable(subject, &what)),
        api::Read::Absent { checked } => support::refused(
            subject,
            &format!("a verified Present native observation; absent: {checked}"),
        ),
        api::Read::Present { .. } => support::refused(subject, "a consistent observation"),
    }
}

#[derive(Debug)]
struct WorkerCancellation;
impl api::Cancellation for WorkerCancellation {
    fn is_cancelled(&self) -> bool {
        false
    }
    fn cancelled(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(std::future::pending())
    }
}
