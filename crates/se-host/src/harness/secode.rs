//! Concrete translation of SE Code's sole native queue, not another queue.
//! The registration binds one immutable G/epoch; replacement never rebinds it.
//! The debt planner reserves before deliver and queries original notice_status
//! after uncertainty; this adapter never invents a reservation or read marker.
#[cfg(test)]
mod fixture;
#[cfg(test)]
mod tests;
mod validate;
use crate::linked::FromLinked;
use secode_stateengine_api as api;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

pub(crate) struct SecodeAdapter {
    epoch: api::HostEpoch,
    generation: api::Generation,
    services: Arc<dyn api::HostServices>,
    fenced: Arc<AtomicBool>,
    // Bounded native adoption witnesses/reservations; no input or queue state.
    adoptions: Mutex<Vec<(api::HostSessionTarget, api::HostSessionTarget, bool)>>,
}
impl SecodeAdapter {
    pub(crate) fn new(
        epoch: api::HostEpoch,
        generation: api::Generation,
        services: Arc<dyn api::HostServices>,
        fenced: Arc<AtomicBool>,
    ) -> api::Result<Self> {
        se_types::HostEpoch::from_linked(epoch.clone()).map_err(validate::conversion)?;
        se_types::Generation::new(generation.0).map_err(validate::conversion)?;
        Ok(Self {
            epoch,
            generation,
            services,
            fenced,
            adoptions: Mutex::new(Vec::new()),
        })
    }
    fn check(&self, options: &api::ServiceOptions) -> api::Result<()> {
        if options.generation != self.generation || self.fenced.load(Ordering::Acquire) {
            return Err(validate::error(
                api::ApiFailure::GenerationPoisoned,
                "native-generation-fenced",
                "This native registration belongs to a fenced or different generation.",
            ));
        }
        if options.cancellation.is_cancelled() || options.timeout.is_zero() {
            return Err(validate::error(
                api::ApiFailure::Cancelled,
                "native-call-cancelled",
                "The native call was cancelled or its deadline expired; this proves no rollback of a previous attempt.",
            ));
        }
        Ok(())
    }
    fn target(&self, target: &api::HostSessionTarget) -> api::Result<()> {
        validate::target(target)?;
        validate::same(target.epoch == self.epoch)
    }
    async fn run<T>(
        &self,
        options: &api::ServiceOptions,
        call: api::HostFuture<'_, T>,
    ) -> api::Result<T> {
        self.check(options)?;
        let result = match futures_util::future::select(
            options.cancellation.cancelled(),
            Box::pin(tokio::time::timeout(options.timeout, call)),
        )
        .await
        {
            futures_util::future::Either::Left(_) => Err(validate::uncertain()),
            futures_util::future::Either::Right((result, _)) => {
                result.map_err(|_| validate::uncertain())?
            }
        };
        if self.fenced.load(Ordering::Acquire) {
            return Err(validate::error(
                api::ApiFailure::GenerationPoisoned,
                "native-generation-fenced",
                "The native generation was fenced while its callback was in flight; preserve the original effect identity.",
            ));
        }
        result
    }
    fn admission(
        &self,
        target: &api::HostSessionTarget,
        id: &api::NoticeId,
        result: &api::NoticeAdmission,
        digest: Option<api::Sha256>,
    ) -> api::Result<()> {
        match result {
            api::NoticeAdmission::Admitted(value) | api::NoticeAdmission::Replayed(value) => {
                validate::target(&value.target)?;
                validate::event(&value.committed)?;
                se_types::HostPendingId::from_linked(value.pending.clone())
                    .map_err(validate::conversion)?;
                validate::same(
                    value.notice == *id
                        && value.committed_in == value.target.epoch
                        && digest.is_none_or(|expected| value.dedupe_sha256 == expected),
                )?;
                if value.target != *target {
                    let mappings = self.adoptions.lock().map_err(|_| validate::invalid())?;
                    validate::same(mappings.iter().any(|(old, new, verified)| {
                        *verified && old == &value.target && new == target
                    }))?;
                }
                Ok(())
            }
            api::NoticeAdmission::Held(held) => validate::hold(held, target),
            api::NoticeAdmission::Refused(_) => Ok(()),
        }
    }
}
impl api::HostServices for SecodeAdapter {
    fn hold<'a>(
        &'a self,
        target: &'a api::HostSessionTarget,
        reason: api::HoldReason,
        key: api::IdempotencyKey,
        options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::HoldReceipt> {
        Box::pin(async move {
            self.check(&options)?;
            self.target(target)?;
            validate::key(&key)?;
            let value = self
                .run(
                    &options,
                    self.services
                        .hold(target, reason, key.clone(), options.clone()),
                )
                .await?;
            validate::hold(&value, target)?;
            validate::same(value.idempotency_key == key)?;
            Ok(value)
        })
    }
    fn interrupt<'a>(
        &'a self,
        held: &'a api::HoldReceipt,
        options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::InterruptReceipt> {
        Box::pin(async move {
            self.check(&options)?;
            self.target(&held.target)?;
            validate::hold(held, &held.target)?;
            let value = self
                .run(&options, self.services.interrupt(held, options.clone()))
                .await?;
            validate::same(value.target == held.target)?;
            Ok(value)
        })
    }
    fn active_session<'a>(
        &'a self,
        target: &'a api::HostSessionTarget,
        options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<Option<api::ActiveSession>>> {
        Box::pin(async move {
            self.check(&options)?;
            self.target(target)?;
            let value = self
                .run(
                    &options,
                    self.services.active_session(target, options.clone()),
                )
                .await?;
            if let api::Read::Present { value: Some(row) } = &value {
                validate::same(row.target == *target)?;
            }
            Ok(value)
        })
    }
    fn active_sessions<'a>(
        &'a self,
        epoch: &'a api::HostEpoch,
        page: api::PageRequest,
        options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::Page<api::ActiveSession>>> {
        Box::pin(async move {
            self.check(&options)?;
            validate::same(*epoch == self.epoch)?;
            validate::page_request(&page)?;
            let value = self
                .run(
                    &options,
                    self.services
                        .active_sessions(epoch, page.clone(), options.clone()),
                )
                .await?;
            if let api::Read::Present { value: rows } = &value {
                validate::page(rows, &page, epoch)?;
                for row in &rows.items {
                    self.target(&row.target)?;
                }
            }
            Ok(value)
        })
    }
    fn idle<'a>(
        &'a self,
        target: &'a api::HostSessionTarget,
        options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::SessionActivity>> {
        Box::pin(async move {
            self.check(&options)?;
            self.target(target)?;
            self.run(&options, self.services.idle(target, options.clone()))
                .await
        })
    }
    fn binding_state<'a>(
        &'a self,
        target: &'a api::HostSessionTarget,
        options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::BindingObservation>> {
        Box::pin(async move {
            self.check(&options)?;
            self.target(target)?;
            let value = self
                .run(
                    &options,
                    self.services.binding_state(target, options.clone()),
                )
                .await?;
            validate::binding(&value, target)?;
            Ok(value)
        })
    }
    fn adopt_binding<'a>(
        &'a self,
        request: api::AdoptBinding,
        options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::BindingObservation>> {
        Box::pin(async move {
            self.check(&options)?;
            validate::target(&request.previous)?;
            validate::key(&request.idempotency_key)?;
            validate::same(request.current_epoch == self.epoch)?;
            let mut current = request.previous.clone();
            current.epoch = self.epoch.clone();
            // Reserve mapping capacity before crossing the async boundary. An
            // uncertain callback retains this slot for same-identity retry; it
            // grants no original-epoch receipt authority until verified.
            {
                let mut mappings = self.adoptions.lock().map_err(|_| validate::invalid())?;
                if !mappings
                    .iter()
                    .any(|(old, new, _)| old == &request.previous && new == &current)
                {
                    validate::same(mappings.len() < 128)?;
                    mappings.push((request.previous.clone(), current.clone(), false));
                }
            }
            let value = self
                .run(
                    &options,
                    self.services
                        .adopt_binding(request.clone(), options.clone()),
                )
                .await?;
            validate::binding(&value, &current)?;
            if matches!(value, api::Read::Present { .. }) {
                let mut mappings = self.adoptions.lock().map_err(|_| validate::invalid())?;
                let mapping = mappings
                    .iter_mut()
                    .find(|(old, new, _)| old == &request.previous && new == &current)
                    .ok_or_else(validate::invalid)?;
                mapping.2 = true;
            }
            Ok(value)
        })
    }
    fn update_mail_target<'a>(
        &'a self,
        transition: api::TargetTransition,
        key: api::IdempotencyKey,
        options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::TargetReceipt> {
        Box::pin(async move {
            self.check(&options)?;
            validate::key(&key)?;
            let (target, expected) = match &transition {
                api::TargetTransition::Select { target, superseded } => {
                    validate::same(superseded.len() <= 128)?;
                    for old in superseded {
                        self.target(old)?;
                    }
                    (target, api::TargetStatus::Eligible)
                }
                api::TargetTransition::Revoke { target } => (target, api::TargetStatus::Revoked),
            };
            self.target(target)?;
            let target = target.clone();
            // Native Select must atomically recheck holds/nonexecution. A prior
            // idle observation or interrupt ACK is never substituted for that.
            let value = self
                .run(
                    &options,
                    self.services
                        .update_mail_target(transition, key, options.clone()),
                )
                .await?;
            validate::event(&value.committed)?;
            validate::same(
                value.target == target
                    && (value.status == expected
                        || (expected == api::TargetStatus::Eligible
                            && value.status == api::TargetStatus::Held)),
            )?;
            Ok(value)
        })
    }
    fn deliver_notice<'a>(
        &'a self,
        notice: &'a api::MailNotice,
        options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::NoticeAdmission> {
        Box::pin(async move {
            self.check(&options)?;
            self.target(&notice.target)?;
            validate::notice(notice)?;
            let value = self
                .run(
                    &options,
                    self.services.deliver_notice(notice, options.clone()),
                )
                .await?;
            self.admission(
                &notice.target,
                &notice.id,
                &value,
                Some(notice.dedupe_sha256),
            )?;
            Ok(value)
        })
    }
    fn notice_status<'a>(
        &'a self,
        target: &'a api::HostSessionTarget,
        notice: &'a api::NoticeId,
        options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::NoticeAdmission>> {
        Box::pin(async move {
            self.check(&options)?;
            self.target(target)?;
            se_types::NoticeId::from_linked(notice.clone()).map_err(validate::conversion)?;
            let value = self
                .run(
                    &options,
                    self.services.notice_status(target, notice, options.clone()),
                )
                .await?;
            if let api::Read::Present { value: admission } = &value {
                self.admission(target, notice, admission, None)?;
            }
            Ok(value)
        })
    }
}
