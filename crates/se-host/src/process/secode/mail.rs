//! Original notice coordinates are retained before the sole authenticated offer.
//! An uncertain write is queried by its old key and is never sent a second time.
use super::*;
use se_types::Read;
use sha2::{Digest, Sha256};

fn input(notice: &se_types::NoticeId) -> String {
    let digest = Sha256::digest(notice.as_str().as_bytes());
    format!("msg_{}", se_types::hex_lower(&digest[..16]))
}
impl LaunchCoordinator {
    /// A lost runtime cannot reconstruct an offer from its replacement epoch.
    /// Keep the original coordinates until actual captured delivery or recipient
    /// disposition is durable; never turn queue admission into a read receipt.
    pub(in crate::process) async fn reconcile_recovered_secode_notice(
        &self,
        work: &owned::Work,
        deadline: &Deadline,
    ) -> Result<()> {
        if work.secode.is_none() || work.mail.flight.is_some() {
            return Ok(());
        }
        let slot = self
            .secode_services
            .get(&work.meta.project.id, &work.meta.agent.id, deadline)
            .await?
            .ok_or_else(|| {
                error(
                    "SE Code recovered notice",
                    "original private service absent",
                )
            })?;
        let notice = lock_service(&slot, deadline).await?.journal.notice.clone();
        let Some(notice) = notice else {
            return Ok(());
        };
        self.reconcile_secode_notice(work, deadline).await?;
        let ids = notice.messages.clone();
        let agent = work.meta.agent.id.clone();
        let resolved = self.store.read(work.cleanup_admission.clone(), deadline, move |cx| {
            use se_store::Snapshot;
            for id in ids {
                let message = se_core::scope::require_present(cx.read.message(id.parse()?).map_err(|e| se_core::store_error::store_error(&e))?, "SE Code original notice message", "Retain the original coordinates and restore access to this recipient's messages.")?;
                if message.recipient != se_store::Actor::Agent(agent.clone()) { return Err(error("SE Code recovered notice", "original recipient differs")); }
                if message.delivered.is_none() && message.read.is_none() && message.dismissed.is_none() && message.superseded_by.is_none() { return Ok(false); }
            }
            Ok(true)
        }).await?;
        if !resolved {
            return Err(error(
                "SE Code recovered notice",
                "original admission is retained; its messages still await captured delivery or recipient disposition, so no replacement notice was offered",
            ));
        }
        let mut service = lock_service(&slot, deadline).await?;
        if !service.journal.notice.as_ref().is_some_and(|current| {
            current.input == notice.input && current.messages == notice.messages
        }) {
            return Err(error(
                "SE Code recovered notice",
                "original notice coordinates changed during reconciliation",
            ));
        }
        service.journal.notice = None;
        service.persist(self, deadline).await
    }
    pub(in crate::process) async fn offer_secode_notice(
        &self,
        work: &owned::Work,
        reservation: &se_core::ops::mail::Reservation,
        deadline: &Deadline,
    ) -> Result<String> {
        let managed = work
            .secode
            .clone()
            .ok_or_else(|| error("SE Code native notice", "original service binding absent"))?;
        let key = input(&reservation.notice_id);
        let messages = reservation
            .ids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let slot = self
            .secode_services
            .get(&work.meta.project.id, &work.meta.agent.id, deadline)
            .await?
            .ok_or_else(|| error("SE Code notice custody", "private service absent"))?;
        let mut service = lock_service(&slot, deadline).await?;
        let qualified = managed.current()?;
        let control = qualified.control.clone();
        let (notice, offer) = if let Some(notice) = &service.journal.notice {
            if notice.input != key || notice.messages != messages {
                return Err(error(
                    "SE Code notice custody",
                    "an older notice remains uncertain; reconcile its original key before another offer",
                ));
            }
            (notice.clone(), false)
        } else {
            let binding = qualified.binding(&managed.session, deadline).await?;
            binding.require_ready()?;
            let notice = custody::Notice {
                input: key.clone(),
                binding,
                messages,
            };
            service.journal.notice = Some(notice.clone());
            service.persist(self, deadline).await?;
            (notice, true)
        };
        drop(service);
        let receipt = if offer {
            control
                .offer_notice(&notice.binding, &notice.input, &notice.messages, deadline)
                .await?
        } else {
            control
                .acceptance(
                    &notice.binding.service,
                    &notice.binding.session_id,
                    &notice.input,
                    deadline,
                )
                .await?
        };
        match receipt.verify_notice(&notice.binding, &notice.input, &notice.messages)? {
            Read::Present { .. } => Ok(key),
            Read::Absent { .. } => Err(error(
                "SE Code notice acceptance",
                "original lookup is null; retain pending/no-replay",
            )),
            _ => Err(error(
                "SE Code notice acceptance",
                "original acceptance unreadable; retain pending/no-replay",
            )),
        }
    }
    pub(in crate::process) async fn reconcile_secode_notice(
        &self,
        work: &owned::Work,
        deadline: &Deadline,
    ) -> Result<()> {
        let Some(managed) = &work.secode else {
            return Ok(());
        };
        let slot = self
            .secode_services
            .get(&work.meta.project.id, &work.meta.agent.id, deadline)
            .await?
            .ok_or_else(|| error("SE Code notice readback", "original service absent"))?;
        let notice = lock_service(&slot, deadline).await?.journal.notice.clone();
        let Some(notice) = notice else {
            return Ok(());
        };
        let control = managed.current()?.control;
        let receipt = control
            .acceptance(
                &notice.binding.service,
                &notice.binding.session_id,
                &notice.input,
                deadline,
            )
            .await?;
        match receipt.verify_notice(&notice.binding, &notice.input, &notice.messages)? {
            Read::Present { .. } => Ok(()),
            _ => Err(error(
                "SE Code notice readback",
                "original input remains pending/no-replay; no replacement was offered",
            )),
        }
    }
    pub(in crate::process) async fn retire_secode_notice(
        &self,
        work: &owned::Work,
        notice: &se_types::NoticeId,
        deadline: &Deadline,
    ) -> Result<()> {
        if work.secode.is_none() || work.mail.flight.is_some() {
            return Ok(());
        }
        let slot = self
            .secode_services
            .get(&work.meta.project.id, &work.meta.agent.id, deadline)
            .await?
            .ok_or_else(|| error("SE Code notice retirement", "original service absent"))?;
        let mut service = lock_service(&slot, deadline).await?;
        if !service
            .journal
            .notice
            .as_ref()
            .is_some_and(|value| value.input == input(notice))
        {
            return Err(error(
                "SE Code notice retirement",
                "original coordinates differ from captured delivery",
            ));
        }
        service.journal.notice = None;
        service.persist(self, deadline).await
    }
}
