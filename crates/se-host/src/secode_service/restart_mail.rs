//! Preserve an uncertain old offer and schedule unread mail on the new binding.
use super::*;
use se_core::{ops::mail as core, scope, store_error::store_error};
use se_store::{Actor, EventBody, RecordIdentity, mail::MailSnapshot};
use std::time::Duration;

impl LaunchCoordinator {
    pub(in crate::process) async fn reconcile_restart_secode_mail(
        &self,
        work: &mut owned::Work,
        deadline: &Deadline,
    ) -> Result<()> {
        if work.secode.is_none() {
            return Ok(());
        }
        let Some(slot) = self
            .secode_services
            .get(&work.meta.project.id, &work.meta.agent.id, deadline)
            .await?
        else {
            return Ok(());
        };
        let mut service = lock_service(&slot, deadline).await?;
        let Some(restart) = &service.restart else {
            return Ok(());
        };
        if !restart.adopted {
            return Err(error(
                "SE Code restart",
                "replacement control has not proved possession; unread mail remains retained",
            ));
        }
        let session_hash = restart.session_hash;
        if service.journal.restart_settled {
            work.pin_hash = Some(session_hash);
            if let Some(restart) = service.restart.as_mut()
                && !restart.mail_notified
            {
                work.mail.reoffer = true;
                restart.mail_notified = true;
            }
            return Ok(());
        }
        let flight_effect = work
            .mail
            .flight
            .as_ref()
            .map(|flight| flight.reservation.effect_id);
        let retained = service.journal.restart_effect.or_else(|| {
            service
                .journal
                .notice
                .as_ref()
                .and_then(|notice| notice.effect)
        });
        if flight_effect.is_some() && retained.is_some() && flight_effect != retained {
            return Err(error(
                "SE Code restart notice",
                "the in-memory and durable original notices differ; preserve both for reconciliation",
            ));
        }
        let mut effect = flight_effect.or(retained);
        if effect.is_none()
            && let Some(notice) = &service.journal.notice
        {
            effect = self.find_restart_notice(work, notice, deadline).await?;
        }
        if let Some(effect) = effect {
            if service.journal.restart_effect != Some(effect) {
                service.journal.restart_effect = Some(effect);
                service.persist(self, deadline).await?;
            }
            self.settle_restart_notice(work, effect, deadline).await?;
        }
        service.journal.notice = None;
        service.journal.restart_settled = true;
        service.persist(self, deadline).await?;
        work.mail.flight = None;
        work.mail.seen.clear();
        work.mail.backlog = false;
        work.mail.reoffer = true;
        if let Some(restart) = service.restart.as_mut() {
            restart.mail_notified = true;
        }
        work.pin_hash = Some(session_hash);
        Ok(())
    }
    async fn settle_restart_notice(
        &self,
        work: &owned::Work,
        effect: se_store::RecordId,
        deadline: &Deadline,
    ) -> Result<()> {
        let target = core::MailTarget {
            project: work.meta.project.id.clone(),
            agent: work.meta.agent.id.clone(),
            session: work.meta.session.clone(),
            epoch: self.options.epoch.clone(),
            generation: self.store.generation.get(),
            fingerprint: work.pin_hash.ok_or_else(|| {
                error(
                    "restart notice",
                    "the original session fingerprint is unavailable",
                )
            })?,
        };
        let admission = se_store::Admission {
            scope: se_store::Scope::Project(target.project.clone()),
            actor: Actor::Agent(target.agent.clone()),
            session: Some(target.session.clone()),
            generation: target.generation,
        };
        super::super::mail::commit::step(
            &self.store,
            admission,
            deadline,
            move |kernel, cx| {
                core::retire_uncertain(kernel, cx, core::RestartNotice { target, effect })
            },
            |_, cx, key, receipt| core::finish_retirement(cx, key, receipt),
        )
        .await?;
        Ok(())
    }
    async fn find_restart_notice(
        &self,
        work: &owned::Work,
        notice: &custody::Notice,
        deadline: &Deadline,
    ) -> Result<Option<se_store::RecordId>> {
        let input = notice.input.clone();
        let messages = notice.messages.clone();
        let agent = work.meta.agent.id.clone();
        let admission = se_store::Admission {
            scope: se_store::Scope::Project(work.meta.project.id.clone()),
            actor: Actor::Agent(agent.clone()),
            session: Some(work.meta.session.clone()),
            generation: self.store.generation.get(),
        };
        let effect = self
            .store
            .read(admission, deadline, move |cx| {
                let page = cx
                    .read
                    .mail_notices(
                        agent,
                        se_store::ReadBudget {
                            page: se_types::PageRequest {
                                after: None,
                                limit: std::num::NonZeroU32::MIN.saturating_add(99),
                                max_bytes: std::num::NonZeroU32::MIN.saturating_add(262143),
                            },
                            deadline: Duration::from_secs(1),
                        },
                    )
                    .map_err(|error| store_error(&error))?;
                if !page.window().complete() {
                    return Err(scope::unreadable(
                        "restart notices",
                        "the pending notice inventory is incomplete",
                    ));
                }
                let mut found = None;
                for record in page.items() {
                    if let EventBody::EffectRequested {
                        effect,
                        intent: se_store::EffectIntent::MailNotice(notice),
                        ..
                    } = &record.original.as_deref().unwrap_or(&record.current).body
                    {
                        let notice_id = se_types::NoticeId::new(format!(
                            "notice-{}",
                            se_types::hex_lower(notice.notice_id.as_bytes())
                        ))?;
                        if super::mail::input(&notice_id) == input
                            && notice
                                .ids
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                == messages
                            && found.replace(*effect).is_some()
                        {
                            return Err(error(
                                "restart notices",
                                "multiple original notices match",
                            ));
                        }
                    }
                }
                found
                    .ok_or_else(|| {
                        error(
                            "restart notices",
                            "the original pending notice is unavailable; preserve its journal",
                        )
                    })
                    .map(Some)
            })
            .await?;
        Ok(effect)
    }
}
