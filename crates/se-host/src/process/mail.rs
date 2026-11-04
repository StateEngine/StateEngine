//! Event-driven delivery to a retained provider; no inbox polling or timer.
//! Stream writes are offers. Only pinned, committed user input proves delivery.
use super::*;
use crate::client::lease::Deadline;
use se_core::{ops::mail as core, scope, store_error::store_error};
use se_store::{Actor, EventBody, RecordId, RecordIdentity, Snapshot, mail::MailSnapshot};
use se_types::{Body, IdempotencyKey, Read, Result};
use sha2::{Digest, Sha256};
use std::{num::NonZeroU32, time::Duration};
mod commit;
pub(super) mod diagnostic;
mod notice;
mod reconcile;

#[derive(Default)]
pub(super) struct State {
    pub idle: bool,
    pub flight: Option<Flight>,
}
pub(super) struct Flight {
    reservation: core::Reservation,
    text_sha256: [u8; 32],
    attempt: RecordId,
    evidence: Option<se_store::mail::OfferObservation>,
    observed: bool,
}
fn id() -> Result<RecordId> {
    let facts = crate::runtime::start::allocate_facts()?;
    let value = facts
        .event
        .as_str()
        .strip_prefix("ev_")
        .ok_or_else(|| error("mail identity", "expected an allocated event identity"))?;
    let uuid = uuid::Uuid::parse_str(value).map_err(|e| error("mail identity", e))?;
    RecordId::from_bytes(*uuid.as_bytes()).map_err(|e| store_error(&e))
}
fn budget() -> se_store::ReadBudget {
    se_store::ReadBudget {
        page: se_types::PageRequest {
            after: None,
            limit: NonZeroU32::new(100).unwrap_or(NonZeroU32::MIN),
            max_bytes: NonZeroU32::new(262144).unwrap_or(NonZeroU32::MIN),
        },
        deadline: Duration::from_secs(1),
    }
}
fn admission(target: &core::MailTarget) -> se_store::Admission {
    se_store::Admission {
        scope: se_store::Scope::Project(target.project.clone()),
        actor: Actor::Agent(target.agent.clone()),
        session: Some(target.session.clone()),
        generation: target.generation,
    }
}
impl LaunchCoordinator {
    pub(super) async fn deliver_mail(
        &self,
        work: &mut owned::Work,
        deadline: &Deadline,
    ) -> Result<()> {
        if !work.active
            || !work.activated
            || work.session_retired
            || work.stop_key.is_some()
            || work
                .binding
                .as_ref()
                .is_none_or(|binding| binding.claude.is_none() && binding.codex.is_none())
        {
            return Ok(());
        }
        let target = core::MailTarget {
            project: work.meta.project.id.clone(),
            agent: work.meta.agent.id.clone(),
            session: work.meta.session.clone(),
            epoch: self.options.epoch.clone(),
            generation: self.store.generation.get(),
            fingerprint: work
                .pin_hash
                .ok_or_else(|| error("mail target", "verified launch pin is unavailable"))?,
        };
        self.reconcile_mail(work, &target, deadline).await?;
        let codex = work
            .binding
            .as_ref()
            .is_some_and(|binding| binding.codex.is_some());
        if (!codex && !work.mail.idle) || work.mail.flight.is_some() {
            return Ok(());
        }
        let notice = id()?;
        let effect = id()?;
        let request = core::ReserveNotice {
            target: target.clone(),
            key: IdempotencyKey::new(format!(
                "mail.reserve.{}",
                se_types::hex_lower(notice.as_bytes())
            ))?,
            notice_id: notice,
            effect_id: effect,
        };
        let reserved = commit::step(
            &self.store,
            admission(&target),
            deadline,
            move |kernel, cx| core::reserve_notice(kernel, cx, request),
            |kernel, cx, then, receipt| {
                core::committed(kernel, cx, then, receipt).map(|value| Read::Present { value })
            },
        )
        .await?;
        let reserved = match reserved {
            Read::Present { value } => value,
            Read::Absent { .. } => return Ok(()),
            Read::Unknown { what } => return Err(scope::unreadable("mail reservation", &what)),
            Read::Unreadable { source, reason, .. } => {
                return Err(scope::unreadable(&source, &reason));
            }
        };
        let text = self.mail_notice_text(&target, &reserved, deadline).await?;
        let expected_conversation = scope::require_present(
            work.meta.conversation.clone(),
            "mail provider conversation",
            "Restore the exact live provider binding before another offer.",
        )?;
        let digest = reserved.digest;
        let bytes = crate::harness::claude::input_frame(&text)?.len() as u64;
        let effect = reserved.effect_id;
        let descriptor = self
            .store
            .read(admission(&target), deadline, move |cx| {
                let record = scope::require_present(
                    cx.read.effect(effect).map_err(|e| store_error(&e))?,
                    "mail descriptor",
                    scope::COMMITTED_READ_RECOVERY,
                )?;
                match &record.original.as_deref().unwrap_or(&record.current).body {
                    EventBody::EffectRequested {
                        intent: se_store::EffectIntent::MailNotice(notice),
                        ..
                    } => Ok(notice.notice_id),
                    _ => Err(error("mail descriptor", "committed intent is not a notice")),
                }
            })
            .await?;
        let binding = work
            .binding
            .as_ref()
            .ok_or_else(|| error("mail transport", "live binding disappeared"))?;
        let call = launch_util::call(self.store.generation, deadline)?;
        let attempt = id()?;
        let observed_at_us = crate::runtime::start::now_unix_micros()?;
        work.mail.flight = Some(Flight {
            reservation: reserved,
            text_sha256: Sha256::digest(text.as_str().as_bytes()).into(),
            attempt,
            evidence: None,
            observed: false,
        });
        // Retain the attempted notice before crossing the transport boundary.
        // A partial/uncertain write is never blindly sent again on this binding.
        let offered = if codex {
            self.codex
                .offer_mail(
                    binding,
                    &expected_conversation,
                    &text,
                    &format!(
                        "{}:{}",
                        se_types::hex_lower(descriptor.as_bytes()),
                        se_types::hex_lower(attempt.as_bytes())
                    ),
                    call,
                )
                .await
                .map(|event_id| se_store::mail::OfferReport::VendorReported {
                    provider: se_store::Provider::Codex,
                    event_id,
                })
                .map_err(|failure| (failure.error, failure.completed_bytes))
        } else {
            self.harness
                .offer_mail(binding, &expected_conversation, &text, call)
                .await
                .map(|()| se_store::mail::OfferReport::TransportWritten {
                    transport: se_store::mail::MailTransport::Stdio,
                    bytes,
                })
                .map_err(|failure| (failure.error, failure.completed_bytes))
        };
        let (report, failure) = match offered {
            Ok(report) => (report, None),
            Err((error, Some(0))) => (
                se_store::mail::OfferReport::Failed {
                    code: "zero-byte-write".into(),
                },
                Some(error),
            ),
            Err((error, _)) => (
                se_store::mail::OfferReport::Unknown {
                    code: "acceptance-unknown".into(),
                },
                Some(error),
            ),
        };
        let flight = work
            .mail
            .flight
            .as_mut()
            .ok_or_else(|| error("mail offer", "retained attempt missing"))?;
        let no_input = matches!(&report, se_store::mail::OfferReport::Failed { .. });
        flight.evidence = Some(se_store::mail::OfferObservation {
            version: 1,
            notice_id: descriptor,
            target_agent: target.agent.clone(),
            session: target.session.clone(),
            epoch: target.epoch.clone(),
            generation: target.generation,
            fingerprint: target.fingerprint,
            observed_at_us,
            digest: *digest.as_bytes(),
            report,
        });
        // A proved zero-byte failure did not start a turn; retain eligibility
        // for an explicit same-key retry wake.
        work.mail.idle = no_input;
        let observed = self.reconcile_mail(work, &target, deadline).await;
        match (observed, failure) {
            (Err(record), Some(original)) => Err(record.with_cause(original)),
            (Ok(()), Some(original)) => Err(original),
            (result, None) => result,
        }
    }
}
