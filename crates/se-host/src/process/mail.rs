//! Event-driven delivery to a retained provider; no inbox polling or timer.
//! Stream writes are offers. Only pinned, committed user input proves delivery.
use super::*;
use crate::client::lease::Deadline;
use se_core::{ops::mail as core, scope, store_error::store_error};
use se_store::{Actor, EventBody, RecordId, RecordIdentity, Snapshot, mail::MailSnapshot};
use se_types::{Body, IdempotencyKey, Read, Result};
use sha2::{Digest, Sha256};
use std::{num::NonZeroU32, time::Duration};
pub(in crate::process) mod commit;
pub(super) mod diagnostic;
mod notice;
mod reconcile;

#[derive(Default)]
pub(super) struct State {
    pub idle: bool,
    pub flight: Option<Flight>,
    pub seen: Vec<se_types::MessageId>,
    pub backlog: bool,
    pub reoffer: bool,
    /// When this agent was last woken for mail, on the monotonic clock.
    pub last_offer: Option<tokio::time::Instant>,
}
pub(super) struct Flight {
    pub(super) reservation: core::Reservation,
    text_sha256: [u8; 32],
    attempt: RecordId,
    evidence: Option<se_store::mail::OfferObservation>,
    observed: bool,
}
/// A retained-notice offer failure and how it was witnessed.
enum OfferFailure {
    /// The retained flight vanished before the SE Code offer crossed the boundary.
    Retired(se_types::SeError),
    /// The transport offer failed, witnessed by its completed bytes if known.
    Transport(se_types::SeError, Option<u32>),
}
/// The retained notice and its provider transport target.
struct NoticeOffer<'a> {
    text: &'a Body,
    expected_conversation: &'a se_types::ProviderSessionId,
    descriptor: RecordId,
    bytes: u64,
    secode: bool,
    codex: bool,
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
    pub(super) async fn reconcile_stopped_secode_mail(
        &self,
        work: &mut owned::Work,
        deadline: &Deadline,
    ) -> Result<()> {
        if work.secode.is_none() || work.mail.flight.is_none() || !work.capture_flushed {
            return Ok(());
        }
        let target = self.mail_target(work)?;
        self.reconcile_captured_mail(work, &target, deadline).await
    }

    pub(super) async fn deliver_mail(
        &self,
        work: &mut owned::Work,
        reoffer: bool,
        deadline: &Deadline,
    ) -> Result<()> {
        if !work.active
            || !work.activated
            || work.session_retired
            || work.stop_key.is_some()
            || work.binding.is_none()
        {
            return Ok(());
        }
        work.mail.reoffer |= reoffer;
        self.reconcile_restart_secode_mail(work, deadline).await?;
        self.reconcile_recovered_secode_notice(work, deadline)
            .await?;
        let target = self.mail_target(work)?;
        self.reconcile_mail(work, &target, deadline).await?;
        let codex = work
            .binding
            .as_ref()
            .is_some_and(|binding| binding.get::<crate::codex_rpc::Binding>().is_some());
        let secode = work.secode.is_some();
        if secode {
            self.require_secode_capability_settled(work, deadline)
                .await?;
        }
        if !codex
            && work
                .binding
                .as_ref()
                .and_then(|b| b.get::<crate::harness::ClaudeBinding>())
                .is_some_and(|b| b.attended)
        {
            // The attended mod consumes the same durable unread view. Never
            // fabricate a console write or record its notification as a read.
            return Ok(());
        }
        if (!secode && !work.mail.idle) || work.mail.flight.is_some() {
            return Ok(());
        }
        if let Some(managed) = &work.secode
            && !managed.current()?.control.is_idle(deadline).await?
        {
            return Ok(());
        }
        let reoffer = work.mail.reoffer;
        if reoffer {
            work.mail.seen.clear();
            work.mail.backlog = false;
        }
        let Some(reserved) = self
            .reserve_coalesced_notice(work, &target, reoffer, deadline)
            .await?
        else {
            return Ok(());
        };
        let text = if secode {
            Body::new(crate::harness::secode_process::notice_text(
                &reserved
                    .ids
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            )?)?
        } else {
            self.mail_notice_text(&target, &reserved, deadline).await?
        };
        let expected_conversation = scope::require_present(
            work.meta.conversation.clone(),
            "mail provider conversation",
            "Restore the exact live provider binding before another offer.",
        )?;
        let bytes = crate::harness::claude::input_frame(&text)?.len() as u64;
        let effect = reserved.effect_id;
        let descriptor = self.notice_descriptor(&target, effect, deadline).await?;
        let offer = NoticeOffer {
            text: &text,
            expected_conversation: &expected_conversation,
            descriptor,
            bytes,
            secode,
            codex,
        };
        self.offer_retained_notice(work, &target, reserved, &offer, deadline)
            .await
    }

    /// Build the durable mail target from the verified launch pin.
    fn mail_target(&self, work: &owned::Work) -> Result<core::MailTarget> {
        Ok(core::MailTarget {
            project: work.meta.project.id.clone(),
            agent: work.meta.agent.id.clone(),
            session: work.meta.session.clone(),
            epoch: self.options.epoch.clone(),
            generation: self.store.generation.get(),
            fingerprint: work
                .pin_hash
                .ok_or_else(|| error("mail target", "verified launch pin is unavailable"))?,
        })
    }
    /// Reserve the coalesced notice; an absent reservation retires reoffer state.
    async fn reserve_coalesced_notice(
        &self,
        work: &mut owned::Work,
        target: &core::MailTarget,
        reoffer: bool,
        deadline: &Deadline,
    ) -> Result<Option<core::Reservation>> {
        let excluded = if work.mail.backlog {
            work.mail.seen.clone()
        } else {
            Vec::new()
        };
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
            admission(target),
            deadline,
            move |kernel, cx| core::reserve_coalesced(kernel, cx, request, reoffer, excluded),
            |kernel, cx, then, receipt| {
                core::committed(kernel, cx, then, receipt).map(|value| Read::Present { value })
            },
        )
        .await?;
        work.mail.reoffer = false;
        Ok(match reserved {
            Read::Present { value } => Some(value),
            Read::Absent { .. } => {
                work.mail.backlog = false;
                work.mail.seen.clear();
                None
            }
            Read::Unknown { what } => return Err(scope::unreadable("mail reservation", &what)),
            Read::Unreadable { source, reason, .. } => {
                return Err(scope::unreadable(&source, &reason));
            }
        })
    }
    /// Read the committed notice descriptor for the reserved effect.
    async fn notice_descriptor(
        &self,
        target: &core::MailTarget,
        effect: RecordId,
        deadline: &Deadline,
    ) -> Result<RecordId> {
        self.store
            .read(admission(target), deadline, move |cx| {
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
            .await
    }
    /// Retain the attempted notice, cross the transport boundary, and observe it.
    async fn offer_retained_notice(
        &self,
        work: &mut owned::Work,
        target: &core::MailTarget,
        reserved: core::Reservation,
        offer: &NoticeOffer<'_>,
        deadline: &Deadline,
    ) -> Result<()> {
        let digest = reserved.digest;
        let binding = work
            .binding
            .as_ref()
            .ok_or_else(|| error("mail transport", "live binding disappeared"))?;
        let call = launch_util::call(self.store.generation, deadline)?;
        let attempt = id()?;
        let observed_at_us = crate::runtime::start::now_unix_micros()?;
        work.mail.last_offer = Some(tokio::time::Instant::now());
        work.mail.flight = Some(Flight {
            reservation: reserved,
            text_sha256: Sha256::digest(offer.text.as_str().as_bytes()).into(),
            attempt,
            evidence: None,
            observed: false,
        });
        // Retain the attempted notice before crossing the transport boundary.
        // A partial/uncertain write is never blindly sent again on this binding.
        let offered = self
            .transport_offer(work, binding, offer, attempt, deadline, call)
            .await;
        let (report, failure) = match offered {
            Ok(report) => (report, None),
            Err(OfferFailure::Retired(error)) => return Err(error),
            Err(OfferFailure::Transport(error, Some(0))) => (
                se_store::mail::OfferReport::Failed {
                    code: "zero-byte-write".into(),
                },
                Some(error),
            ),
            Err(OfferFailure::Transport(error, _)) => (
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
            notice_id: offer.descriptor,
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
        let observed = self.reconcile_mail(work, target, deadline).await;
        match (observed, failure) {
            (Err(record), Some(original)) => Err(record.with_cause(original)),
            (Ok(()), Some(original)) => Err(original),
            (result, None) => result,
        }
    }
    /// Offer the retained notice over its provider transport.
    async fn transport_offer(
        &self,
        work: &owned::Work,
        binding: &crate::HarnessBinding,
        offer: &NoticeOffer<'_>,
        attempt: RecordId,
        deadline: &Deadline,
        call: crate::CallContext,
    ) -> std::result::Result<se_store::mail::OfferReport, OfferFailure> {
        if offer.secode {
            let reserved = match work.mail.flight.as_ref() {
                Some(flight) => flight.reservation.clone(),
                None => {
                    return Err(OfferFailure::Retired(error(
                        "SE Code mail offer",
                        "original reservation absent",
                    )));
                }
            };
            self.offer_secode_notice(work, &reserved, deadline)
                .await
                .map(|event_id| se_store::mail::OfferReport::VendorReported {
                    provider: se_store::Provider::SeCode,
                    event_id,
                })
                .map_err(|error| OfferFailure::Transport(error, None))
        } else if work.meta.provider == se_store::Provider::Acp {
            self.acp
                .offer_mail(
                    binding,
                    offer.expected_conversation,
                    offer.text,
                    &format!(
                        "acp-notice-{}:{}",
                        se_types::hex_lower(offer.descriptor.as_bytes()),
                        se_types::hex_lower(attempt.as_bytes())
                    ),
                    call,
                )
                .await
                .map(|bytes| se_store::mail::OfferReport::TransportWritten {
                    transport: se_store::mail::MailTransport::Stdio,
                    bytes,
                })
                .map_err(|failure| OfferFailure::Transport(failure.error, failure.completed_bytes))
        } else if offer.codex {
            self.codex
                .offer_mail(
                    binding,
                    offer.expected_conversation,
                    offer.text,
                    &format!(
                        "{}:{}",
                        se_types::hex_lower(offer.descriptor.as_bytes()),
                        se_types::hex_lower(attempt.as_bytes())
                    ),
                    call,
                )
                .await
                .map(|event_id| se_store::mail::OfferReport::VendorReported {
                    provider: se_store::Provider::Codex,
                    event_id,
                })
                .map_err(|failure| OfferFailure::Transport(failure.error, failure.completed_bytes))
        } else {
            self.harness
                .offer_mail(binding, offer.expected_conversation, offer.text, call)
                .await
                .map(|()| se_store::mail::OfferReport::TransportWritten {
                    transport: se_store::mail::MailTransport::Stdio,
                    bytes: offer.bytes,
                })
                .map_err(|failure| OfferFailure::Transport(failure.error, failure.completed_bytes))
        }
    }
}
