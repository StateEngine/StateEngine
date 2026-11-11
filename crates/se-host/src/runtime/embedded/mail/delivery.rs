//! Reconcile a durable reservation before offering its original IDs to native.
use super::*;
use se_core::ops::mail as core;
use se_store::{RecordId, RecordIdentity, mail::MailSnapshot};
use se_types::Read;

fn id() -> Result<RecordId> {
    let event = crate::runtime::start::allocate_facts()?.event;
    RecordId::from_bytes(
        event
            .canonical_bytes()?
            .ok_or_else(|| SeError::invalid("mail identity", "a fresh UUIDv7"))?,
    )
    .map_err(|error| store_error(&error))
}
fn target(value: &api::HostSessionTarget, generation: api::Generation) -> Result<core::MailTarget> {
    Ok(core::MailTarget {
        project: se_types::ProjectId::from_linked(value.binding.project.clone())?,
        agent: se_types::AgentId::from_linked(value.binding.agent.clone())?,
        session: se_types::SessionId::from_linked(value.binding.session.clone())?,
        epoch: se_types::HostEpoch::from_linked(value.epoch.clone())?,
        generation: generation.0,
        fingerprint: value.binding_fingerprint.0,
    })
}
impl Generation {
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub(super) async fn deliver_native(
        &self,
        router: &HostedRouter,
        native: &api::HostSessionTarget,
    ) -> api::Result<()> {
        self.bindings
            .current(&native.binding)
            .map_err(|e| support::api_error(&e))?;
        let options = api::CallOptions {
            generation: self.negotiated.generation,
            timeout: Duration::from_secs(5),
            cancellation: Arc::new(WorkerCancellation),
        };
        let (deadline, _cancel) =
            support::call_deadline(&self.runtime, &options).map_err(|e| support::api_error(&e))?;
        let (epoch, services) = self.services()?;
        if epoch != native.epoch || self.native_fence.load(Ordering::Acquire) {
            return Err(support::refused(
                "native delivery",
                "the current unfenced epoch",
            ));
        }
        let held = match services
            .binding_state(native, self.service_options(&options, &deadline)?)
            .await?
        {
            api::Read::Present { value } => match value.status {
                api::TargetStatus::Eligible => false,
                api::TargetStatus::Held => true,
                api::TargetStatus::Revoked => return Ok(()),
            },
            other => return Err(read_error("native mail eligibility", other)),
        };
        let current = target(native, options.generation).map_err(|e| support::api_error(&e))?;
        self.settle_native(router, native, &current, &deadline)
            .await
            .map_err(|e| support::api_error(&e))?;
        let notice = id().map_err(|e| support::api_error(&e))?;
        let reserve = core::ReserveNotice {
            target: current.clone(),
            key: se_types::IdempotencyKey::new(format!(
                "mail.reserve.{}",
                se_types::hex_lower(notice.as_bytes())
            ))
            .map_err(|e| support::api_error(&e))?,
            notice_id: notice,
            effect_id: id().map_err(|e| support::api_error(&e))?,
        };
        let maximum_ids = self.negotiated.limits.notice_ids.get().min(32);
        let reserved = step::run(
            router,
            native,
            options.generation,
            &deadline,
            move |kernel, cx| core::reserve_notice_bounded(kernel, cx, reserve, maximum_ids),
            |kernel, cx, then, receipt| {
                core::committed(kernel, cx, then, receipt).map(|value| Read::Present { value })
            },
        )
        .await
        .map_err(|e| support::api_error(&e))?;
        let reserved = match reserved {
            Read::Present { value } => value,
            Read::Absent { .. } => return Ok(()),
            Read::Unreadable { source, reason, .. } => {
                return Err(support::api_error(&scope::unreadable(&source, &reason)));
            }
            Read::Unknown { what } => {
                return Err(support::api_error(&scope::unreadable(
                    "native reservation",
                    &what,
                )));
            }
        };
        let mut notice = api::MailNotice {
            id: reserved.notice_id.to_linked(),
            target: native.clone(),
            messages: reserved.ids.iter().map(ToLinked::to_linked).collect(),
            through: reserved.through.to_linked(),
            dedupe_sha256: api::Sha256([0; 32]),
        };
        notice.dedupe_sha256 =
            crate::linked::native_notice_digest(&notice).map_err(|e| support::api_error(&e))?;
        let bytes = crate::harness::secode::notice_bytes(&notice)?;
        if bytes > self.negotiated.limits.payload_bytes.get() as usize {
            return Err(support::refused(
                "native notice bytes",
                &format!("at least {bytes} negotiated bytes for this complete reserved descriptor"),
            ));
        }
        // This is also the lost-reply path: only explicit Absent permits another
        // callback, always with the same durable notice identity and bytes.
        let outcome: api::Result<Option<api::NoticeAdmission>> = async {
            match services
                .notice_status(
                    native,
                    &notice.id,
                    self.service_options(&options, &deadline)?,
                )
                .await?
            {
                api::Read::Present { value } => Ok(Some(value)),
                api::Read::Absent { .. } if held => {
                    self.observe_native(
                        router,
                        native,
                        &reserved,
                        se_store::mail::OfferReport::Held,
                        &deadline,
                    )
                    .await?;
                    // No callback may select or unhold this target.
                    Ok(None)
                }
                api::Read::Absent { .. } => services
                    .deliver_notice(&notice, self.service_options(&options, &deadline)?)
                    .await
                    .map(Some),
                other => Err(read_error("native notice reconciliation", other)),
            }
        }
        .await;
        let admitted = match outcome {
            Ok(None) => return Ok(()),
            Err(error) => {
                self.observe_native(
                    router,
                    native,
                    &reserved,
                    se_store::mail::OfferReport::Unknown {
                        code: "native-outcome-unknown".into(),
                    },
                    &deadline,
                )
                .await?;
                return Err(error);
            }
            Ok(Some(api::NoticeAdmission::Held(_))) => {
                return self
                    .observe_native(
                        router,
                        native,
                        &reserved,
                        se_store::mail::OfferReport::Held,
                        &deadline,
                    )
                    .await;
            }
            Ok(Some(api::NoticeAdmission::Refused(error))) => {
                self.observe_native(
                    router,
                    native,
                    &reserved,
                    se_store::mail::OfferReport::Failed {
                        code: "native-refused".into(),
                    },
                    &deadline,
                )
                .await?;
                return Err(error);
            }
            Ok(Some(
                api::NoticeAdmission::Admitted(value) | api::NoticeAdmission::Replayed(value),
            )) => value,
        };
        if admitted.dedupe_sha256 != notice.dedupe_sha256 {
            return Err(support::refused(
                "native admission digest",
                "the original reserved descriptor",
            ));
        }
        // Queue commit is offered evidence only. It cannot produce message
        // delivered/read marks or claim the model has consumed the notice.
        self.observe_native(
            router,
            native,
            &reserved,
            se_store::mail::OfferReport::NativeAdmitted {
                event_id: admitted.committed.id.0,
                sequence: admitted.admitted_sequence.get(),
            },
            &deadline,
        )
        .await?;
        Ok(())
    }
    async fn settle_native(
        &self,
        router: &HostedRouter,
        native: &api::HostSessionTarget,
        target: &core::MailTarget,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<()> {
        let agent = target.agent.clone();
        let target_session = target.session.clone();
        let records = store::read(
            router,
            scope(native, self.negotiated.generation)?,
            deadline,
            move |read| {
                let page = read
                    .mail_notices(
                        agent.clone(),
                        se_store::ReadBudget {
                            page: se_types::PageRequest {
                                after: None,
                                limit: std::num::NonZeroU32::MIN.saturating_add(99),
                                max_bytes: std::num::NonZeroU32::MIN.saturating_add(262143),
                            },
                            deadline: Duration::from_secs(1),
                        },
                    )
                    .map_err(|e| store_error(&e))?;
                if !page.window().complete() {
                    return Err(scope::unreadable(
                        "native mail settlement",
                        "bounded debt inventory is incomplete",
                    ));
                }
                let mut ready = Vec::new();
                for record in page.items() {
                    let se_store::EventBody::EffectRequested {
                        effect,
                        intent: se_store::EffectIntent::MailNotice(notice),
                        ..
                    } = &record.original.as_deref().unwrap_or(&record.current).body
                    else {
                        return Err(scope::unreadable(
                            "native mail settlement",
                            "indexed debt differs from its immutable intent",
                        ));
                    };
                    if notice.session != target_session {
                        continue;
                    }
                    let mut evidence = Vec::new();
                    for message in &notice.ids {
                        match read
                            .mail_resolution(message.clone(), agent.clone())
                            .map_err(|e| store_error(&e))?
                        {
                            Read::Present { value } => evidence.push(value.header.event),
                            Read::Absent { .. } => break,
                            Read::Unreadable { source, reason, .. } => {
                                return Err(scope::unreadable(&source, &reason));
                            }
                            Read::Unknown { what } => {
                                return Err(scope::unreadable("native mail resolution", &what));
                            }
                        }
                    }
                    if evidence.len() == notice.ids.len() {
                        ready.push((*effect, evidence));
                    }
                }
                Ok(ready)
            },
        )
        .await?;
        for (effect, evidence) in records {
            let request = core::SettleResolved {
                target: target.clone(),
                effect,
                evidence,
            };
            step::run(
                router,
                native,
                self.negotiated.generation,
                deadline,
                move |kernel, cx| core::settle_resolved(kernel, cx, request),
                |_, cx, then, receipt| {
                    core::settlement_committed(cx, then, receipt)
                        .map(|value| Read::Present { value })
                },
            )
            .await?;
        }
        Ok(())
    }
}
pub(super) fn notice_record(id: &se_types::NoticeId) -> Result<RecordId> {
    let hex = id
        .as_str()
        .strip_prefix("notice-")
        .ok_or_else(|| SeError::invalid("notice identity", "the committed notice codec"))?;
    let bytes = uuid::Uuid::parse_str(hex)
        .map_err(|e| scope::unreadable("notice identity", &e.to_string()))?;
    RecordId::from_bytes(*bytes.as_bytes()).map_err(|e| store_error(&e))
}
