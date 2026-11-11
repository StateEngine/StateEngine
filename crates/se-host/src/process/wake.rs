//! Wake offers one running agent's pending mail and reports the committed
//! offer. It never launches a process and never claims the mail was read or
//! acted on: stream writes are offers, and only a positive transport or
//! provider report is reported as offered.
use super::*;
use crate::client::lease::Deadline;
use se_core::{
    commit::Cx,
    ops::{
        WakeResult,
        agent_wake::{WakeLifecycle, WakeOffer, WakeOutcome, WakePlan},
    },
    scope,
    store_error::store_error,
};
use se_store::{
    Actor, EventBody, EventKind, HistoryQuery, ReadBudget, Scope, Snapshot, StoredEvent,
    TranscriptFilter,
    mail::{MailTransport, OfferEvidence, OfferReport},
};
use se_types::Result;
use std::{num::NonZeroU32, sync::atomic::Ordering, time::Duration};

/// One offer read: every committed mail offer for the admitted target
/// session, oldest first, until the finite window completes.
fn offers_for<R: Snapshot>(
    cx: &mut Cx<'_, R>,
    agent: &se_types::AgentId,
    session: &se_types::SessionId,
) -> Result<Vec<StoredEvent>> {
    let mut result = Vec::new();
    let mut after = None;
    for _ in 0..16 {
        let page = cx
            .read
            .history(
                HistoryQuery {
                    agent: Some(agent.clone()),
                    session: Some(session.clone()),
                    kinds: vec![EventKind::EffectOffered],
                    families: vec![],
                    transcript: TranscriptFilter::All,
                    since: None,
                },
                ReadBudget {
                    page: se_types::PageRequest {
                        after: after.clone(),
                        limit: NonZeroU32::new(1000).unwrap_or(NonZeroU32::MIN),
                        max_bytes: NonZeroU32::new(2 * 1024 * 1024).unwrap_or(NonZeroU32::MIN),
                    },
                    deadline: Duration::from_secs(1),
                },
            )
            .map_err(|e| store_error(&e))?;
        result.extend(
            page.items()
                .iter()
                .filter(|event| matches!(event.body, EventBody::EffectOffered { .. }))
                .cloned(),
        );
        if let Some(next) = page.next() {
            after = Some(next.clone());
            continue;
        }
        if !page.window().complete() {
            return Err(scope::unreadable(
                "wake offer window",
                "the finite offer window is incomplete",
            ));
        }
        return Ok(result);
    }
    Err(scope::unreadable(
        "wake offer window",
        "more than 16000 offers for one session; narrow the history",
    ))
}
impl LaunchCoordinator {
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub(super) async fn agent_wake(
        &self,
        plan: WakePlan,
        _admission: se_store::Admission,
        deadline: &Deadline,
    ) -> Result<WakeResult> {
        let jobs: Vec<Arc<super::supervisor::Job>> = {
            let registry = self
                .jobs
                .0
                .lock()
                .map_err(|_| error("wake registry", "launch registry is poisoned"))?;
            registry
                .values()
                .filter(|job| {
                    !job.settled.load(Ordering::Acquire)
                        && job.target == (plan.project.id.clone(), plan.agent.id.clone())
                })
                .cloned()
                .collect()
        };
        let name = plan.agent.name.clone();
        if jobs.is_empty() {
            return Ok(WakeResult {
                outcome: WakeOutcome::Refused,
                agent: plan.agent.clone(),
                lifecycle: WakeLifecycle {
                    state: "not_running".into(),
                    session: None,
                    lifecycle: None,
                },
                offer: None,
                detail: Some(format!("agent {name} has no running process on this host")),
                remedy: Some(format!("Launch {name} so it can read its pending mail.")),
            });
        }
        let job = jobs[0].clone();
        let lifecycle = WakeLifecycle {
            state: "running".into(),
            session: Some(job.session.clone()),
            lifecycle: Some(job.lifecycle.clone()),
        };
        let admission = se_store::Admission {
            scope: Scope::Project(plan.project.id.clone()),
            actor: Actor::Agent(plan.agent.id.clone()),
            session: Some(job.session.clone()),
            generation: self.store.generation.get(),
        };
        let agent = plan.agent.id.clone();
        let session = job.session.clone();
        let base_agent = agent.clone();
        let base_session = session.clone();
        let baseline: Vec<se_store::StorePosition> = self
            .store
            .read(admission.clone(), deadline, move |cx| {
                offers_for(cx, &base_agent, &base_session)
            })
            .await?
            .into_iter()
            .map(|event| event.position)
            .collect();
        // The same offer pass msg send would arm: one flag, one nudge, per live job.
        for job in &jobs {
            job.mail_pending.store(true, Ordering::Release);
            job.wake.event.notify_one();
        }
        let stage = deadline.stage(Duration::from_secs(5))?;
        let notified = std::time::Instant::now();
        let mut latest_negative: Option<OfferReport> = None;
        loop {
            let loop_agent = agent.clone();
            let loop_session = session.clone();
            let newest: Option<StoredEvent> = match self
                .store
                .read(admission.clone(), &stage, move |cx| {
                    offers_for(cx, &loop_agent, &loop_session)
                })
                .await
            {
                Ok(events) => events.into_iter().last(),
                // The stage clock ended inside the read: report the elapsed
                // window instead of an error.
                Err(_) if stage.at() <= std::time::Instant::now() => break,
                Err(error) => return Err(error),
            }
            .filter(|event| !baseline.contains(&event.position));
            if let Some(event) = newest {
                let offer = classify_offer(&event);
                if let Some(offer) = offer.positive {
                    return Ok(WakeResult {
                        outcome: WakeOutcome::Offered,
                        agent: plan.agent.clone(),
                        lifecycle,
                        offer: Some(offer),
                        detail: None,
                        remedy: None,
                    });
                }
                if let Some(report) = offer.negative {
                    latest_negative = Some(report);
                }
            }
            if job.settled.load(Ordering::Acquire) {
                return Ok(pending(
                    plan.agent.clone(),
                    WakeLifecycle {
                        state: "not_running".into(),
                        session: Some(session.clone()),
                        lifecycle: Some(job.lifecycle.clone()),
                    },
                    latest_negative,
                    "the agent process ended before a positive offer was committed; the mail stays queued for its next launch",
                ));
            }
            // The supervisor clears the flag when its delivery pass finishes.
            // A second without a committed offer then proves this window will
            // not produce one.
            if !job.mail_pending.load(Ordering::Acquire)
                && notified.elapsed() >= Duration::from_millis(1000)
            {
                return Ok(pending(
                    plan.agent.clone(),
                    lifecycle.clone(),
                    latest_negative,
                    "no positive mail offer was committed after the delivery pass finished; the mail stays queued for the agent's next read",
                ));
            }
            match stage.remaining() {
                Ok(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                Err(_) => break,
            }
        }
        Ok(pending(
            plan.agent.clone(),
            lifecycle,
            latest_negative,
            "no positive mail offer was committed within the wait window; the mail stays queued for the agent's next read",
        ))
    }
}
struct Classified {
    positive: Option<WakeOffer>,
    negative: Option<OfferReport>,
}
/// A positive report is an accepted offer; held, failed and unknown reports
/// are committed attempts without acceptance, reported as pending.
fn classify_offer(event: &StoredEvent) -> Classified {
    let EventBody::EffectOffered { evidence, .. } = &event.body else {
        return Classified {
            positive: None,
            negative: None,
        };
    };
    match evidence {
        OfferEvidence::Committed(_) => Classified {
            positive: Some(WakeOffer {
                kind: "committed-event".into(),
                transport: None,
                bytes: None,
                observed_at_us: None,
            }),
            negative: None,
        },
        OfferEvidence::Observed(observed) => match &observed.report {
            OfferReport::TransportWritten { transport, bytes } => Classified {
                positive: Some(WakeOffer {
                    kind: "transport-written".into(),
                    transport: Some(transport_name(transport)),
                    bytes: Some(*bytes),
                    observed_at_us: Some(observed.observed_at_us),
                }),
                negative: None,
            },
            OfferReport::VendorReported { provider, .. } => Classified {
                positive: Some(WakeOffer {
                    kind: "vendor-reported".into(),
                    transport: Some(provider_name(provider)),
                    bytes: None,
                    observed_at_us: Some(observed.observed_at_us),
                }),
                negative: None,
            },
            OfferReport::NativeAdmitted { .. } => Classified {
                positive: Some(WakeOffer {
                    kind: "native-admitted".into(),
                    transport: None,
                    bytes: None,
                    observed_at_us: Some(observed.observed_at_us),
                }),
                negative: None,
            },
            negative => Classified {
                positive: None,
                negative: Some(negative.clone()),
            },
        },
    }
}
fn transport_name(transport: &MailTransport) -> String {
    match transport {
        MailTransport::ClaudeMod => "claude_mod".into(),
        MailTransport::CodexAppServer => "codex_app_server".into(),
        MailTransport::LocalHttp => "local_http".into(),
        MailTransport::Stdio => "stdio".into(),
    }
}
fn provider_name(provider: &se_store::Provider) -> String {
    match provider {
        se_store::Provider::Claude => "claude".into(),
        se_store::Provider::Codex => "codex".into(),
        se_store::Provider::SeCode => "secode".into(),
        se_store::Provider::Acp => "acp".into(),
    }
}
fn pending(
    agent: se_types::Named<se_types::AgentId>,
    lifecycle: WakeLifecycle,
    negative: Option<OfferReport>,
    fallback: &str,
) -> WakeResult {
    let detail = match negative {
        Some(OfferReport::Held) => {
            "the native target explicitly held the offer; the mail stays queued for the agent's next read".into()
        }
        Some(OfferReport::Failed { code }) => {
            format!("the transport proved no bytes were accepted ({code}); the mail stays queued for the agent's next read")
        }
        Some(OfferReport::Unknown { code }) => {
            format!("the offer acceptance is unknown ({code}); the mail stays queued for the agent's next read")
        }
        _ => fallback.into(),
    };
    WakeResult {
        outcome: WakeOutcome::Pending,
        agent,
        lifecycle,
        offer: None,
        detail: Some(detail),
        remedy: Some("The agent picks the mail up at its next inbox read.".into()),
    }
}
