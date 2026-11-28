//! Bounded store scanning, multi-project pagination, and cursor/authority
//! verification for `events.subscribe`.
//!
//! Every scan captures a common upper watermark (`upper_seq`) from `reader.info()`
//! so concurrent commits landing between per-project snapshots can never advance
//! the stream cursor past unread projects. Cross-project buffering is strictly
//! bounded by both event count and estimated byte budget.
use super::{
    EventPushFrame, EventStreamKind,
    admit::{AdmittedSubscribe, SubscribePrincipal},
    cursor, project,
};
use crate::runtime::HostedRouter;
use se_core::store_error::store_error;
use se_store::{
    Actor, Admission, HistoryDirection, HistoryQuery, ReadScope, ReadStore, Scope, Snapshot,
    StoreInfo, StorePosition, TranscriptFilter, Visibility,
};
use se_types::{AgentId, ProjectId, Result};
use std::{sync::Arc, time::Duration};

const SCAN_LIMIT: u32 = 128;
const SCAN_BYTES: u32 = 2 * 1024 * 1024;
const SCAN_DEADLINE_SECS: u64 = 5;
const PROJECT_PAGE_LIMIT: u32 = 256;
const MAX_PROJECT_PAGES: usize = 64;

pub(crate) struct ScanOutcome {
    pub(crate) frames: Vec<EventPushFrame>,
    pub(crate) next_seq: u64,
    pub(crate) safe_cursor: String,
    pub(crate) missed_cursor: String,
    pub(crate) has_more: bool,
}

enum ScanPrincipal {
    Owner(se_types::HumanId),
    Session {
        secret: Arc<se_types::Secret>,
        purpose: &'static str,
        project: ProjectId,
        agent: AgentId,
        session: se_types::SessionId,
        credential: se_store::RecordId,
    },
}

pub(crate) async fn resolve_start_cursor(
    router: &HostedRouter,
    sub: &AdmittedSubscribe,
) -> Result<(u64, String)> {
    router.check_open()?;
    let context = router.context.clone();
    let reader = Arc::clone(&router.execution.reader);
    let after = sub.after_cursor.clone();
    let deadline = crate::runtime::serve::options(Duration::from_secs(SCAN_DEADLINE_SECS))?;
    router
        .execution
        .blocking
        .run_owned(&deadline, move || {
            let phase = context.reads.read_phase().map_err(|e| store_error(&e))?;
            let res = (|| {
                context.check_generation(&phase)?;
                let info = reader.info().map_err(|e| store_error(&e))?;
                let head_seq = info.head.as_ref().map_or(0, StorePosition::sequence);
                let start_seq = match after.as_deref() {
                    Some(raw) => cursor::decode_and_verify(raw, &info, context.generation)?,
                    None => head_seq,
                };
                let head_cursor = cursor::encode(&info, context.generation, head_seq)?;
                Ok((start_seq, head_cursor))
            })();
            crate::runtime::executor::close_read(res, phase.close())
        })
        .await
}

pub(crate) async fn verify_live_authority(
    router: &HostedRouter,
    sub: &AdmittedSubscribe,
) -> Result<()> {
    router.check_open()?;
    let SubscribePrincipal::Session {
        secret, purpose, ..
    } = &sub.principal
    else {
        return Ok(());
    };
    let context = router.context.clone();
    let secret = Arc::clone(secret);
    let purpose = *purpose;
    let deadline = crate::runtime::serve::options(Duration::from_secs(SCAN_DEADLINE_SECS))?;
    router
        .execution
        .blocking
        .run_owned(&deadline, move || {
            let phase = context.reads.read_phase().map_err(|e| store_error(&e))?;
            let res = (|| {
                context.check_generation(&phase)?;
                if purpose == crate::external::EXTERNAL_SESSION_CAPABILITY {
                    context.external_session(&phase, &secret).map(drop)
                } else {
                    context.verify_session(&phase, &secret).map(drop)
                }
            })();
            crate::runtime::executor::close_read(res, phase.close())
        })
        .await
}

pub(crate) async fn scan_events(
    router: &HostedRouter,
    sub: &AdmittedSubscribe,
    after_seq: u64,
    max_items: usize,
) -> Result<ScanOutcome> {
    router.check_open()?;
    let context = router.context.clone();
    let reader = Arc::clone(&router.execution.reader);
    let project_filter = sub.project_filter.clone();
    let agent_filter = sub.agent_filter.clone();
    let filter = sub.filter.clone();
    let principal = match &sub.principal {
        SubscribePrincipal::Owner { human } => ScanPrincipal::Owner(human.clone()),
        SubscribePrincipal::Session {
            secret,
            purpose,
            project,
            agent,
            session,
            credential,
        } => ScanPrincipal::Session {
            secret: Arc::clone(secret),
            purpose,
            project: project.clone(),
            agent: agent.clone(),
            session: session.clone(),
            credential: *credential,
        },
    };
    let deadline = crate::runtime::serve::options(Duration::from_secs(SCAN_DEADLINE_SECS))?;
    router
        .execution
        .blocking
        .run_owned(&deadline, move || {
            scan_events_blocking(
                &context,
                &reader,
                &principal,
                project_filter.as_ref(),
                agent_filter.as_ref(),
                filter.as_deref(),
                after_seq,
                max_items,
            )
        })
        .await
}

#[allow(clippy::too_many_arguments)]
fn scan_events_blocking(
    context: &crate::runtime::admission::AdmissionContext,
    reader: &se_store::SqliteReader,
    principal: &ScanPrincipal,
    project_filter: Option<&ProjectId>,
    agent_filter: Option<&AgentId>,
    filter: Option<&[EventStreamKind]>,
    after_seq: u64,
    max_items: usize,
) -> Result<ScanOutcome> {
    let phase = context.reads.read_phase().map_err(|e| store_error(&e))?;
    let info = match verify_scan_phase(context, reader, principal, &phase) {
        Ok(info) => info,
        Err(err) => return crate::runtime::executor::close_read(Err(err), phase.close()),
    };

    let upper_seq = info.head.as_ref().map_or(0, StorePosition::sequence);
    let upper_cursor = cursor::encode(&info, context.generation, upper_seq)?;
    if upper_seq <= after_seq {
        return crate::runtime::executor::close_read(
            Ok(ScanOutcome {
                frames: Vec::new(),
                next_seq: upper_seq,
                safe_cursor: upper_cursor.clone(),
                missed_cursor: upper_cursor,
                has_more: false,
            }),
            phase.close(),
        );
    }

    let projects = resolve_projects(context, phase, principal, project_filter)?;
    let kinds = project::event_kinds_for_filter(filter);
    let since = (after_seq > 0)
        .then(|| {
            StorePosition::new_internal(info.id.clone(), info.incarnation, after_seq)
                .map_err(|e| store_error(&e))
        })
        .transpose()?;

    let max_items = max_items.max(1);
    let max_bytes = SCAN_BYTES as usize;
    let mut collected: Vec<(u64, usize, EventPushFrame)> = Vec::new();
    let mut collected_bytes: usize = 0;
    let mut effective_upper_seq = upper_seq;
    let mut min_truncated_seq: Option<u64> = None;
    let mut saw_newer = false;

    for proj in &projects {
        let scan = read_project_events(
            context,
            principal,
            proj,
            agent_filter,
            &kinds,
            filter,
            since.as_ref(),
            effective_upper_seq,
            &info,
        )?;
        saw_newer |= scan.saw_newer;
        if let Some(limit_seq) = scan.truncated_at {
            effective_upper_seq = effective_upper_seq.min(limit_seq);
            min_truncated_seq = Some(min_truncated_seq.map_or(limit_seq, |cur| cur.min(limit_seq)));
        }
        for (seq, bytes, frame) in scan.items {
            if seq <= effective_upper_seq {
                collected_bytes = collected_bytes.saturating_add(bytes);
                collected.push((seq, bytes, frame));
            }
        }
        if collected.len() > max_items
            || collected_bytes > max_bytes
            || effective_upper_seq < upper_seq
        {
            prune_collected_budget(
                &mut collected,
                &mut collected_bytes,
                max_items,
                max_bytes,
                &mut effective_upper_seq,
                &mut min_truncated_seq,
            );
        }
    }

    collected.sort_by_key(|(seq, _, _)| *seq);
    if let Some(frontier) = min_truncated_seq {
        collected.retain(|(seq, _, _)| *seq <= frontier);
        let safe_cursor = cursor::encode(&info, context.generation, frontier)?;
        return Ok(ScanOutcome {
            frames: collected.into_iter().map(|(_, _, f)| f).collect(),
            next_seq: frontier,
            safe_cursor,
            missed_cursor: upper_cursor,
            has_more: true,
        });
    }
    Ok(ScanOutcome {
        frames: collected.into_iter().map(|(_, _, f)| f).collect(),
        next_seq: upper_seq,
        safe_cursor: upper_cursor.clone(),
        missed_cursor: upper_cursor,
        has_more: saw_newer,
    })
}

fn verify_scan_phase(
    context: &crate::runtime::admission::AdmissionContext,
    reader: &se_store::SqliteReader,
    principal: &ScanPrincipal,
    phase: &se_store::ReadPhase,
) -> Result<StoreInfo> {
    context.check_generation(phase)?;
    let info = reader.info().map_err(|e| store_error(&e))?;
    if let ScanPrincipal::Session {
        secret, purpose, ..
    } = principal
    {
        if *purpose == crate::external::EXTERNAL_SESSION_CAPABILITY {
            context.external_session(phase, secret)?;
        } else {
            context.verify_session(phase, secret)?;
        }
    }
    Ok(info)
}

fn prune_collected_budget(
    collected: &mut Vec<(u64, usize, EventPushFrame)>,
    collected_bytes: &mut usize,
    max_items: usize,
    max_bytes: usize,
    effective_upper_seq: &mut u64,
    min_truncated_seq: &mut Option<u64>,
) {
    collected.sort_by_key(|(seq, _, _)| *seq);
    collected.retain(|(seq, _, _)| *seq <= *effective_upper_seq);
    *collected_bytes = collected.iter().map(|(_, b, _)| *b).sum();
    let mut trimmed = false;
    while collected.len() > max_items || (collected.len() > 1 && *collected_bytes > max_bytes) {
        if let Some((_, b, _)) = collected.pop() {
            *collected_bytes = collected_bytes.saturating_sub(b);
            trimmed = true;
        }
    }
    if trimmed && let Some((frontier, _, _)) = collected.last() {
        *effective_upper_seq = (*effective_upper_seq).min(*frontier);
        *min_truncated_seq = Some(min_truncated_seq.map_or(*frontier, |cur| cur.min(*frontier)));
    }
}

fn resolve_projects(
    context: &crate::runtime::admission::AdmissionContext,
    phase: se_store::ReadPhase,
    principal: &ScanPrincipal,
    project_filter: Option<&ProjectId>,
) -> Result<Vec<ProjectId>> {
    match (principal, project_filter) {
        (_, Some(project)) => {
            crate::runtime::executor::close_read(Ok(()), phase.close())?;
            Ok(vec![project.clone()])
        }
        (ScanPrincipal::Owner(human), None) => {
            let scope = ReadScope {
                admission: Admission {
                    scope: Scope::Registry,
                    actor: Actor::Human(human.clone()),
                    session: None,
                    generation: context.generation.get(),
                },
                visibility: Visibility::Owner,
            };
            let mut snap = phase.into_snapshot(scope).map_err(|e| store_error(&e))?;
            let list = (|| {
                let mut all = Vec::new();
                let mut next_cursor = None;
                for _ in 0..MAX_PROJECT_PAGES {
                    let budget = se_store::read_budget(
                        next_cursor.take(),
                        PROJECT_PAGE_LIMIT,
                        SCAN_BYTES,
                        Duration::from_secs(SCAN_DEADLINE_SECS),
                    );
                    let page = snap.projects(budget).map_err(|e| store_error(&e))?;
                    for rec in page.items() {
                        match &rec.current.body {
                            se_store::EventBody::ProjectRegistered { project, .. }
                            | se_store::EventBody::ProjectUpdated { project, .. }
                            | se_store::EventBody::ProjectMoved { project, .. } => {
                                all.push(project.clone());
                            }
                            _ => {}
                        }
                    }
                    match page.next() {
                        Some(cursor) => next_cursor = Some(cursor.clone()),
                        None => return Ok(all),
                    }
                }
                Err(se_core::scope::unreadable(
                    "project list",
                    "registered project count exceeds all-project stream enumeration cap; pass an explicit project_id",
                ))
            })();
            crate::runtime::executor::close_read(list, snap.close())
        }
        (ScanPrincipal::Session { project, .. }, None) => {
            crate::runtime::executor::close_read(Ok(()), phase.close())?;
            Ok(vec![project.clone()])
        }
    }
}

struct ProjectScan {
    items: Vec<(u64, usize, EventPushFrame)>,
    truncated_at: Option<u64>,
    saw_newer: bool,
}

#[allow(clippy::too_many_arguments)]
fn read_project_events(
    context: &crate::runtime::admission::AdmissionContext,
    principal: &ScanPrincipal,
    project_id: &ProjectId,
    agent_filter: Option<&AgentId>,
    kinds: &[se_store::EventKind],
    filter: Option<&[EventStreamKind]>,
    since: Option<&StorePosition>,
    upper_seq: u64,
    info: &StoreInfo,
) -> Result<ProjectScan> {
    let p_phase = context.reads.read_phase().map_err(|e| store_error(&e))?;
    let (read_scope, session_scope) = match principal {
        ScanPrincipal::Owner(human) => (
            ReadScope {
                admission: Admission {
                    scope: Scope::Project(project_id.clone()),
                    actor: Actor::Human(human.clone()),
                    session: None,
                    generation: context.generation.get(),
                },
                visibility: Visibility::Owner,
            },
            None,
        ),
        ScanPrincipal::Session {
            agent,
            session,
            credential,
            ..
        } => (
            ReadScope {
                admission: Admission {
                    scope: Scope::Project(project_id.clone()),
                    actor: Actor::Agent(agent.clone()),
                    session: Some(session.clone()),
                    generation: context.generation.get(),
                },
                visibility: Visibility::SelfOnly(agent.clone()),
            },
            Some(project::SessionScope {
                agent,
                session,
                credential: *credential,
            }),
        ),
    };
    let mut snap = p_phase
        .into_snapshot(read_scope)
        .map_err(|e| store_error(&e))?;
    let query = HistoryQuery {
        agent: agent_filter.cloned(),
        session: None,
        kinds: kinds.to_vec(),
        families: Vec::new(),
        transcript: TranscriptFilter::All,
        since: since.cloned(),
        direction: HistoryDirection::OldestFirst,
    };
    let budget = se_store::read_budget(
        None,
        SCAN_LIMIT,
        SCAN_BYTES,
        Duration::from_secs(SCAN_DEADLINE_SECS),
    );
    let page = snap.history(query, budget).map_err(|e| store_error(&e));
    let page = crate::runtime::executor::close_read(page, snap.close())?;
    let mut out = Vec::new();
    let mut last_seq = None;
    let mut saw_newer = false;
    for event in page.items() {
        let seq = event.position.sequence();
        if seq > upper_seq {
            saw_newer = true;
            break;
        }
        last_seq = Some(seq);
        if let Some(frame) = project::project_event(
            event,
            info,
            context.generation,
            filter,
            session_scope.as_ref(),
        )? {
            let est_bytes = frame.cursor.len()
                + frame.event_id.as_str().len()
                + frame.payload.to_string().len()
                + 128;
            out.push((seq, est_bytes, frame));
        }
    }
    let truncated_at = (!saw_newer && page.next().is_some())
        .then_some(last_seq)
        .flatten();
    Ok(ProjectScan {
        items: out,
        truncated_at,
        saw_newer,
    })
}
