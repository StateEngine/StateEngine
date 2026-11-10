use super::*;
use se_types::{Cursor, Omission, OmissionReason};
use std::collections::BTreeMap;
mod manifest;
mod start;
#[derive(Clone, Default)]
struct Position {
    durable: Option<se_store::StorePosition>,
    live: Option<publish::LivePosition>,
    wire: Option<RemoteCursorSet>,
}
struct State {
    request: Arc<view_request::ViewRequest>,
    input: RemoteWatch,
    positions: BTreeMap<RemoteTarget, Position>,
    manifest: bool,
    manifest_after: Option<Cursor>,
    initial: bool,
    offset: usize,
    durable_revision: Option<u64>,
}
pub(super) struct Watch {
    _work: Option<super::super::activity::Work>,
    service: Service,
    state: Option<State>,
}
impl Watch {
    pub fn new(service: Service, request: auth::AuthorizedRemoteRequest) -> Result<Self> {
        Self::from_request(
            service,
            view_request::ViewRequest::Remote(Box::new(request)),
        )
    }
    pub(crate) fn from_request(
        service: Service,
        request: view_request::ViewRequest,
    ) -> Result<Self> {
        let RemoteRequest::Watch(input) = request.request() else {
            return Err(SeError::invalid("watch", "an authorized watch request"));
        };
        let input = input.clone();
        // Remote wire subscriptions stay open until cancellation. A local view
        // cache survives individual IPC calls, so only those calls own activity.
        let work = matches!(&request, view_request::ViewRequest::Remote(_))
            .then(|| service.router.execution.mail_waits.remote_work())
            .transpose()?;
        Ok(Self {
            _work: work,
            service,
            state: Some(State {
                request: Arc::new(request),
                input,
                positions: BTreeMap::new(),
                manifest: true,
                manifest_after: None,
                initial: true,
                offset: 0,
                durable_revision: None,
            }),
        })
    }
    async fn poll(&mut self, wait: Duration) -> Result<RemoteWatchBatch> {
        if wait > Duration::from_secs(30) {
            return Err(SeError::invalid("watch wait", "at most 30000ms"));
        }
        let until = tokio::time::Instant::now() + wait;
        loop {
            // Register before the finite drain, so publication during a store
            // read is retained in the ring and cannot become a lost wakeup.
            let changed = self.service.live.changed();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let mut state = self.state.take().ok_or_else(|| {
                SeError::invalid("watch state", "reconnect after an interrupted page")
            })?;
            let service = self.service.clone();
            let (state, batch, more) = self
                .service
                .blocking(move || {
                    let (batch, more) = state.drain(&service)?;
                    Ok((state, batch, more))
                })
                .await?;
            self.state = Some(state);
            if !batch.records.is_empty()
                || batch.reset_required
                || more
                || tokio::time::Instant::now() >= until
            {
                return Ok(batch);
            }
            // Both attributed observations and the existing post-COMMIT
            // observer notify this wait. Idle watches do not scan SQLite.
            tokio::select! {_=changed=>(),_=tokio::time::sleep_until(until)=>()}
        }
    }
}
impl RemoteWatchStream for Watch {
    fn next(&mut self, wait: Duration) -> RemoteFuture<'_, RemoteWatchBatch> {
        Box::pin(self.poll(wait))
    }
}
impl State {
    fn drain(&mut self, service: &Service) -> Result<(RemoteWatchBatch, bool)> {
        let mut batch = RemoteWatchBatch {
            schema: RemoteWatchBatch::SCHEMA.into(),
            body: RemoteWatchBody {
                observation_clock: self
                    .input
                    .measure
                    .then(|| service.live.clock())
                    .transpose()?,
                records: vec![],
                cursors: vec![],
                complete: true,
                omitted_records: Omission::None,
                reset_required: false,
            },
        };
        if self.initial {
            self.start(service, &mut batch)?;
            if !batch.records.is_empty() {
                return self.finish(batch, true);
            }
        }
        if self.manifest {
            return self.manifest_page(service);
        }
        let mut targets = self.request.targets().to_vec();
        targets.sort();
        if !targets.is_empty() {
            let len = targets.len();
            targets.rotate_left(self.offset % len);
        }
        if let Some(visible) = &self.input.visible
            && let Some(at) = targets.iter().position(|target| target == visible)
        {
            let target = targets.remove(at);
            targets.insert(0, target);
        }
        let revision = service.live.commit_revision();
        let durable = self.durable_revision != Some(revision) || revision == u64::MAX;
        let mut durable_pending = false;
        let mut visited = 0;
        let mut more = false;
        for target in &targets {
            let original = self.positions.get(target).cloned().unwrap_or_default();
            let mut next = original.clone();
            let live =
                service
                    .live
                    .read(target, original.live.as_ref(), self.input.budget as usize)?;
            if live.more && live.items.is_empty() {
                return Err(SeError::invalid(
                    "live preview budget",
                    "increase the encoded-byte budget to return one whole attributed preview; the original cursor was retained",
                ));
            }
            if live.gap {
                let record=RemoteWatchRecord::Gap {target:target.clone(),reason:"provisional source restarted, overflowed or became unavailable; replaying bounded durable state".into(),reset_required:true};
                let mut cursor = original.wire.clone().unwrap_or_else(|| RemoteCursorSet {
                    target: target.clone(),
                    durable: None,
                    live: None,
                });
                // A gap clears the old source stamp. With no retained item,
                // acknowledge only the observed loss/empty source watermark;
                // never advance across an item this page did not render.
                cursor.live = if live.items.is_empty() {
                    live.position
                        .as_ref()
                        .map(|position| {
                            service
                                .cursors
                                .json(&self.request, Some(target), "live", position)
                        })
                        .transpose()?
                } else {
                    None
                };
                if !push(&mut batch, record, Some(cursor.clone()), self.input.budget)? {
                    more = true;
                    break;
                }
                batch.reset_required = true;
                next.live = None;
                next.wire = Some(cursor);
            }
            if !live.available && original.live.is_none() {
                // Native status remains independently available in the manifest.
                // No provisional sequence or fake empty-history count is invented.
                next.live = None;
            }
            for observation in live.items.iter().take(1) {
                let cursor = service.cursors.json(
                    &self.request,
                    Some(target),
                    "live",
                    &observation.position,
                )?;
                let set = RemoteCursorSet {
                    target: target.clone(),
                    durable: next.wire.as_ref().and_then(|set| set.durable.clone()),
                    live: Some(cursor.clone()),
                };
                if !push(
                    &mut batch,
                    RemoteWatchRecord::Provisional {
                        target: target.clone(),
                        cursor,
                        item: observation.item.clone(),
                        observation: self
                            .input
                            .measure
                            .then(|| {
                                Ok::<_, SeError>(RemoteObservationTime {
                                    at_us: service.live.clock_us(observation.observed_at)?,
                                    age_upper_bound_us: None,
                                })
                            })
                            .transpose()?,
                    },
                    Some(set.clone()),
                    self.input.budget,
                )? {
                    more = true;
                    break;
                }
                next.live = Some(observation.position.clone());
                next.wire = Some(set);
            }
            more |= live.more || live.items.len() > 1;
            if live.items.is_empty() {
                next.live = live.position;
            }
            if durable {
                let changes = service.store.changes(
                    &self.request,
                    target,
                    se_store::remote::ChangeRequest {
                        after: next.durable.as_ref(),
                        limit: 100,
                        budget: self.input.budget,
                    },
                );
                let changes = match changes {
                    Ok(changes) => changes,
                    Err(error)
                        if matches!(error.body.detail(), se_types::Detail::CursorInvalid(_)) =>
                    {
                        if !push(&mut batch,RemoteWatchRecord::Gap {target:target.clone(),reason:"durable replay position no longer belongs to this store snapshot; reset this scoped view".into(),reset_required:true},None,self.input.budget)? {more=true;break;}
                        batch.reset_required = true;
                        self.positions.remove(target);
                        self.manifest = true;
                        self.manifest_after = None;
                        more = true;
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                if changes.more && changes.changes.is_empty() {
                    return Err(SeError::invalid(
                        "replay page budget",
                        "increase the encoded-byte budget to return one whole authorized record; the original cursor was retained",
                    ));
                }
                let mut admitted = true;
                for change in changes.changes {
                    let cursor =
                        service
                            .cursors
                            .durable(&self.request, target, &change.position)?;
                    let set = RemoteCursorSet {
                        target: target.clone(),
                        durable: Some(cursor.clone()),
                        live: next.wire.as_ref().and_then(|set| set.live.clone()),
                    };
                    let record = match change.kind {
                        se_store::remote::ChangeKind::Durable(event) => {
                            RemoteWatchRecord::Durable {
                                target: target.clone(),
                                cursor,
                                event,
                            }
                        }
                        se_store::remote::ChangeKind::ObserveStatus => {
                            let views = service.store.targets(
                                &self.request,
                                std::time::Instant::now() + Duration::from_secs(10),
                            )?;
                            let view = views
                                .into_iter()
                                .find(|view| &view.target == target)
                                .ok_or_else(|| {
                                    SeError::invalid("watch status", "the exact authorized target")
                                })?;
                            match view.status {se_types::Read::Present {value}=>RemoteWatchRecord::Durable {target:target.clone(),cursor,event:RemoteDurableEvent::Status {status:value}},_=>RemoteWatchRecord::Gap {target:target.clone(),reason:"native status observation is incomplete; inspect the scoped snapshot".into(),reset_required:false}}
                        }
                        se_store::remote::ChangeKind::Unavailable { reason } => {
                            RemoteWatchRecord::Gap {
                                target: target.clone(),
                                reason,
                                reset_required: true,
                            }
                        }
                    };
                    if !push(&mut batch, record, Some(set.clone()), self.input.budget)? {
                        more = true;
                        admitted = false;
                        break;
                    }
                    next.durable = Some(change.position);
                    next.wire = Some(set);
                }
                if admitted && !changes.more {
                    next.durable = changes.through;
                }
                more |= changes.more;
                durable_pending |= changes.more || !admitted;
            }
            self.positions.insert(target.clone(), next);
            visited += 1;
            self.offset = (self.offset + 1) % targets.len().max(1);
        }
        // A bounded page may stop before a target or its next durable row.
        // Do not acknowledge the wake until every selected target was drained.
        if durable && !durable_pending && visited == targets.len() {
            self.durable_revision = Some(revision);
        }
        self.finish(batch, more)
    }
    fn finish(&self, mut batch: RemoteWatchBatch, more: bool) -> Result<(RemoteWatchBatch, bool)> {
        batch.complete = !more && !batch.reset_required;
        batch.omitted_records = if more {
            Omission::Unknown {
                reason: OmissionReason::Budget,
            }
        } else if batch.reset_required {
            Omission::Unknown {
                reason: OmissionReason::SourceIncomplete,
            }
        } else {
            Omission::None
        };
        let length = wire::encode(&batch, wire::Phase::Authenticated)?.len();
        if length > self.input.budget as usize {
            return Err(SeError::too_large(
                "watch page; increase its encoded-byte budget",
                self.input.budget as usize,
                length,
            ));
        }
        Ok((batch, more))
    }
}
fn push(
    batch: &mut RemoteWatchBatch,
    record: RemoteWatchRecord,
    cursor: Option<RemoteCursorSet>,
    budget: u32,
) -> Result<bool> {
    let old_cursors = batch.cursors.clone();
    let old_reset = batch.reset_required;
    batch.reset_required |= matches!(
        &record,
        RemoteWatchRecord::Gap {
            reset_required: true,
            ..
        }
    );
    batch.records.push(record);
    if let Some(cursor) = cursor {
        if let Some(current) = batch
            .cursors
            .iter_mut()
            .find(|current| current.target == cursor.target)
        {
            *current = cursor;
        } else {
            batch.cursors.push(cursor);
        }
    }
    // Reserve space for the explicit incomplete marker before advancing any cursor.
    let measured = batch
        .records
        .iter()
        .filter(|record| {
            matches!(
                record,
                RemoteWatchRecord::Provisional {
                    observation: Some(_),
                    ..
                }
            )
        })
        .count();
    // A source release replaces null with up to twenty age digits.
    let bytes = wire::encode(batch, wire::Phase::Authenticated)?.len() + 96 + measured * 16;
    if bytes <= budget as usize {
        return Ok(true);
    }
    batch.records.pop();
    batch.cursors = old_cursors;
    batch.reset_required = old_reset;
    if batch.records.is_empty() {
        return Err(SeError::too_large(
            "whole watch record; increase the encoded-byte budget",
            budget as usize,
            bytes,
        ));
    }
    Ok(false)
}
