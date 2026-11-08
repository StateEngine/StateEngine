//! Decode resumed cursors or establish a fresh current-view cut.
use super::*;
impl State {
    pub(super) fn start(&mut self, service: &Service, batch: &mut RemoteWatchBatch) -> Result<()> {
        for cursor in &self.input.cursors {
            let decoded = (|| {
                Ok::<_, SeError>(Position {
                    durable: cursor
                        .durable
                        .as_ref()
                        .map(|value| {
                            service
                                .cursors
                                .position(&self.request, &cursor.target, value)
                        })
                        .transpose()?,
                    live: cursor
                        .live
                        .as_ref()
                        .map(|value| {
                            service.cursors.decoded(
                                &self.request,
                                Some(&cursor.target),
                                "live",
                                value,
                            )
                        })
                        .transpose()?,
                    wire: Some(cursor.clone()),
                })
            })();
            match decoded {
                Ok(position) => {
                    self.positions.insert(cursor.target.clone(), position);
                }
                Err(_) => {
                    batch.records.push(RemoteWatchRecord::Gap {target:cursor.target.clone(),reason:"cursor authentication, restore or scope binding differs; resetting this scoped history".into(),reset_required:true});
                    batch.reset_required = true;
                }
            }
        }
        self.initial = false;
        if !batch.records.is_empty() {
            return Ok(());
        }
        // Establish both high waters before the metadata view. Commits
        // concurrent with its read remain replayable after this cut.
        for target in self.request.admission().targets() {
            if self.positions.contains_key(target) {
                continue;
            }
            let durable = service.store.watch_position(&self.request, target)?;
            let live = service.live.checkpoint(target)?;
            let wire = RemoteCursorSet {
                target: target.clone(),
                durable: durable
                    .as_ref()
                    .map(|p| service.cursors.durable(&self.request, target, p))
                    .transpose()?,
                live: live
                    .as_ref()
                    .map(|p| service.cursors.json(&self.request, Some(target), "live", p))
                    .transpose()?,
            };
            self.positions.insert(
                target.clone(),
                Position {
                    durable,
                    live,
                    wire: Some(wire),
                },
            );
        }
        Ok(())
    }
}
