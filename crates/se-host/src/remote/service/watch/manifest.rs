//! Whole metadata rows and their scoped checkpoint fit one current-view page.
use super::*;
impl State {
    pub(super) fn manifest_page(&mut self, service: &Service) -> Result<(RemoteWatchBatch, bool)> {
        let mut limit = 20;
        loop {
            let page = list::page(
                service,
                &self.request,
                &RemoteList {
                    targets: self.input.targets.clone(),
                    cursor: self.manifest_after.clone(),
                    limit,
                    budget: self.input.budget.saturating_sub(256).max(512),
                },
            )?;
            let next = page.agents.next().cloned();
            let mut batch = RemoteWatchBatch {
                schema: RemoteWatchBatch::SCHEMA.into(),
                body: RemoteWatchBody {
                    records: vec![],
                    cursors: vec![],
                    complete: next.is_none(),
                    omitted_records: Omission::None,
                    reset_required: false,
                },
            };
            for view in page.agents.items() {
                if let Some(cursor) = self
                    .positions
                    .get(&view.target)
                    .and_then(|p| p.wire.clone())
                {
                    batch.cursors.push(cursor);
                }
                if matches!(
                    view.status,
                    se_types::Read::Present {
                        value: RemoteAgentStatus::Running { .. }
                    }
                ) && !service.live.read(&view.target, None, 0)?.available
                {
                    batch.records.push(RemoteWatchRecord::Gap {target: view.target.clone(), reason: "the running target has no attributed provisional publisher; local recovery or stream capacity must be resolved".into(), reset_required: true});
                    batch.reset_required = true;
                }
            }
            batch.records.insert(
                0,
                RemoteWatchRecord::Snapshot {
                    view: Box::new(page),
                },
            );
            let length = wire::encode(&batch, wire::Phase::Authenticated)?.len() + 96;
            if length > self.input.budget as usize {
                if limit == 1 {
                    return Err(SeError::too_large(
                        "whole watch snapshot and scoped checkpoint; increase the encoded-byte budget",
                        self.input.budget as usize,
                        length,
                    ));
                }
                limit = (limit / 2).max(1);
                continue;
            }
            self.manifest_after = next;
            self.manifest = self.manifest_after.is_some();
            return self.finish(batch, self.manifest);
        }
    }
}
