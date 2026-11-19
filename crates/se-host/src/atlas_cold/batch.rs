//! Bounded transactions for an unpublished cold epoch.
use super::*;

const MAX_FILES: usize = 4;
const FILE_GROWTH: u64 = 2_000_000;
const BATCH_TIME: Duration = Duration::from_millis(250);

pub(super) struct Runner<'a, 'db, F> {
    pub source: &'a RegisteredSource<NativeAtlasSource>,
    pub db: &'a mut CacheConnection<'db>,
    pub parser: &'a mut SemanticParser,
    pub request: &'a protocol::Request,
    pub notify: &'a mut F,
    pub deadline: Instant,
    pub completed: u64,
    pub reported: u64,
}

impl<F: FnMut(protocol::Reply) -> AtlasResult<()>> Runner<'_, '_, F> {
    pub(super) fn drain(
        &mut self,
        paths: &mut Vec<RelativePath>,
        discovered: u64,
        finish: bool,
    ) -> AtlasResult<()> {
        while paths.len() >= MAX_FILES || (finish && !paths.is_empty()) {
            let capacity = self.db.cold_batch_capacity(self.deadline)?.min(MAX_FILES);
            if capacity == 0 {
                return Err(failure("cold batch has no WAL capacity"));
            }
            let end = capacity.min(paths.len());
            let completed = self.chunk(&paths[..end], discovered)?;
            drop(paths.drain(..completed));
        }
        Ok(())
    }

    fn chunk(&mut self, paths: &[RelativePath], discovered: u64) -> AtlasResult<usize> {
        if paths.len() == 1 {
            self.single(&paths[0], discovered)?;
            return Ok(1);
        }
        self.db.release_cold_memory(sql_deadline())?;
        let source = self.source;
        let parser = &mut *self.parser;
        let request = self.request;
        let notify = &mut *self.notify;
        let mut attempted = 0usize;
        let mut changed = Vec::new();
        let mut retry_individually = false;
        let mut entered = false;
        let deadline = sql_deadline().min(self.deadline);
        let result = self
            .db
            .write(FILE_GROWTH * paths.len() as u64, deadline, |sql| {
                entered = true;
                let mut store = ingest::BatchStore {
                    sql,
                    failed_write: false,
                };
                let started = Instant::now();
                let mut witnesses = Vec::new();
                for path in paths {
                    let file_result =
                        ingest::file(source, &mut store, parser, path, request, &mut |phase| {
                            notify(protocol::Reply::Working {
                                job: request.job,
                                path: Some(path.clone()),
                                phase,
                            })
                        });
                    if store.failed_write {
                        retry_individually = true;
                        return Err(failure("retry failed cold write individually"));
                    }
                    let witness = file_result?;
                    witnesses.push(witness);
                    attempted += 1;
                    if started.elapsed() >= BATCH_TIME {
                        break;
                    }
                }
                for (index, witness) in witnesses.iter().enumerate() {
                    if !witness.unchanged(source).unwrap_or(false) {
                        changed.push(index);
                    }
                }
                if !changed.is_empty() {
                    return Err(failure("source changed during cold batch"));
                }
                Ok(())
            });
        match result {
            Ok(()) => {
                self.completed += attempted as u64;
                self.after_commit(discovered)?;
            }
            Err(error)
                if !changed.is_empty()
                    && retry_signal(&error, "source changed during cold batch") =>
            {
                for index in &changed {
                    self.single(&paths[*index], discovered)?;
                }
                let remaining: Vec<_> = paths[..attempted]
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| !changed.contains(index))
                    .map(|(_, path)| path.clone())
                    .collect();
                if !remaining.is_empty() {
                    let mut remaining = remaining;
                    self.drain(&mut remaining, discovered, true)?;
                }
            }
            Err(error)
                if (retry_individually
                    && retry_signal(&error, "retry failed cold write individually"))
                    || (!entered
                        && matches!(
                            error.body.detail(),
                            se_types::Detail::AtlasResourceBudget(_)
                        ))
                    || (self.db.cold_rollback_completed()
                        && matches!(error.body.detail(), se_types::Detail::DeadlineExceeded(detail) if detail.op == "Atlas SQL")) =>
            {
                for path in paths {
                    if let Err(single) = self.single(path, discovered) {
                        return Err(single.with_cause(error));
                    }
                }
                attempted = paths.len();
            }
            Err(error) => return Err(error),
        }
        Ok(attempted)
    }

    fn single(&mut self, path: &RelativePath, discovered: u64) -> AtlasResult<()> {
        let request = self.request;
        let notify = &mut *self.notify;
        ingest::file(
            self.source,
            self.db,
            self.parser,
            path,
            request,
            &mut |phase| {
                notify(protocol::Reply::Working {
                    job: request.job,
                    path: Some(path.clone()),
                    phase,
                })
            },
        )?;
        self.completed += 1;
        self.after_commit(discovered)
    }

    fn after_commit(&mut self, discovered: u64) -> AtlasResult<()> {
        if self.completed / 16 > self.reported / 16 {
            (self.notify)(protocol::Reply::Progress {
                job: self.request.job,
                discovered,
                completed: self.completed,
            })?;
            self.reported = self.completed;
        }
        (self.notify)(protocol::Reply::Working {
            job: self.request.job,
            path: None,
            phase: protocol::Phase::Checkpoint,
        })?;
        if !self.db.checkpoint(self.deadline)? {
            return Err(failure("unpublished cold epoch checkpoint remains busy"));
        }
        self.db.release_cold_memory(sql_deadline())?;
        se_proc::atlas_worker::release_allocator_pages();
        Ok(())
    }
}

fn retry_signal(error: &SeError, expected: &str) -> bool {
    matches!(error.body.detail(), se_types::Detail::UsageInvalidValue(detail)
        if detail.argument == "Atlas cold index" && detail.expected == expected)
}
