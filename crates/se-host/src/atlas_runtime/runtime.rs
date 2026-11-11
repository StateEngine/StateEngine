use super::*;
impl<D: RenewalDriver> Runtime for NativeRuntime<D> {
    type Source = RegisteredSource<NativeAtlasSource>;
    fn observed_summary(&self, root: &RootId) -> AtlasResult<Option<IndexSummary>> {
        Ok(self
            .roots
            .iter()
            .find(|r| &r.summary.root == root)
            .map(|r| r.summary.clone()))
    }
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    fn step(
        &mut self,
        registration: &RootRegistration,
        policy: &AtlasPolicy,
        work: &Scheduled,
        deadline: Instant,
    ) -> AtlasResult<Step> {
        self.admit(registration, policy)?;
        let result = (|| {
            let root = self.root(&registration.root)?;
            if (root.summary.epoch.is_none() || root.needs_rebuild) && self.active.is_none() {
                let mut bytes = [0; 16];
                se_proc::fill_entropy(&mut bytes).map_err(atlas_cold::failure)?;
                let job = AtlasJobId(bytes);
                self.pending = Some(WorkerRequest {
                    job,
                    root: registration.clone(),
                    expected_epoch: root.summary.epoch.clone(),
                    purpose: WorkerPurpose::ColdIndex,
                    paths: Vec::new(),
                    reservation: WorkerReservation {
                        host_steady_ceiling_bytes: 25_000_000,
                        child_peak_bytes: 64_000_000,
                        wall_deadline: Duration::from_secs(900),
                    },
                    policy: policy.clone(),
                });
                self.active = Some((job, registration.root.clone()));
            }
            if let Some((job, id)) = &self.active
                && id == &registration.root
            {
                let root = self
                    .roots
                    .iter_mut()
                    .find(|r| r.summary.root == registration.root)
                    .ok_or_else(|| atlas_cold::failure("native root disappeared"))?;
                root.summary.state = IndexState::ColdIndexing {
                    job: *job,
                    discovered_files: 0,
                };
                return Ok(Step {
                    report: WorkReport {
                        root: registration.root.clone(),
                        phase: WorkPhase::Discover,
                        completed_files: 0,
                        remaining_known: 1,
                        generation: None,
                        state: root.summary.state.clone(),
                    },
                    summary: root.summary.clone(),
                    complete: true,
                });
            }
            if self.active.is_some() {
                if let Some(root) = self
                    .roots
                    .iter_mut()
                    .find(|r| r.summary.root == registration.root)
                {
                    root.waiting_on_child = true;
                }
                return Err(atlas_cold::failure(
                    "another cold root owns the home writer; work resumes on exact child exit",
                ));
            }
            let profile = self.profile.as_ref().ok_or_else(|| {
                atlas_cold::failure(
                    "native SQL profile is unqualified; cold map remains verification-needed",
                )
            })?;
            let root = self
                .roots
                .iter_mut()
                .find(|r| r.summary.root == registration.root)
                .ok_or_else(|| atlas_cold::failure("native root disappeared"))?;
            let cache = NativeAtlasCache::create(&self.home, root.source.scope.clone())?;
            let mut current = super::connections::writer(&cache, root, profile, deadline)?
                .ok_or_else(|| atlas_cold::failure("renewal index disappeared"))?;
            root.checked_epoch = Some(current.connection.identity().epoch.clone());
            if root.serial_domain.is_none() {
                let base = current.connection.read(deadline, |sql| {
                    let value: i64 = sql
                        .prepare("SELECT observed_serial FROM meta WHERE singleton=1")?
                        .query_row([], |r| r.get(0))
                        .map_err(atlas_cold::failure)?;
                    u64::try_from(value).map_err(atlas_cold::failure)
                })?;
                root.serial_domain = Some((current.connection.identity().epoch.clone(), base));
            }
            let (epoch, base) = root
                .serial_domain
                .as_ref()
                .ok_or_else(|| atlas_cold::failure("renewal serial domain disappeared"))?;
            if epoch != &current.connection.identity().epoch {
                return Err(atlas_cold::failure(
                    "cache epoch changed; close and reconcile the native root before renewal",
                ));
            }
            let mapped = Scheduled {
                root: work.root.clone(),
                serial: durable_serial(*base, work.serial)?,
                hint: work.hint.clone(),
            };
            let step = self.driver.step(
                &root.source,
                &mut current.connection,
                &root.policy,
                &mapped,
                deadline,
            )?;
            root.summary = step.summary.clone();
            Ok(step)
        })();
        match result {
            Err(error) if se_atlas::controller::quantum_expired(&error) => {
                let root = self
                    .roots
                    .iter_mut()
                    .find(|root| root.summary.root == work.root)
                    .ok_or_else(|| atlas_cold::failure("paused native root disappeared"))?;
                // No failed SQL transaction advances its cursor. Keep native
                // readiness and the controller's unfinished work for the next
                // finite slice, with an explicit non-current observation.
                if !matches!(root.summary.state, IndexState::Partial { .. }) {
                    root.summary.state = IndexState::VerificationNeeded {
                        reason: CoverageReason::TimeLimit,
                    };
                }
                if !root
                    .summary
                    .coverage
                    .reasons
                    .contains(&CoverageReason::TimeLimit)
                {
                    root.summary
                        .coverage
                        .reasons
                        .push(CoverageReason::TimeLimit);
                }
                Ok(Step {
                    report: WorkReport {
                        root: work.root.clone(),
                        phase: WorkPhase::Read,
                        completed_files: 0,
                        remaining_known: 1,
                        generation: root.summary.generation,
                        state: root.summary.state.clone(),
                    },
                    summary: root.summary.clone(),
                    complete: false,
                })
            }
            result => result,
        }
    }
    fn publish(
        &mut self,
        id: &RootId,
        serial: u64,
        deadline: Instant,
    ) -> AtlasResult<IndexSummary> {
        if self.active.as_ref().is_some_and(|(_, root)| root == id) {
            return Ok(self.root(id)?.summary.clone());
        }
        let mut summary = self.root(id)?.summary.clone();
        let (epoch, base) = self.root(id)?.serial_domain.clone().ok_or_else(|| {
            atlas_cold::failure(
                "reconciliation must establish the durable source serial before publication",
            )
        })?;
        let serial = durable_serial(base, serial)?;
        let published=self.with_writer(id,deadline,|db,_| {
            let db_epoch=db.identity().epoch.clone();
            db.write(2_000_000,deadline,|sql| {
            if db_epoch!=epoch {return Err(atlas_cold::failure("publication cache epoch differs from the reconciled serial domain"));}
            let observed:i64=sql.prepare("SELECT observed_serial FROM meta WHERE singleton=1")?
                .query_row([],|r|r.get(0)).map_err(atlas_cold::failure)?;
            if u64::try_from(observed).map_err(atlas_cold::failure)?>serial {
                return Err(atlas_cold::failure("publication fence precedes the observed source serial"));
            }
            let pending:i64=sql.prepare("SELECT (SELECT count(*) FROM pending_paths)+(SELECT count(*) FROM renewal_directories)")?
                .query_row([],|r|r.get(0)).map_err(atlas_cold::failure)?;
            if pending!=0 {return Err(atlas_cold::failure("renewal has pending importer repairs or directory discovery; publication deferred"));}
            let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .map_err(atlas_cold::failure)?.as_millis().try_into().map_err(atlas_cold::failure)?;
            se_atlas::update::batch::publish(sql,now,false)?;
            let (generation,complete,coverage,state):(i64,bool,String,String)=sql.prepare("SELECT published_generation,discovery_complete,coverage_json,state_json FROM meta WHERE singleton=1")?
                .query_row([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(atlas_cold::failure)?;
            summary.generation=Some(Generation(generation.try_into().map_err(atlas_cold::failure)?));
            summary.coverage=serde_json::from_str(&coverage).map_err(atlas_cold::failure)?;
            let state: IndexState = serde_json::from_str(&state).map_err(atlas_cold::failure)?;
            if (summary.coverage.failed_files > 0 || summary.coverage.stale_files > 0) && matches!(state, IndexState::Partial { .. }) {
                summary.state = state;
            } else if complete {
                summary.state=if let Some(reason) = se_atlas::history::limitation(sql)? {
                    IndexState::VerificationNeeded {reason}
                } else if summary.coverage.unwatched_directories==0 && summary.coverage.watch_discovery_complete {
                    IndexState::Current
                } else {
                    IndexState::VerificationNeeded {reason:CoverageReason::PartialWatch}
                };
            }
            sql.prepare("UPDATE meta SET state_json=?1 WHERE singleton=1")?
                .execute([serde_json::to_string(&summary.state).map_err(atlas_cold::failure)?]).map_err(atlas_cold::failure)?;
            Ok(summary)
        })
        })?;
        if let Some(root) = self.roots.iter_mut().find(|r| &r.summary.root == id) {
            root.summary = published.clone();
        }
        Ok(published)
    }
    fn captured(&mut self, id: &RootId, evidence: EditEvidence) -> AtlasResult<()> {
        self.with_writer(id, atlas_cold::sql_deadline(), |db, _| {
            db.write(131072, atlas_cold::sql_deadline(), |sql| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(atlas_cold::failure)?
                    .as_millis()
                    .try_into()
                    .map_err(atlas_cold::failure)?;
                se_atlas::update::authors::captured(sql, &evidence, now, 0).map(|_| ())
            })
        })
    }
    fn with_reader<T>(
        &self,
        id: &RootId,
        read: impl FnOnce(&mut CacheConnection<'_>, &Self::Source) -> AtlasResult<T>,
    ) -> AtlasResult<T> {
        NativeRuntime::with_reader(self, id, read)
    }
    fn close(
        &mut self,
        id: &RootId,
        _reason: CloseReason,
        deadline: Instant,
    ) -> AtlasResult<CloseResult> {
        if self.active.as_ref().is_some_and(|(_, r)| r == id) {
            #[cfg(any(target_os = "linux", windows, target_os = "macos"))]
            {
                if let Some(child) = &mut self.child {
                    child.cancel_until(deadline)?;
                }
                self.child.take();
                self.child_failure = None;
            }
            self.pending.take();
            self.active.take();
        }
        // Native custody must close independently of this disposable index.
        // A child or watch close failure still retains ownership and refuses.
        self.driver.close(id, None, deadline)?;
        if let Err(error) = self.persist_closed(id, deadline) {
            eprintln!(
                "Code index shutdown metadata was not saved; native resources are closed and the cache is preserved: {error}"
            );
        }
        self.roots.retain(|r| &r.summary.root != id);
        Ok(CloseResult::Closed)
    }
    fn remove(&mut self, _id: &RootId) -> AtlasResult<CacheRemoval> {
        Err(atlas_cold::failure(
            "owned full-cache erasure is not available in the cold-index slice",
        ))
    }
    fn forget(&mut self, _id: &RootId, _events: &[se_types::EventId]) -> AtlasResult<CacheRemoval> {
        Err(atlas_cold::failure(
            "record erasure requires the bounded L6 record-feed maintenance path",
        ))
    }
    fn child_request(&mut self) -> AtlasResult<Option<WorkerRequest>> {
        Ok(self.pending.take())
    }
    fn child_event(&mut self, event: WorkerEvent) -> AtlasResult<(RootId, ScheduleReceipt)> {
        let (job, id) = self
            .active
            .as_ref()
            .ok_or_else(|| atlas_cold::failure("no active Atlas cold job"))?;
        let (received, exited) = match &event {
            WorkerEvent::Started { job } | WorkerEvent::Progress { job, .. } => (*job, false),
            WorkerEvent::Exited { job, .. } => (*job, true),
        };
        if &received != job {
            return Err(atlas_cold::failure("cold event belongs to another job"));
        }
        let id = id.clone();
        if exited {
            let root = self
                .roots
                .iter_mut()
                .find(|r| r.summary.root == id)
                .ok_or_else(|| atlas_cold::failure("native root disappeared"))?;
            let mut receipt = ScheduleReceipt::Coalesced;
            if let WorkerEvent::Exited { outcome, .. } = event {
                match outcome {
                    WorkerExit::Completed {
                        candidate_epoch, ..
                    } => {
                        if root.summary.epoch.as_ref() != Some(&candidate_epoch) {
                            return Err(atlas_cold::failure(
                                "candidate has not been independently adopted",
                            ));
                        }
                        receipt = ScheduleReceipt::ReconciliationRequired;
                    }
                    WorkerExit::Failed { error } => {
                        root.summary.state = IndexState::Suspended { reason: error }
                    }
                    _ => {
                        root.summary.state = IndexState::VerificationNeeded {
                            reason: CoverageReason::StaleSnapshot,
                        }
                    }
                }
            }
            self.active.take();
            return Ok((id, receipt));
        }
        Ok((id, ScheduleReceipt::Coalesced))
    }
}
fn durable_serial(base: u64, local: u64) -> AtlasResult<u64> {
    base.checked_add(local).filter(|serial|*serial<=i64::MAX as u64)
        .ok_or_else(||atlas_cold::failure("durable source serial exhausted; preserve the cache and perform explicit owned epoch repair"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restarted_source_serials_share_a_checked_durable_domain() -> AtlasResult<()> {
        assert_eq!(durable_serial(40, 1)?, 41);
        assert_eq!(durable_serial(40, 9)?, 49);
        assert!(durable_serial(i64::MAX as u64, 1).is_err());
        assert!(durable_serial(u64::MAX, 1).is_err());
        Ok(())
    }
}
