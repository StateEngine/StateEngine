//! Event-driven Linux renewal. The runtime lends its one connection for each
//! operation; this driver owns no SQLite executor, thread or timer.
mod glob;
mod ignore;
mod metadata;
mod observe;
mod port;
pub use port::{drive_events, drive_quantum};
mod scan;
mod summary;
mod watch;
use crate::atlas_source::NativeAtlasSource;
use se_atlas::{
    cache::connection::CacheConnection,
    controller::Step,
    errors::AtlasResult,
    lifecycle::*,
    model::*,
    parse::{ParserProfile, SemanticParser},
    scheduler::Scheduled,
    source::RegisteredSource,
    update::{batch, file, observation},
};
use se_proc::{
    NativeSourceKind, NativeSourceRoot, NativeSourceWatch, NativeWatchAction, NativeWatchDirectory,
    NativeWatchEvents,
};
use se_types::{Detail, SeError, code::AtlasText, details};
use std::{
    os::fd::{AsFd, BorrowedFd},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
type Source = RegisteredSource<NativeAtlasSource>;
// Reserve room within the adapter share for a native DIR buffer, retained
// metadata pins and transient bounded ignore input. Qualification may admit less.
const MAX_MAP: usize = 1024;
const WAL: u64 = 2_000_000;
#[derive(Clone, Copy)]
#[repr(C)]
struct Mapping {
    descriptor: u32,
    root: u32,
    directory: i64,
}
struct Native {
    root: NativeSourceRoot,
    watch: NativeSourceWatch,
    metadata: Option<metadata::Watches>,
}
struct Root {
    id: RootId,
    epoch: CacheEpoch,
    native: Option<Native>,
    attempts: u64,
    limited: u64,
    limited_this_activation: bool,
    started: Option<se_types::UnixMicros>,
    cap: u32,
    observed: Option<u64>,
    limit_error: Option<String>,
    unwatched: u64,
    discovery_complete: bool,
    requires_reconcile: bool,
    last_lock: Option<bool>,
    pending_lock: Option<bool>,
    reasons: Vec<CoverageReason>,
}
struct Cycle {
    root: RootId,
    serial: u64,
    reconcile: bool,
    cursor: Option<NativeWatchDirectory>,
    rules: Option<ignore::Rules>,
    pending_entry: Option<se_proc::NativeSourceEntry>,
    phase: Phase,
    after: i64,
    retained_last: i64,
    directories: u32,
    files: u32,
    part: u8,
    coverage: se_atlas::coverage::CoverageScan,
}
#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Retained,
    Directories,
    Files,
    Watches,
    Repairs,
    Coverage,
    Done,
}
pub struct NativeRenewal {
    started: Option<se_types::UnixMicros>,
    profiles: Vec<ParserProfile>,
    roots: Vec<Root>,
    mappings: Vec<Mapping>,
    cycle: Option<Cycle>,
}
impl NativeRenewal {
    /// Empty profiles preserve path/text coverage and explicitly defer semantics.
    /// A production profile must come from independent native qualification.
    pub fn new(profiles: Vec<ParserProfile>) -> AtlasResult<Self> {
        if profiles.len() > 6 {
            return Err(limit("renewal parser profiles", profiles.len() as u64, 6));
        }
        for p in &profiles {
            ParserProfile::from_qualified_measurement(
                p.language,
                p.placement,
                p.max_source_bytes,
                p.max_rows,
                p.parser_reservation_bytes,
                p.extraction_bytes,
            )?;
            if p.placement != se_atlas::parse::ParserPlacement::Incremental {
                return Err(SeError::invalid("renewal parser", "an incremental profile"));
            }
        }
        let started = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|n| u64::try_from(n.as_micros()).ok())
            .and_then(|n| se_types::UnixMicros::new(n).ok());
        Ok(Self {
            started,
            profiles,
            roots: Vec::with_capacity(2),
            mappings: Vec::new(),
            cycle: None,
        })
    }
    pub fn event_fd(&self, root: &RootId) -> Option<BorrowedFd<'_>> {
        self.roots
            .iter()
            .find(|r| &r.id == root)?
            .native
            .as_ref()
            .map(|r| r.watch.as_fd())
    }
    pub fn watch_diagnostic(&self, root: &RootId) -> Option<(u32, Option<u64>, Option<&str>)> {
        self.roots
            .iter()
            .find(|r| &r.id == root)
            .map(|r| (r.cap, r.observed, r.limit_error.as_deref()))
    }
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    fn root(
        &mut self,
        source: &Source,
        connection: &mut CacheConnection<'_>,
        policy: &AtlasPolicy,
        deadline: Instant,
    ) -> AtlasResult<usize> {
        timely(deadline)?;
        se_atlas::policy::validate(policy)?;
        let scope = &source.scope;
        if connection.identity().scope.registration != scope.registration
            || connection.identity().scope.physical_root != scope.physical_root
        {
            return Err(SeError::invalid(
                "renewal connection",
                "the same retained source scope",
            ));
        }
        let index = if let Some(index) = self
            .roots
            .iter()
            .position(|r| r.id == scope.registration.root)
        {
            index
        } else {
            let slot = if self.roots.len() < 2 {
                self.roots.len()
            } else {
                self.roots
                    .iter()
                    .position(|r| r.native.is_none())
                    .ok_or_else(|| limit("live renewal watch slots", 3, 2))?
            };
            let previous: Coverage = connection.read(deadline, |sql| {
                let json: String = sql
                    .prepare("SELECT coverage_json FROM meta WHERE singleton=1")?
                    .query_row([], |r| r.get(0))
                    .map_err(sql_error)?;
                serde_json::from_str(&json).map_err(sql_error)
            })?;
            let same_process =
                self.started.is_some() && previous.watch_stats_started == self.started;
            let root = Root {
                id: scope.registration.root.clone(),
                epoch: connection.identity().epoch.clone(),
                native: None,
                attempts: if same_process {
                    previous.watch_activation_attempts
                } else {
                    0
                },
                limited: if same_process {
                    previous.watch_limited_activations
                } else {
                    0
                },
                limited_this_activation: false,
                started: self.started,
                cap: 0,
                observed: None,
                limit_error: None,
                unwatched: 0,
                discovery_complete: false,
                requires_reconcile: true,
                last_lock: None,
                pending_lock: None,
                reasons: Vec::new(),
            };
            if slot == self.roots.len() {
                self.roots.push(root);
            } else {
                self.mappings.retain(|m| m.root != slot as u32);
                self.roots[slot] = root;
            }
            slot
        };
        if self.roots[index].epoch != connection.identity().epoch {
            self.roots[index].native = None;
            self.roots[index].epoch = connection.identity().epoch.clone();
            self.mappings.retain(|m| m.root != index as u32);
            if self
                .cycle
                .as_ref()
                .is_some_and(|c| c.root == scope.registration.root)
            {
                self.cycle = None;
            }
        }
        if self.roots[index].native.is_none() {
            self.mappings.retain(|m| m.root != index as u32);
            let native = NativeSourceRoot::open(&scope.registration.canonical_source_root)
                .map_err(|e| source_error("source activation", e))?;
            if native
                .physical_identity()
                .map_err(|e| source_error("source activation", e))?
                != scope.physical_root
            {
                return Err(source_error(
                    "source activation",
                    "physical root changed; rebind",
                ));
            }
            let (observed, limit_error) = match NativeSourceWatch::observed_limit() {
                Ok(limit) => (Some(limit), None),
                Err(error) => (None, Some(error.to_string())),
            };
            let available = observed
                .map(|n| (n / 8).min(MAX_MAP as u64) as u32)
                .unwrap_or(1024);
            let root = &mut self.roots[index];
            root.cap = policy
                .watch
                .max_directories
                .min(available)
                .min((policy.watch.max_mapping_bytes / 16).min(MAX_MAP as u32));
            root.observed = observed;
            root.limited_this_activation = false;
            root.limit_error = limit_error;
            root.attempts = root.attempts.saturating_add(1);
            root.discovery_complete = false;
            root.requires_reconcile = true;
            connection.write(65536, deadline, |sql| {
                sql.prepare("DELETE FROM watch_directories")?
                    .execute([])
                    .map_err(sql_error)?;
                Ok(())
            })?;
            root.native = Some(Native {
                root: native,
                watch: NativeSourceWatch::new().map_err(|e| source_error("source watch", e))?,
                metadata: None,
            });
        }
        Ok(index)
    }
    pub fn close(
        &mut self,
        root: &RootId,
        connection: Option<&mut CacheConnection<'_>>,
        deadline: Instant,
    ) -> AtlasResult<()> {
        if let Some(connection) = connection.as_ref()
            && &connection.identity().scope.registration.root != root
        {
            return Err(SeError::invalid(
                "closing renewal connection",
                "the same root",
            ));
        }
        // Native handles close even when an absent cache cannot lend SQL.
        if let Some(index) = self.roots.iter().position(|r| &r.id == root) {
            self.roots[index].native = None;
            self.roots[index].discovery_complete = false;
            self.roots[index].last_lock = None;
            self.roots[index].pending_lock = None;
            self.mappings.retain(|m| m.root != index as u32);
        }
        if self.cycle.as_ref().is_some_and(|c| &c.root == root) {
            self.cycle = None;
        }
        if self.roots.iter().all(|root| root.native.is_none()) {
            self.mappings = Vec::new();
        }
        if let Some(connection) = connection {
            let observed_unix_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| source_error("source batch close", e))?
                .as_millis();
            let observed_unix_ms = i64::try_from(observed_unix_ms).map_err(sql_error)?;
            connection.write(WAL, deadline, |sql| {
                batch::publish(sql, observed_unix_ms, true)?;
                let (json, prior): (String, String) = sql
                    .prepare("SELECT coverage_json,state_json FROM meta WHERE singleton=1")?
                    .query_row([], |r| Ok((r.get(0)?, r.get(1)?)))
                    .map_err(sql_error)?;
                let mut coverage: Coverage = serde_json::from_str(&json).map_err(sql_error)?;
                coverage.watched_directories = 0;
                coverage.watch_discovery_complete = false;
                let state = match serde_json::from_str(&prior).map_err(sql_error)? {
                    state @ IndexState::Partial { .. } => state,
                    _ => IndexState::VerificationNeeded {
                        reason: CoverageReason::StaleSnapshot,
                    },
                };
                sql.prepare("UPDATE meta SET coverage_json=?1,state_json=?2 WHERE singleton=1")?
                    .execute((
                        serde_json::to_string(&coverage).map_err(sql_error)?,
                        serde_json::to_string(&state).map_err(sql_error)?,
                    ))
                    .map_err(sql_error)?;

                sql.prepare("DELETE FROM watch_directories")?
                    .execute([])
                    .map_err(sql_error)?;
                sql.prepare("DELETE FROM renewal_directories")?
                    .execute([])
                    .map_err(sql_error)?;
                Ok(())
            })?;
        }
        Ok(())
    }
}
fn sql_error(error: impl std::fmt::Display) -> SeError {
    SeError::new(Detail::AtlasUnreadable(details::AtlasUnreadable {
        path: "atlas.db".into(),
        reason: error.to_string(),
    }))
}
fn source_error(path: &str, error: impl std::fmt::Display) -> SeError {
    SeError::new(Detail::AtlasSourceUnreadable(
        details::AtlasSourceUnreadable {
            path: path.into(),
            reason: error.to_string(),
        },
    ))
}
fn limit(resource: &str, requested: u64, available: u64) -> SeError {
    SeError::new(Detail::AtlasResourceBudget(details::AtlasResourceBudget {
        resource: resource.into(),
        requested,
        available,
    }))
}
fn timely(deadline: Instant) -> AtlasResult<()> {
    if Instant::now() >= deadline {
        Err(limit("renewal work deadline", 1, 0))
    } else {
        Ok(())
    }
}
fn reason(root: &mut Root, reason: CoverageReason) {
    if !root.reasons.contains(&reason) {
        root.reasons.push(reason);
    }
}
