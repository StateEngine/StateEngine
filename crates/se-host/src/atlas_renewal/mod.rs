//! Event-driven Linux renewal. The runtime lends its one connection for each
//! operation; this driver owns no SQLite executor, thread or timer.
use crate::atlas_git_watch as metadata;
use crate::atlas_ignore as ignore;
mod observe;
mod port;
pub use port::{drive_events, drive_quantum};
#[cfg(windows)]
mod cold_capture;
mod scan;
mod summary;
mod watch;
use crate::atlas_source::NativeAtlasSource;
use crate::atlas_watch_error::{limit, source_error, timely};
use se_atlas::{
    cache::connection::CacheConnection,
    controller::Step,
    errors::AtlasResult,
    lifecycle::*,
    model::*,
    parse::ParserProfile,
    scheduler::Scheduled,
    source::RegisteredSource,
    update::{batch, file, observation},
};
use se_proc::{
    NativeSourceKind, NativeSourceRoot, NativeSourceWatch, NativeWatchAction, NativeWatchDirectory,
    NativeWatchEvents,
};
use se_types::{Detail, SeError, code::AtlasText, details};
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, BorrowedFd};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
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
    #[cfg(windows)]
    state: WatchState,
}
#[cfg(windows)]
#[derive(Clone, Copy)]
enum WatchState {
    Active,
    Retiring,
}
#[cfg(windows)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Catchup {
    Pending,
    Complete,
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
    pending_events: Option<PendingEvents>,
    #[cfg(windows)]
    catching_up: Catchup,
    last_lock: Option<bool>,
    pending_lock: Option<bool>,
    reasons: Vec<CoverageReason>,
}
struct PendingEvents {
    bytes: Vec<u8>,
    next: usize,
    hints: Vec<SourceHint>,
}
struct Cycle {
    root: RootId,
    serial: u64,
    reconcile: bool,
    subtree: Option<RelativePath>,
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
    #[cfg(windows)]
    signal: std::sync::Arc<tokio::sync::Notify>,
    #[cfg(windows)]
    cold_capture: Option<cold_capture::Capture>,
    started: Option<se_types::UnixMicros>,
    parser: crate::atlas_parse::Parser,
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
            #[cfg(windows)]
            signal: std::sync::Arc::new(tokio::sync::Notify::new()),
            #[cfg(windows)]
            cold_capture: None,
            started,
            parser: crate::atlas_parse::Parser::new(profiles),
            roots: Vec::with_capacity(2),
            mappings: Vec::new(),
            cycle: None,
        })
    }
    #[cfg(target_os = "linux")]
    pub fn event_fd(&self, root: &RootId) -> Option<BorrowedFd<'_>> {
        self.roots
            .iter()
            .find(|r| &r.id == root)?
            .native
            .as_ref()
            .map(|r| r.watch.as_fd())
    }
    #[cfg(windows)]
    pub fn signal(&self) -> std::sync::Arc<tokio::sync::Notify> {
        self.signal.clone()
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
                pending_events: None,
                #[cfg(windows)]
                catching_up: Catchup::Complete,
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
        #[cfg(windows)]
        if self.roots[index]
            .native
            .as_ref()
            .is_some_and(|native| matches!(native.state, WatchState::Retiring))
        {
            self.retire_native(index, deadline)?;
        }
        if self.roots[index].epoch != connection.identity().epoch {
            self.retire_native(index, deadline)?;
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
        #[cfg(windows)]
        if self.roots[index].native.is_none()
            && self
                .cold_capture
                .as_ref()
                .is_some_and(|capture| capture.activated && capture.id == scope.registration.root)
        {
            let capture = self
                .cold_capture
                .as_ref()
                .ok_or_else(|| source_error("cold source watch", "capture disappeared"))?;
            if capture
                .native
                .root
                .physical_identity()
                .map_err(|error| source_error("cold source activation", error))?
                != scope.physical_root
            {
                return Err(source_error(
                    "cold source activation",
                    "physical root changed; rebind",
                ));
            }
            let registration = capture.registration;
            let directory = connection.write(65536, deadline, |sql| {
                sql.prepare("DELETE FROM watch_directories WHERE path=''")?
                    .execute([])
                    .map_err(sql_error)?;
                sql.prepare(
                    "INSERT INTO watch_directories(descriptor,path,identity) VALUES(?1,'',?2)",
                )?
                .execute((
                    registration.descriptor,
                    registration.physical_directory.as_slice(),
                ))
                .map_err(sql_error)?;
                sql.prepare("SELECT id FROM watch_directories WHERE descriptor=?1")?
                    .query_row([registration.descriptor], |row| row.get::<_, i64>(0))
                    .map_err(sql_error)
            })?;
            let capture = self
                .cold_capture
                .take()
                .ok_or_else(|| source_error("cold source watch", "capture disappeared"))?;
            self.mappings.retain(|mapping| mapping.root != index as u32);
            self.mappings.push(Mapping {
                descriptor: registration.descriptor,
                root: index as u32,
                directory,
            });
            let root = &mut self.roots[index];
            root.native = Some(capture.native);
            root.cap = policy
                .watch
                .max_directories
                .min((policy.watch.max_mapping_bytes / 16).min(MAX_MAP as u32));
            root.attempts = root.attempts.saturating_add(1);
            root.unwatched = 0;
            root.limited_this_activation = false;
            root.reasons.clear();
            root.discovery_complete = true;
            root.requires_reconcile = false;
            root.catching_up = Catchup::Pending;
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
            let watch = NativeSourceWatch::new().map_err(|e| source_error("source watch", e))?;
            #[cfg(windows)]
            {
                let signal = self.signal.clone();
                watch
                    .set_signal(std::sync::Arc::new(move || signal.notify_one()))
                    .map_err(|e| source_error("source watch readiness", e))?;
            }
            root.native = Some(Native {
                root: native,
                watch,
                metadata: None,
                #[cfg(windows)]
                state: WatchState::Active,
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
        #[cfg(windows)]
        if let Some(capture) = self
            .cold_capture
            .as_mut()
            .filter(|capture| &capture.id == root)
        {
            let timeout = deadline.saturating_duration_since(Instant::now());
            capture
                .native
                .watch
                .shutdown(timeout)
                .map_err(|error| crate::atlas_parse::cleanup_error(error, timeout))?;
            self.cold_capture = None;
        }
        if let Some(connection) = connection.as_ref()
            && &connection.identity().scope.registration.root != root
        {
            return Err(SeError::invalid(
                "closing renewal connection",
                "the same root",
            ));
        }
        self.parser.close(deadline)?;
        // Native handles close even when an absent cache cannot lend SQL.
        if let Some(index) = self.roots.iter().position(|r| &r.id == root) {
            self.retire_native(index, deadline)?;
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

    fn retire_native(&mut self, index: usize, deadline: Instant) -> AtlasResult<()> {
        #[cfg(windows)]
        {
            let root = &mut self.roots[index];
            if let Some(native) = root.native.as_mut() {
                native.state = WatchState::Retiring;
                let timeout = deadline.saturating_duration_since(Instant::now());
                native
                    .watch
                    .shutdown(timeout)
                    .map_err(|error| crate::atlas_parse::cleanup_error(error, timeout))?;
            }
        }
        #[cfg(not(windows))]
        let _ = deadline;
        self.roots[index].native = None;
        self.roots[index].pending_events = None;
        self.mappings.retain(|mapping| mapping.root != index as u32);
        Ok(())
    }
}
fn sql_error(error: impl std::fmt::Display) -> SeError {
    SeError::new(Detail::AtlasUnreadable(details::AtlasUnreadable {
        path: "atlas.db".into(),
        reason: error.to_string(),
    }))
}
fn reason(root: &mut Root, reason: CoverageReason) {
    if !root.reasons.contains(&reason) {
        root.reasons.push(reason);
    }
}
