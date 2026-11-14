type ResumeRow = (
    Option<u64>,
    Option<u64>,
    Option<u64>,
    Option<u64>,
    u64,
    u64,
    u64,
);
mod access;
mod atlas_resume;
mod capture;
mod channel;
mod continuity;
mod control;
mod conversation;
mod cursor;
mod grant;
mod history;
mod import;
mod mail;
mod mail_legacy;
mod mail_sender;
mod message;
mod message_count;
mod notification;
mod page;
mod project;
mod query;
mod receipt;
mod remote_launch;
mod runtime;
mod search;
mod selector;
mod snapshot;
mod transcript;
use crate::{codec, connection, error::*, identity::*, open::SqliteReader, *};
use rusqlite::{Connection, OptionalExtension};
use se_types::{
    AgentId, Cursor, EventId, Omission, OmissionReason, Page, ProjectId, Read, Sequence, Source,
    StopReason, Window, WindowFields,
};
use se_types::{LifecycleId, SessionId};
use std::{marker::PhantomData, rc::Rc, time::Instant};
// SQLite closes and rolls back on implicit drop. Only an explicit successful
// close may return a connection to its host pool.
pub struct SqliteSnapshot {
    pub(crate) db: Connection,
    remote_launch_grant: Option<se_types::RemoteGrantId>,
    recycle: Option<crate::read_phase_pool::Recycle>,
    info: StoreInfo,
    scope: ReadScope,
    path: std::path::PathBuf,
    _slot: crate::read_slots::ReadSlot,
    _local: PhantomData<Rc<()>>,
}
impl SqliteSnapshot {
    pub(crate) fn open(reader: &SqliteReader, scope: ReadScope) -> StoreResult<Self> {
        reader.read_phase()?.into_snapshot(scope)
    }
    pub(crate) fn from_phase(phase: ReadPhase, scope: ReadScope) -> StoreResult<Self> {
        if matches!(scope.admission.actor, Actor::Remote(_))
            || matches!(scope.visibility, Visibility::None)
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "delegated clients require the closed grant-filtered remote read port",
            ));
        }
        if phase.info.state != StoreState::Ready {
            return Err(fail(StoreErrorCode::NotReady, "store is in maintenance"));
        }
        Ok(Self {
            db: phase.db,
            remote_launch_grant: None,
            recycle: phase.recycle,
            info: phase.info,
            scope,
            path: phase.path,
            _slot: phase.slot,
            _local: phase.local,
        })
    }
    /// Narrow one owner Registry read pin after CLI project selection. This
    /// changes no principal, visibility, generation or snapshot boundary.
    pub fn select_project(&mut self, project: ProjectId) -> StoreResult<()> {
        if self.scope.admission.scope == Scope::Project(project.clone()) {
            return Ok(());
        }
        if !matches!(self.scope.admission.scope, Scope::Registry)
            || !matches!(self.scope.visibility, Visibility::Owner)
            || !matches!(self.scope.admission.actor, Actor::Human(_))
            || self.scope.admission.session.is_some()
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "only an owner Registry pin can narrow to a selected project",
            ));
        }
        self.scope.admission.scope = Scope::Project(project);
        Ok(())
    }
}
pub struct LegacyRegistry<'a> {
    snapshot: &'a SqliteSnapshot,
}
impl se_types::LegacyIdRegistry for LegacyRegistry<'_> {
    fn resolve_alias(
        &self,
        kind: se_types::IdKind,
        alias: &str,
    ) -> se_types::Result<Option<String>> {
        if kind != se_types::IdKind::AgentId {
            return Ok(None);
        }
        let p = self
            .snapshot
            .project_bytes()
            .map_err(|e| se_types::SeError::invalid("imported alias scope", &e.cause))?;
        let scope = scope_key(
            &self.snapshot.db,
            &self.snapshot.scope.admission.scope,
            false,
        )
        .map_err(|e| se_types::SeError::invalid("imported alias scope", &e.cause))?;
        let id:Option<Vec<u8>>=self.snapshot.db.query_row("SELECT a.principal_id FROM aliases a JOIN events e ON e.seq=a.imported_seq JOIN principals p ON p.project_id=a.project_id AND p.principal_id=a.principal_id WHERE a.project_id=? AND a.alias=? AND p.principal_kind='agent' AND e.door='import'",rusqlite::params![p,alias],|r|r.get(0)).optional().map_err(|e|se_types::SeError::invalid("imported alias lookup",&e.to_string()))?;
        id.map(|id| {
            wire(&self.snapshot.db, "agent", &id, &scope)
                .map_err(|e| se_types::SeError::invalid("imported alias target", &e.cause))
        })
        .transpose()
    }
    fn contains(&self, kind: se_types::IdKind, text: &str) -> se_types::Result<bool> {
        let scope = scope_key(
            &self.snapshot.db,
            &self.snapshot.scope.admission.scope,
            false,
        )
        .map_err(|e| se_types::SeError::invalid("legacy registry", &e.cause))?;
        let kind = match kind {
            se_types::IdKind::AgentId => "agent",
            se_types::IdKind::HumanId => "human",
            se_types::IdKind::ProjectId => "project",
            se_types::IdKind::MessageId => "message",
            se_types::IdKind::DecisionId => "decision",
            se_types::IdKind::EventId => "event",
            se_types::IdKind::SessionId => "session",
            _ => return Ok(false),
        };
        if kind != "agent" {
            return Ok(false);
        }
        se_types::LegacyIdRegistry::contains(
            &crate::identity::StoredLegacyRegistry {
                db: &self.snapshot.db,
                scope: &scope,
            },
            se_types::IdKind::AgentId,
            text,
        )
    }
}

pub(crate) use crate::codec::event::load_event;
pub(crate) use cursor::checked_window_end;
