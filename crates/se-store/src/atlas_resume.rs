//! Private delivered-code cursor CAS, executed by the existing sole store writer.
//! No tool/request can submit a delivery fact; the host calls this after IO completes.
use crate::{connection, error::*, identity::*, *};
use rusqlite::{Connection, OptionalExtension, params};
use se_types::{
    AtlasRootId, IndexEpochId,
    code::{AtlasCursor, ResumeAdvance, ResumeCursorCommit},
};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct AtlasResumeHead {
    pub cursor: Option<AtlasCursor>,
    pub revision: u64,
    pub fence: u64,
}
#[derive(Clone, Debug)]
pub enum AtlasResumeMutation {
    /// Lifecycle-only. Epoch replacement/privacy retirement invalidates pending offers.
    Epoch {
        project: se_types::ProjectId,
        root: AtlasRootId,
        expected: Option<IndexEpochId>,
        next: Option<IndexEpochId>,
    },
    /// The host supplies the verified viewer and the actual successful context
    /// delivery ID, after retaining the code section in the transmitted frame.
    Delivered {
        admission: Admission,
        root: AtlasRootId,
        epoch: IndexEpochId,
        viewer: se_types::AgentId,
        delivery: se_types::EventId,
        section_sha256: [u8; 32],
        advance: ResumeAdvance,
    },
}
#[derive(Debug)]
pub enum AtlasResumeWrite {
    EpochSet,
    Cursor(ResumeCursorCommit),
}
impl AtlasResumeMutation {
    pub(crate) fn bytes(&self) -> StoreResult<usize> {
        match self {
            Self::Epoch { .. } => Ok(512),
            Self::Delivered { advance, .. } => {
                let bytes = serde_json::to_vec(advance).map_err(invalid)?.len() + 1024;
                if bytes > 12_288 {
                    return Err(invalid("Atlas resume control data exceeds 12 KiB"));
                }
                Ok(bytes)
            }
        }
    }
}
pub(crate) fn apply(
    db: &Connection,
    mutation: AtlasResumeMutation,
    generation: u64,
) -> StoreResult<AtlasResumeWrite> {
    let transaction =
        rusqlite::Transaction::new_unchecked(db, rusqlite::TransactionBehavior::Immediate)
            .map_err(sql)?;
    let fence: Option<(u64, Option<String>)> = db
        .query_row(
            "SELECT owner_generation,phase FROM runtime_owner WHERE singleton=1",
            [],
            |r| Ok((crate::sql_value::value(r, 0)?, r.get(1)?)),
        )
        .optional()
        .map_err(sql)?;
    if fence.is_none_or(|(g, p)| {
        g != generation || matches!(p.as_deref(), Some("Prepared" | "Claimed"))
    }) {
        return Err(fail(
            StoreErrorCode::GenerationChanged,
            "Atlas delivery owner/fence changed",
        ));
    }
    let result = match mutation {
        AtlasResumeMutation::Epoch {
            project,
            root,
            expected,
            next,
        } => {
            let p = connection::project_id(db, &Scope::Project(project), false)?;
            active_project(db, &p)?;
            let old: Option<(String, bool)> = db
                .query_row(
                    "SELECT epoch,active FROM atlas_resume_roots WHERE project_id=?1 AND root=?2",
                    params![p, root.as_str()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(sql)?;
            if old
                .as_ref()
                .filter(|(_, active)| *active)
                .map(|(epoch, _)| epoch.as_str())
                != expected.as_ref().map(IndexEpochId::as_str)
            {
                return Err(fail(
                    StoreErrorCode::RevisionConflict,
                    "Atlas epoch changed before lifecycle update",
                ));
            }
            if let Some(next) = next {
                if old
                    .as_ref()
                    .is_some_and(|(epoch, active)| *active && epoch == next.as_str())
                {
                    return Ok(AtlasResumeWrite::EpochSet);
                }
                db.execute(
                    "DELETE FROM atlas_resume_cursors WHERE project_id=?1 AND root=?2",
                    params![p, root.as_str()],
                )
                .map_err(sql)?;
                db.execute("INSERT INTO atlas_resume_roots VALUES(?1,?2,?3,1) ON CONFLICT(project_id,root) DO UPDATE SET epoch=excluded.epoch,active=1",params![p,root.as_str(),next.as_str()]).map_err(sql)?;
            } else {
                db.execute(
                    "DELETE FROM atlas_resume_roots WHERE project_id=?1 AND root=?2",
                    params![p, root.as_str()],
                )
                .map_err(sql)?;
            }
            AtlasResumeWrite::EpochSet
        }
        AtlasResumeMutation::Delivered {
            admission,
            root,
            epoch,
            viewer,
            delivery,
            section_sha256,
            advance,
        } => {
            if admission.generation != generation
                || admission.actor != Actor::Agent(viewer.clone())
                || admission.session.is_none()
            {
                return Err(fail(
                    StoreErrorCode::ScopeMismatch,
                    "Atlas delivered cursor requires the verified active viewer/session",
                ));
            }
            let p = connection::project_id(db, &admission.scope, false)?;
            active_project(db, &p)?;
            let scope = scope_key(db, &admission.scope, false)?;
            let a = key(db, "agent", viewer.as_str(), &scope, false)?;
            let session = admission
                .session
                .as_ref()
                .ok_or_else(|| invalid("missing Atlas viewer session"))?;
            let session = key(db, "session", session.as_str(), &scope, false)?;
            let active:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM sessions WHERE project_id=?1 AND session_id=?2 AND agent_id=?3 AND state='active')",params![p,session,a],|r|r.get(0)).map_err(sql)?;
            if !active {
                return Err(fail(
                    StoreErrorCode::InvalidTransition,
                    "Atlas viewer session is no longer active",
                ));
            }
            let current:Option<String>=db.query_row("SELECT epoch FROM atlas_resume_roots WHERE project_id=?1 AND root=?2 AND active=1",params![p,root.as_str()],|r|r.get(0)).optional().map_err(sql)?;
            if current.as_deref() != Some(epoch.as_str()) {
                return Err(fail(
                    StoreErrorCode::RevisionConflict,
                    "Atlas epoch retired; discard the old offer",
                ));
            }
            let Scope::Project(project) = &admission.scope else {
                return Err(fail(
                    StoreErrorCode::ScopeMismatch,
                    "Atlas cursor requires one project",
                ));
            };
            let position = se_types::code::CodeCursorPosition::decode(&advance.next_cursor)
                .map_err(invalid)?;
            if position
                .resume_fence(
                    project,
                    &root,
                    &epoch,
                    &se_types::code::AtlasPrincipal::Agent(viewer.clone()),
                )
                .map_err(invalid)?
                != advance.fence.0
            {
                return Err(invalid("Atlas next cursor fence differs from the offer"));
            }
            let fingerprint: [u8; 32] = Sha256::digest(
                serde_json::to_vec(&(&advance, section_sha256, &epoch, &viewer))
                    .map_err(invalid)?,
            )
            .into();
            let prior:Option<(Vec<u8>,u64)>=db.query_row("SELECT fingerprint,revision FROM atlas_resume_deliveries WHERE project_id=?1 AND root=?2 AND agent_id=?3 AND offer=?4",params![p,root.as_str(),a,advance.offer.0.as_slice()],|r|Ok((r.get(0)?,crate::sql_value::value(r,1)?))).optional().map_err(sql)?;
            if let Some((digest, revision)) = prior {
                if digest != fingerprint {
                    return Err(fail(
                        StoreErrorCode::NaturalKeyConflict,
                        "Atlas offer replay differs from its delivered section",
                    ));
                }
                return Ok(AtlasResumeWrite::Cursor(
                    ResumeCursorCommit::AlreadyApplied { revision },
                ));
            }
            let old:Option<(String,u64,u64)>=db.query_row("SELECT cursor,revision,fence FROM atlas_resume_cursors WHERE project_id=?1 AND root=?2 AND agent_id=?3",params![p,root.as_str(),a],|r|Ok((r.get(0)?,crate::sql_value::value(r,1)?,crate::sql_value::value(r,2)?))).optional().map_err(sql)?;
            let actual_revision = old.as_ref().map_or(0, |v| v.1);
            if actual_revision != advance.expected_revision
                || old.as_ref().map(|v| v.0.as_str())
                    != advance
                        .expected_cursor
                        .as_ref()
                        .map(se_types::code::AtlasText::as_str)
            {
                return Ok(AtlasResumeWrite::Cursor(ResumeCursorCommit::Stale {
                    actual_revision,
                }));
            }
            if old.as_ref().is_some_and(|v| advance.fence.0 < v.2) {
                return Err(fail(
                    StoreErrorCode::InvalidTransition,
                    "Atlas cursor cannot move backward",
                ));
            }
            let revision = actual_revision
                .checked_add(1)
                .ok_or_else(|| invalid("Atlas cursor revision exhausted"))?;
            db.execute("INSERT INTO atlas_resume_cursors VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(project_id,root,agent_id) DO UPDATE SET cursor=excluded.cursor,revision=excluded.revision,fence=excluded.fence",crate::sql_value::sql_params![p,root.as_str(),a,se_types::code::AtlasText::as_str(&advance.next_cursor),revision,advance.fence.0]).map_err(sql)?;
            db.execute(
                "INSERT INTO atlas_resume_deliveries VALUES(?1,?2,?3,?4,?5,?6,?7)",
                crate::sql_value::sql_params![
                    p,
                    root.as_str(),
                    a,
                    advance.offer.0.as_slice(),
                    delivery.as_str(),
                    fingerprint,
                    revision
                ],
            )
            .map_err(sql)?;
            db.execute("DELETE FROM atlas_resume_deliveries WHERE project_id=?1 AND root=?2 AND agent_id=?3 AND revision<=?4",crate::sql_value::sql_params![p,root.as_str(),a,revision.saturating_sub(64)]).map_err(sql)?;
            AtlasResumeWrite::Cursor(ResumeCursorCommit::Applied { revision })
        }
    };
    transaction.commit().map_err(|e| {
        let mut error = sql(e);
        error.code = StoreErrorCode::CommitOutcomeUnknown;
        error
            .cause
            .push_str("; retry the identical delivered Atlas offer");
        error
    })?;
    Ok(result)
}
fn active_project(db: &Connection, p: &[u8]) -> StoreResult<()> {
    let active: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM projects WHERE project_id=?1 AND state<>'removed')",
            [p],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if !active {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "Atlas project is absent or removed",
        ));
    }
    Ok(())
}
