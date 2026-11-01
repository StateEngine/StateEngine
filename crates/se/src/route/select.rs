//! Select exact IDs/names or the nearest registered native ancestor. Every
//! bounded inventory must finish before absence or ambiguity is concluded.
use crate::bootstrap::Bootstrap;
use se_core::{admission::read_scope, registry, scope, store_error::store_error};
use se_store::{Admission, EventBody, ProjectionRecord, ReadBudget, ReadStore, Scope, Snapshot};
use se_types::{Detail, PageRequest, PathEncoding, ProjectChoice, Result, SeError, details};
use std::{num::NonZeroU32, time::Duration};

pub fn budget(after: Option<se_types::Cursor>) -> Result<ReadBudget> {
    Ok(ReadBudget {
        page: PageRequest {
            after,
            limit: NonZeroU32::new(100)
                .ok_or_else(|| SeError::invalid("project page", "positive limit"))?,
            max_bytes: NonZeroU32::new(1024 * 1024)
                .ok_or_else(|| SeError::invalid("project page", "positive byte budget"))?,
        },
        deadline: Duration::from_secs(1),
    })
}
pub fn projects<R: ReadStore>(reader: &R, admission: &Admission) -> Result<Vec<ProjectionRecord>> {
    let mut snapshot = reader
        .snapshot(read_scope(admission))
        .map_err(|e| store_error(&e))?;
    let result = (|| {
        let mut records = Vec::new();
        let mut after = None;
        for _ in 0..64 {
            let page = snapshot
                .projects(budget(after)?)
                .map_err(|e| store_error(&e))?;
            let next = page.next().cloned();
            let complete = page.window().complete();
            records.extend(page.into_items());
            match next {
                Some(cursor) => after = Some(cursor),
                None if complete => return Ok(records),
                None => break,
            }
        }
        Err(scope::unreadable(
            "project selection",
            "bounded registered-project inventory is incomplete",
        ))
    })();
    let closed = snapshot.close().map_err(|e| store_error(&e));
    match result {
        Ok(value) => {
            closed?;
            Ok(value)
        }
        Err(error) => Err(match closed {
            Ok(()) => error,
            Err(close) => error.with_cause(close),
        }),
    }
}
pub fn apply<R: ReadStore>(
    cx: &Bootstrap,
    reader: &R,
    admission: &mut Admission,
    op: &se_core::ops::AnyOp,
) -> Result<()> {
    let requested = cx.project.as_deref().or_else(|| {
        (!cx.config.value.default_project.is_empty())
            .then_some(cx.config.value.default_project.as_str())
    });
    if let Scope::Project(bound) = &admission.scope {
        if let Some(selector) = cx.project.as_deref() {
            let mut snap = reader
                .snapshot(read_scope(admission))
                .map_err(|e| store_error(&e))?;
            let record = snap.project(bound.clone()).map_err(|e| store_error(&e));
            let closed = snap.close().map_err(|e| store_error(&e));
            let record = scope::require_present(record?, "bound project")?;
            closed?;
            let name = match &record.current.body {
                EventBody::ProjectRegistered { name, .. }
                | EventBody::ProjectUpdated { name, .. } => name,
                _ => {
                    return Err(scope::unreadable(
                        "bound project",
                        "unexpected project metadata",
                    ));
                }
            };
            if selector != bound.to_string() && selector != name {
                return Err(SeError::invalid(
                    "project selection",
                    "the authenticated session's bound project",
                ));
            }
        }
        return Ok(());
    }
    if !matches!(
        op.meta().scope,
        registry::Scope::Project | registry::Scope::ProjectOrAll | registry::Scope::Session
    ) || cx.selections.status_all
    {
        return Ok(());
    }
    let cwd = se_proc::canonicalize_path(&cx.cwd)
        .map_err(|e| scope::unreadable("current directory", &e.to_string()))?;
    let mut candidates = Vec::new();
    let mut choices = Vec::new();
    for record in projects(reader, admission)? {
        let (id, name, roots) = match record.current.body {
            EventBody::ProjectRegistered {
                project,
                name,
                roots,
                ..
            }
            | EventBody::ProjectUpdated {
                project,
                name,
                roots,
                ..
            } => (project, name, roots),
            _ => {
                return Err(scope::unreadable(
                    "project metadata",
                    "unexpected registered-project body",
                ));
            }
        };
        choices.push(ProjectChoice {
            id: id.clone(),
            name: name.clone(),
            root: match roots.first().map(|root| root.path.encoded()) {
                Some(PathEncoding::UnixBytes(bytes)) => String::from_utf8_lossy(bytes).into_owned(),
                Some(PathEncoding::WindowsUtf16(units)) => String::from_utf16_lossy(units),
                None => "no registered root".into(),
            },
        });
        let depth = if let Some(selector) = requested {
            if selector == name || selector == id.to_string() {
                Some(0)
            } else {
                None
            }
        } else {
            let mut nearest = None;
            for root in roots {
                let root = root.path.to_local()?;
                if cwd.starts_with(&root) {
                    nearest = Some(nearest.unwrap_or(0).max(root.components().count()));
                }
            }
            nearest
        };
        if let Some(depth) = depth {
            candidates.push((depth, id));
        }
    }
    let nearest = candidates.iter().map(|(depth, _)| *depth).max();
    candidates.retain(|(depth, _)| Some(*depth) == nearest);
    match candidates.as_slice() {
        [(_, id)] => {
            admission.scope = Scope::Project(id.clone());
            Ok(())
        }
        [] if requested.is_none() && matches!(op, se_core::ops::AnyOp::ProjectStatus(_)) => Ok(()),
        [] => Err(SeError::new(Detail::ProjectRequired(
            details::ProjectRequired { choices },
        ))),
        rows => Err(SeError::new(Detail::SelectorAmbiguous(
            details::SelectorAmbiguous {
                kind: "project".into(),
                selector: requested.unwrap_or("current directory").into(),
                matches: rows.iter().map(|(_, id)| id.to_string()).collect(),
            },
        ))),
    }
}
