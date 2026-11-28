//! Select exact IDs/names or the nearest registered native ancestor. Every
//! bounded inventory must finish before absence or ambiguity is concluded.
use crate::bootstrap::Bootstrap;
use se_core::{admission::read_scope, registry, scope, store_error::store_error};
use se_store::{
    Admission, EventBody, ProjectionRecord, ReadBudget, ReadStore, RemovedProjectQuery, Root,
    Scope, Snapshot,
};
use se_types::{
    Detail, PageRequest, PathEncoding, ProjectChoice, ProjectId, Result, SeError, details,
};
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
/// Opens a read snapshot under the caller's admitted read scope.
pub(super) fn open_snapshot<R: ReadStore>(
    reader: &R,
    admission: &Admission,
) -> Result<R::Snapshot> {
    reader
        .snapshot(read_scope(admission))
        .map_err(|e| store_error(&e))
}
/// The identity, name and current roots of an active project body; `None`
/// for any body that is not an active registration.
pub(super) fn active_project<T>(body: &EventBody<T>) -> Option<(&ProjectId, &str, &[Root])> {
    match body {
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
        } => Some((project, name, roots)),
        EventBody::ProjectMoved {
            project, name, to, ..
        } => Some((project, name, std::slice::from_ref(to))),
        _ => None,
    }
}
pub(super) fn inventory_at<S: Snapshot>(
    snapshot: &mut S,
    query: Option<RemovedProjectQuery>,
) -> Result<Vec<ProjectionRecord>> {
    let mut records = Vec::new();
    let mut after = None;
    for _ in 0..64 {
        let page = match &query {
            Some(query) => snapshot.removed_projects(query.clone(), budget(after)?),
            None => snapshot.projects(budget(after)?),
        }
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
}

/// Resolve an explicit `--project` selector (either a `ProjectId` or a saved
/// project name) against the registered projects in `home`, using the same
/// candidate/ambiguity policy as ordinary CLI commands without requiring
/// owner-terminal presence (so `se mcp --stdio --as` works under coding agents).
pub(crate) fn resolve_project_selector(
    home: &std::path::Path,
    selector: &str,
) -> Result<ProjectId> {
    use se_store::StoreFactory as _;
    if let Ok(id) = selector.parse::<ProjectId>() {
        return Ok(id);
    }
    let files = super::files::Files::open(home).map_err(|e| store_error(&e))?;
    let options = se_store::StoreOptions {
        state_directory: home.to_path_buf(),
        busy_timeout: Duration::from_secs(2),
    };
    let reader = scope::require_present(
        se_store::SqliteFactory::open_reader(&options).map_err(|e| store_error(&e))?,
        "project registry",
        "Run `se init` to initialize this StateEngine home first.",
    )?;
    let inventory = super::owner::inventory(&reader, &files)?;
    let [owner] = inventory.owners.as_slice() else {
        return Err(scope::unreadable(
            "project selection",
            "one retained protected owner is required",
        ));
    };
    let mut admission = Admission {
        actor: se_store::Actor::Human(owner.clone()),
        scope: Scope::Registry,
        session: None,
        generation: 1,
    };
    let mut snap = open_snapshot(&reader, &admission)?;
    let dummy = se_core::ops::AnyOp::ProjectStatus(Default::default());
    let res = gather_candidates(&mut snap, Some(selector), home, None, &dummy).and_then(
        |(candidates, choices)| {
            select_scope(candidates, choices, Some(selector), &dummy, &mut admission)
        },
    );
    super::execute::finish_read(res, snap.close().map_err(|e| store_error(&e)))?;
    match admission.scope {
        Scope::Project(id) => Ok(id),
        Scope::Registry => Err(SeError::new(Detail::ProjectRequired(
            details::ProjectRequired { choices: vec![] },
        ))),
    }
}

pub fn apply<S: Snapshot>(
    cx: &Bootstrap,
    snapshot: &mut S,
    admission: &mut Admission,
    op: &se_core::ops::AnyOp,
) -> Result<()> {
    let requested = cx.project.as_deref().or_else(|| {
        (!cx.config.value.default_project.is_empty())
            .then_some(cx.config.value.default_project.as_str())
    });
    if let Scope::Project(bound) = &admission.scope {
        bound_project_check(snapshot, bound, cx.project.as_deref())?;
        return Ok(());
    }
    if !matches!(
        op.meta().scope,
        registry::Scope::Project | registry::Scope::ProjectOrAll | registry::Scope::Session
    ) || cx.selections.status_all
        || (cx.selections.control_all && cx.project.is_none())
    {
        return Ok(());
    }
    // Retained history and removal retries must still select a tombstone by
    // its exact ID. The ordinary project list intentionally contains only
    // active registrations; sessions remain bound by the earlier branch.
    if retained_exact_id(snapshot, admission, op, requested)? {
        return Ok(());
    }
    let ancestry_cwd = requested
        .is_none()
        .then(|| std::fs::canonicalize(&cx.cwd))
        .transpose()
        .map_err(|e| scope::unreadable("current directory", &e.to_string()))?;
    let (candidates, choices) =
        gather_candidates(snapshot, requested, &cx.cwd, ancestry_cwd.as_deref(), op)?;
    select_scope(candidates, choices, requested, op, admission)
}
fn bound_project_check<S: Snapshot>(
    snapshot: &mut S,
    bound: &ProjectId,
    selector: Option<&str>,
) -> Result<()> {
    let Some(selector) = selector else {
        return Ok(());
    };
    let record = scope::require_present(
        snapshot
            .project(bound.clone())
            .map_err(|e| store_error(&e))?,
        "bound project",
        "Select an existing project in this data home with --project, or restore its original project binding.",
    )?;
    let Some((_, name, _)) = active_project(&record.current.body) else {
        return Err(scope::unreadable(
            "bound project",
            "unexpected project metadata",
        ));
    };
    if selector != bound.to_string() && selector != name {
        return Err(SeError::invalid(
            "project selection",
            "the authenticated session's bound project",
        ));
    }
    Ok(())
}
fn retained_exact_id<S: Snapshot>(
    snapshot: &mut S,
    admission: &mut Admission,
    op: &se_core::ops::AnyOp,
    requested: Option<&str>,
) -> Result<bool> {
    if op.meta().effect != registry::Effect::Read
        && !matches!(op, se_core::ops::AnyOp::ProjectRemove(_))
    {
        return Ok(false);
    }
    let Some(id) = requested.and_then(|value| value.parse::<se_types::ProjectId>().ok()) else {
        return Ok(false);
    };
    let record = snapshot.project(id.clone()).map_err(|e| store_error(&e))?;
    match record {
        se_types::Read::Present { .. } => {
            admission.scope = Scope::Project(id);
            Ok(true)
        }
        se_types::Read::Absent { .. } => Ok(false),
        other => {
            scope::require_present(
                other,
                "selected project",
                "Restore access to the retained project metadata, then retry its exact ID.",
            )?;
            Ok(false)
        }
    }
}
type Candidate = (usize, ProjectId);
fn gather_candidates<S: Snapshot>(
    snapshot: &mut S,
    requested: Option<&str>,
    raw_cwd: &std::path::Path,
    ancestry_cwd: Option<&std::path::Path>,
    op: &se_core::ops::AnyOp,
) -> Result<(Vec<Candidate>, Vec<ProjectChoice>)> {
    let mut candidates = Vec::new();
    let mut choices = Vec::new();
    for record in inventory_at(snapshot, None)? {
        let Some((id, name, roots)) = active_project(&record.current.body) else {
            return Err(scope::unreadable(
                "project metadata",
                "unexpected registered-project body",
            ));
        };
        choices.push(ProjectChoice {
            id: id.clone(),
            name: name.to_owned(),
            root: match roots.first().map(|root| root.path.encoded()) {
                Some(PathEncoding::UnixBytes(bytes)) => String::from_utf8_lossy(bytes).into_owned(),
                Some(PathEncoding::WindowsUtf16(units)) => String::from_utf16_lossy(units),
                None => "no registered root".into(),
            },
        });
        let depth = candidate_depth(requested, id, name, roots, ancestry_cwd)?;
        if let Some(depth) = depth {
            candidates.push((depth, id.clone()));
        }
    }
    if candidates.is_empty()
        && (op.meta().effect == registry::Effect::Read
            || matches!(op, se_core::ops::AnyOp::ProjectRemove(_)))
    {
        for record in super::retained::select(snapshot, requested, raw_cwd)? {
            let view = se_core::ops::project_remove::removed_view(&record)?.ok_or_else(|| {
                scope::unreadable(
                    "retained project selection",
                    "lookup returned an active project",
                )
            })?;
            candidates.push((0, view.project.id.clone()));
            choices.push(ProjectChoice {
                id: view.project.id,
                name: view.project.name,
                root: view.root,
            });
        }
    }
    Ok((candidates, choices))
}
fn candidate_depth(
    requested: Option<&str>,
    id: &ProjectId,
    name: &str,
    roots: &[Root],
    ancestry_cwd: Option<&std::path::Path>,
) -> Result<Option<usize>> {
    if let Some(selector) = requested {
        return Ok(if selector == name || selector == id.to_string() {
            Some(0)
        } else {
            None
        });
    }
    let Some(ancestry_cwd) = ancestry_cwd else {
        return Ok(None);
    };
    let mut nearest = None;
    for root in roots {
        let root = match std::fs::canonicalize(root.path.to_local()?) {
            Ok(root) => root,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(scope::unreadable(
                    "registered project root",
                    &error.to_string(),
                ));
            }
        };
        if ancestry_cwd.starts_with(&root) {
            nearest = Some(nearest.unwrap_or(0).max(root.components().count()));
        }
    }
    Ok(nearest)
}
fn select_scope(
    mut candidates: Vec<Candidate>,
    choices: Vec<ProjectChoice>,
    requested: Option<&str>,
    op: &se_core::ops::AnyOp,
    admission: &mut Admission,
) -> Result<()> {
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
