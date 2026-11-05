//! Owner CLI route for `se project move <ROOT>`. The native folder checks and
//! the recorded git identity verification happen here, in the owner's
//! terminal; the store then re-enforces the door, scope, owner and
//! live-custody rules before the roots revision applies. The kernel itself
//! never plans a move, so no other surface can propose one.
use super::{admit::Caller, execute, files::DirectLease, files::Files, git_identity};
use crate::bootstrap::Bootstrap;
use se_core::{
    admission::read_scope,
    commit::Cx,
    dispatch::Kernel,
    ops::{AnyOutput, MoveOutput, ProjectMove, inputs::Validate, project},
    scope,
    store_error::{store_error, write_error},
};
use se_store::{
    DirectStore, EventBody, LeaseIdentity, LeaseMode, ReadStore, Snapshot, SqliteFactory,
    SqliteReader, StoreFactory, StoreOptions,
};
use se_types::{EventId, NativePath, Read, Result, SeError, details};
use std::{path::PathBuf, time::Duration};

pub(super) fn execute(
    cx: &Bootstrap,
    reader: &SqliteReader,
    caller: &Caller,
    input: ProjectMove,
) -> Result<AnyOutput> {
    input.validate()?;
    let project_id = scope::project(&caller.admission)?;
    let mut preflight = reader
        .snapshot(read_scope(&caller.admission))
        .map_err(|e| store_error(&e))?;
    let record = scope::require_present(
        preflight
            .project(project_id.clone())
            .map_err(|e| store_error(&e))?,
        "moved project",
        "Select the project by name or exact ID, then retry se project move with the new folder.",
    )?;
    let from_roots = match &record.current.body {
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
        } if *project == project_id => roots.clone(),
        EventBody::ProjectMoved {
            project, name, to, ..
        } if *project == project_id => {
            vec![to.clone()]
        }
        _ => {
            return Err(scope::unreadable(
                "moved project",
                "active registration metadata is unavailable",
            ));
        }
    };
    let replayed = preflight
        .operation_receipt(
            caller.admission.actor.clone(),
            input.idempotency_key.clone(),
        )
        .map_err(|e| store_error(&e))?;
    preflight.close().map_err(|e| store_error(&e))?;
    match replayed {
        Read::Present { value: receipt } => {
            // The key is retained by an earlier committed call. Return that
            // call's output: the folder already holds the moved repository,
            // so the physical preflight applies to first use only.
            let target = resolve_target(cx, &input.root)?;
            let to_path = NativePath::from_local(target)
                .map_err(|e| scope::unreadable("move target identity", &e.to_string()))?;
            let mut readback = reader
                .snapshot(read_scope(&caller.admission))
                .map_err(|e| store_error(&e))?;
            let output: MoveOutput = project::move_replay(
                &project_id,
                &input.idempotency_key,
                &to_path,
                receipt,
                &mut Cx {
                    read: &mut readback,
                    admission: &caller.admission,
                },
            )?;
            readback.close().map_err(|e| store_error(&e))?;
            return Ok(AnyOutput::from(output));
        }
        Read::Absent { .. } => {}
        Read::Unreadable { reason, .. } => {
            return Err(scope::unreadable("operation receipt", &reason));
        }
        Read::Unknown { what } => {
            return Err(scope::unreadable("operation receipt", &what));
        }
    }
    let target = resolve_target(cx, &input.root)?;
    if git_identity::is_bare(&target)? {
        return Err(refusal(
            "moved repository folder",
            "the new folder is a bare Git repository without a working tree",
            "Clone it (git clone FOLDER work) and move or register the clone's working tree instead.",
        ));
    }
    let (head, branch) = git_identity::verify(&target, &project_id.to_string())?;
    // A move re-attaches a repository whose registered folder is gone. A copy
    // with the old folder still present is refused so one registration can
    // never point at two locations of the same history.
    let mut present = Vec::new();
    for root in &from_roots {
        let path = root
            .path
            .to_local()
            .map_err(|e| scope::unreadable("registered root", &e.to_string()))?;
        // Absent and unreadable are different facts: a permission error is
        // not proof the repository left, so it refuses instead of copying.
        match std::fs::metadata(&path) {
            Ok(_) => present.push(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(refusal(
                    "registered root",
                    &format!(
                        "the original folder at {} is unreadable ({error})",
                        path.display()
                    ),
                    "Restore read access to the original folder, verify the repository left it, then retry the move; an unreadable folder is not proof that it is gone.",
                ));
            }
        }
    }
    if let Some(path) = present.first() {
        return Err(refusal(
            "moved repository folder",
            &format!("the original folder still exists at {}", path.display()),
            "Move the repository folder to the new location first, then retry; a copy is not a move. To keep both locations, register the copy as a new project with se init.",
        ));
    }
    for root in &from_roots {
        let path = root
            .path
            .to_local()
            .map_err(|e| scope::unreadable("registered root", &e.to_string()))?;
        if path == target {
            return Err(refusal(
                "move target",
                "the new folder is one of the registered roots",
                "Pass the folder the repository was moved to, a different path from the registered roots.",
            ));
        }
    }
    let to_path = NativePath::from_local(target)?;
    let canonical_key = serde_json::to_vec(&to_path)
        .map_err(|e| scope::unreadable("move target identity", &e.to_string()))?;
    let to = se_store::Root {
        path: to_path,
        canonical_key,
    };
    let identity = LeaseIdentity {
        store: Some(reader.info().map_err(|e| store_error(&e))?.id),
        generation: caller.admission.generation,
        mode: LeaseMode::DirectClient,
    };
    let lease =
        match DirectLease::acquire(
            Files::open(&cx.home).map_err(|e| store_error(&e))?,
            &cx.home.join("runtime.lock"),
            identity,
        )
        .map_err(|e| store_error(&e))?
        {
            Some(lease) => lease,
            None => return Err(SeError::new(se_types::Detail::SourceUnreadable(
                details::SourceUnreadable {
                    subject: "move writer lease".into(),
                    reason: "the state home's runtime is holding the writer lease".into(),
                    next_step:
                        "Stop the runtime with se down, then retry the move from the new folder."
                            .into(),
                },
            ))),
        };
    let store_options = StoreOptions {
        state_directory: cx.home.clone(),
        busy_timeout: Duration::from_millis(250),
    };
    let mut store = scope::require_present(
        SqliteFactory::open_direct(&store_options, &lease).map_err(|e| store_error(&e))?,
        "initialized direct store",
        "Restore access to the initialized store in this same data home, then retry the move with the original --key.",
    )?;
    let kernel = Kernel::new(execute::facts()?)?.with_configuration(cx.config.value.clone())?;
    let mut snapshot = store
        .snapshot(se_core::admission::read_scope(&caller.admission))
        .map_err(|e| store_error(&e))?;
    let (batch, then) = project::move_root(
        &kernel,
        &input,
        &record,
        from_roots,
        to,
        &project::MoveIdentity {
            head: Some(head),
            branch,
        },
        &mut Cx {
            read: &mut snapshot,
            admission: &caller.admission,
        },
    )?;
    snapshot.close().map_err(|e| store_error(&e))?;
    let key = batch.request.as_ref().map(|request| request.key.clone());
    let natural_events: Vec<EventId> = key.as_ref().map(|_| Vec::new()).unwrap_or_else(|| {
        batch
            .events
            .iter()
            .map(|e| e.header.event.clone())
            .collect()
    });
    let receipt = store
        .append(batch, &lease)
        .map_err(|error| write_error(&error, "project.move", key.as_ref(), &natural_events))?;
    let mut readback = store
        .snapshot(se_core::admission::read_scope(&caller.admission))
        .map_err(|e| store_error(&e))?;
    let output: MoveOutput = project::move_committed(
        then,
        receipt,
        &mut Cx {
            read: &mut readback,
            admission: &caller.admission,
        },
    )?;
    let closed = readback.close().map_err(|e| store_error(&e));
    closed?;
    Ok(AnyOutput::from(output))
}
fn resolve_target(cx: &Bootstrap, root: &str) -> Result<PathBuf> {
    let requested = PathBuf::from(root);
    let absolute = if requested.is_absolute() {
        requested
    } else {
        cx.cwd.join(requested)
    };
    let target = se_proc::canonicalize_path(&absolute).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            refusal(
                "new repository folder",
                &format!("the folder {} does not exist", absolute.display()),
                "Move the repository into that folder, or pass the folder it was moved to, then retry.",
            )
        } else {
            scope::unreadable("new repository folder", &e.to_string())
        }
    })?;
    if !target.is_dir() {
        return Err(refusal(
            "new repository folder",
            "the selected path is not a directory",
            "Pass the repository folder itself, not a file inside it.",
        ));
    }
    Ok(target)
}
fn refusal(subject: &str, reason: &str, next_step: &str) -> SeError {
    SeError::new(se_types::Detail::RepoInvalid(details::RepoInvalid {
        subject: subject.into(),
        reason: reason.into(),
        next_step: next_step.into(),
    }))
}
