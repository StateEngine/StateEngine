//! Bounded discovery of named user-history leaves. Caches, credentials,
//! process records and provider account directories are never traversed.
use super::node::NodeKind;
use super::source::SourceFile;
use crate::client::lease::Deadline;
use se_core::scope;
use se_store::ImportFamily;
use se_types::{HumanId, ProjectId, Read, Result};
use std::path::{Path, PathBuf};

pub(super) struct Plan {
    pub root: PathBuf,
    pub registry: PathBuf,
    pub source: se_store::SourceEvidence,
    pub projects: Vec<Project>,
    pub source_owner: HumanId,
}
pub(super) struct Project {
    pub id: ProjectId,
    pub tombstone: bool,
}
#[derive(Clone)]
pub(super) struct File {
    pub path: PathBuf,
    pub family: ImportFamily,
    pub kind: NodeKind,
    pub observation: Option<Read<()>>,
    pub anchor: Option<se_store::SourceEvidence>,
}
fn io(subject: &str, error: impl std::fmt::Display) -> se_types::SeError {
    scope::unreadable(subject, &error.to_string())
}
fn named(path: PathBuf, family: ImportFamily, kind: NodeKind) -> File {
    File {
        path,
        family,
        kind,
        observation: None,
        anchor: None,
    }
}
pub(super) fn inspect(
    path: &Path,
    owner: &HumanId,
    selected: Option<&HumanId>,
    mappings: &std::collections::BTreeMap<HumanId, HumanId>,
    deadline: &Deadline,
) -> Result<Plan> {
    if !path.is_absolute() {
        return Err(se_types::SeError::invalid(
            "Node source",
            "an absolute retained source-copy path",
        ));
    }
    let state = if path.file_name().is_some_and(|n| n == ".stateengine") {
        path.to_path_buf()
    } else {
        path.join(".stateengine")
    };
    let root = state
        .parent()
        .ok_or_else(|| io("Node source", "state directory has no parent"))?
        .to_path_buf();
    let registry = state.join("projects.jsonl");
    let mut source = match SourceFile::open(registry.clone(), None, deadline)? {
        Read::Present { value } => value,
        Read::Absent { checked } => {
            return Err(io(
                "Node project registration source",
                format!(
                    "{checked}; preserve the original projects.jsonl registry in the source copy; repository roots cannot be inferred from folder labels"
                ),
            ));
        }
        Read::Unreadable { source, reason, .. } => return Err(io(&source, reason)),
        Read::Unknown { what } => return Err(io("Node project registration source", what)),
    };
    let mut registrations =
        std::collections::BTreeMap::<ProjectId, (u64, serde_json::Value, bool)>::new();
    while let Some(row) = source.next(deadline)? {
        let Some(value) = row.value else {
            // The registry file pass records this final unreadable range. Roots
            // cannot be inferred from it; earlier complete registrations remain known.
            if source.next(deadline)?.is_none() {
                break;
            }
            return Err(io(
                "Node project registry",
                row.code
                    .unwrap_or("undecodable registry row before later registrations"),
            ));
        };
        let text = value
            .get("project_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| io("Node project registry", "row has no exact project_id"))?;
        let id = ProjectId::from_legacy(text)?;
        let revision = value
            .get("revision")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| io("Node project registry", "row has no revision"))?;
        let previous = registrations.get(&id);
        if revision != previous.map(|p| p.0 + 1).unwrap_or(1) {
            return Err(io(
                "Node project registry",
                "out-of-sequence source registration; no invalid rows are discarded",
            ));
        }
        match value.get("record_type").and_then(serde_json::Value::as_str) {
            Some("project-registration") => {
                let source_owner = value
                    .get("owner_human_id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| io("Node source owner", "registration lacks owner_human_id"))?;
                let selected = selected.unwrap_or(owner);
                if source_owner != selected.as_str() {
                    return Err(io(
                        "Node source owner correspondence",
                        format!(
                            "source project {id} names owner {source_owner}, importing owner {owner}; pass --source-owner {source_owner} explicitly and preserve a copy containing only that owner's projects"
                        ),
                    ));
                }
                registrations.insert(id, (revision, value, false));
            }
            Some("project-decommission") => {
                let (_, prior, removed) = previous.ok_or_else(|| {
                    io("Node project registry", "decommission has no registration")
                })?;
                if *removed {
                    return Err(io(
                        "Node project registry",
                        "repeated decommission is not a new registration",
                    ));
                }
                registrations.insert(id, (revision, prior.clone(), true));
            }
            _ => {
                return Err(io(
                    "Node project registry",
                    "unsupported registration record type",
                ));
            }
        }
        if registrations.len() > 512 {
            return Err(io(
                "Node project registry",
                "discovery bound is 512 projects",
            ));
        }
    }
    source.verify(deadline)?;
    let source_owner = super::ownership::check(
        &state,
        owner,
        selected,
        mappings,
        registrations.values().map(|(_, value, _)| value),
        deadline,
    )?;
    let mut projects = Vec::new();
    for (id, (_, value, tombstone)) in registrations {
        if value
            .get("repo_root")
            .and_then(serde_json::Value::as_str)
            .is_none()
        {
            return Err(io(
                "Node project registry",
                "registration lacks its source root",
            ));
        }
        projects.push(Project { id, tombstone });
    }
    Ok(Plan {
        root,
        registry,
        source: source.evidence(),
        projects,
        source_owner,
    })
}
/// Enumerate one project's source paths at a time; history bytes are streamed
/// later through native pins and never accumulated across the source registry.
pub(super) fn sources(root: &Path, id: &ProjectId, deadline: &Deadline) -> Result<Vec<File>> {
    let state = root.join(".stateengine");
    let text = id.as_str();
    let slug = text
        .to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    let slug = slug.chars().take(40).collect::<String>();
    use sha2::{Digest, Sha256};
    let suffix = se_types::hex_lower(&Sha256::digest(text.as_bytes()));
    let floor = state.join(format!("{slug}-{}", &suffix[..16]));
    let backend_issue = backend(&state, text, &floor, deadline).err();
    deadline.remaining()?;
    if let Some(error) = backend_issue {
        let mut issue = named(floor, ImportFamily::Projects, NodeKind::Ledger);
        issue.observation = Some(Read::Unreadable {
            source: "Node project backend authority".into(),
            reason: error.to_string(),
            error: Some(Box::new(error.into_body())),
        });
        return Ok(vec![issue]);
    }
    let mut files = vec![
        named(
            state.join("humans.jsonl"),
            ImportFamily::Owners,
            NodeKind::Owners,
        ),
        named(
            floor.join("events.jsonl"),
            ImportFamily::Agents,
            NodeKind::Ledger,
        ),
        named(
            floor.join("seats/messages.jsonl"),
            ImportFamily::Messages,
            NodeKind::Messages,
        ),
        named(
            floor.join("working-state.json"),
            ImportFamily::WorkingState,
            NodeKind::WorkingState,
        ),
    ];
    files.insert(
        2,
        named(
            root.join("seats-config.json"),
            ImportFamily::Profiles,
            NodeKind::Profiles,
        ),
    );
    discover(
        &mut files,
        &floor.join("working-state"),
        "json",
        ImportFamily::WorkingState,
        NodeKind::WorkingState,
        deadline,
    )?;
    // The exact project spelling is a source ID, never a provider model ID.
    discover(
        &mut files,
        &state.join(text).join("RawLogs"),
        "jsonl",
        ImportFamily::Turns,
        NodeKind::Turns,
        deadline,
    )?;
    Ok(files)
}
fn discover(
    files: &mut Vec<File>,
    path: &Path,
    extension: &str,
    family: ImportFamily,
    kind: NodeKind,
    deadline: &Deadline,
) -> Result<()> {
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        let mut observation = named(path.to_path_buf(), family, kind);
        observation.observation = Some(Read::Unreadable {
            source: "Node history directory".into(),
            reason: "a retained history directory is a symlink; no external source was followed"
                .into(),
            error: None,
        });
        files.push(observation);
        return Ok(());
    }
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) => {
            let mut observation = named(path.to_path_buf(), family, kind);
            observation.observation = Some(if error.kind() == std::io::ErrorKind::NotFound {
                Read::Absent {
                    checked: "named Node history directory is absent".into(),
                }
            } else {
                Read::Unreadable {
                    source: "Node history directory".into(),
                    reason: error.to_string(),
                    error: None,
                }
            });
            files.push(observation);
            return Ok(());
        }
    };
    let mut result = Vec::new();
    let mut issue = None;
    for entry in entries {
        deadline.remaining()?;
        let entry = match entry {
            Ok(value) => value,
            Err(error) => {
                issue = Some(error.to_string());
                break;
            }
        };
        let ty = match entry.file_type() {
            Ok(value) => value,
            Err(error) => {
                issue = Some(error.to_string());
                break;
            }
        };
        if !ty.is_file() {
            issue=Some("only regular retained history files are supported; a symlink or nested entry requires a separately preserved source copy".into());
            continue;
        }
        if entry.path().extension().is_some_and(|ext| ext == extension) {
            if result.len() >= 4096 {
                issue = Some("history directory exceeds its 4096-file discovery bound".into());
                break;
            }
            result.push(entry.path());
        }
    }
    result.sort();
    if result.is_empty() || issue.is_some() {
        let mut observation = named(path.to_path_buf(), family, kind);
        observation.observation = Some(match issue {
            Some(reason) => Read::Unreadable {
                source: "Node history directory".into(),
                reason,
                error: None,
            },
            None => Read::Present { value: () },
        });
        files.push(observation);
    }
    files.extend(result.into_iter().map(|path| named(path, family, kind)));
    Ok(())
}
fn backend(state: &Path, project: &str, floor: &Path, deadline: &Deadline) -> Result<()> {
    let directory = floor
        .file_name()
        .ok_or_else(|| io("Node source directory", "missing floor directory"))?;
    let path = state
        .join("runtime")
        .join(directory)
        .join("floor-storage/storage.json");
    match SourceFile::open(path, None, deadline)? {
        Read::Absent { .. } => Ok(()),
        Read::Present { mut value } => {
            let row = value.next(deadline)?.ok_or_else(|| {
                io(
                    "Node backend authority",
                    "empty control file is not absence",
                )
            })?;
            let row = row
                .value
                .ok_or_else(|| io("Node backend authority", "unreadable control document"))?;
            if row.get("schema").and_then(serde_json::Value::as_str) != Some("floor-storage/v1")
                || row.get("project_id").and_then(serde_json::Value::as_str) != Some(project)
                || row.get("mode").and_then(serde_json::Value::as_str) != Some("files")
                || row.get("transition").is_some_and(|v| !v.is_null())
            {
                return Err(io(
                    "Node backend authority",
                    "the retained file floor is not proven authoritative; preserve an authenticated immutable user-record export instead of importing a database/transition window",
                ));
            }
            value.verify(deadline)
        }
        Read::Unreadable { source, reason, .. } => Err(io(&source, reason)),
        Read::Unknown { what } => Err(io("Node backend authority", what)),
    }
}
