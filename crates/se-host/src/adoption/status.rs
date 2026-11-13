//! Project-scoped latest hook outcomes, including refusals before agent binding.
//! These are observations, never evidence that a caller belongs to an agent.
use super::*;
use crate::state_files::{Acquisition, AcquisitionRetry};
use se_core::ops::{AgentCommand, PendingFact, StatusOutput};
const MAX_BYTES: usize = 64 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attempt {
    schema: u16,
    project: ProjectId,
    action: Action,
    observed_at: String,
    refusal: Option<String>,
    #[serde(default)]
    discovery: Option<[u8; 32]>,
    #[serde(default)]
    installation: Option<String>,
}
fn path(home: &Path, project: &ProjectId, action: Action, kind: Kind) -> std::path::PathBuf {
    home.join(if kind == Kind::Claude {
        "adoption-status"
    } else {
        "codex-adoption-status"
    })
    .join(format!(
        "{:x}-{}.json",
        Sha256::digest(project.as_str()),
        action.name()
    ))
}

/// One bounded record per registered project/event; successful authenticated
/// replies clear only that event's earlier refusal, not another event's failure.
pub fn record(
    home: &Path,
    project: &ProjectId,
    action: Action,
    error: Option<&SeError>,
) -> Result<()> {
    record_for(home, Kind::Claude, project, action, error)
}
pub fn record_for(
    home: &Path,
    kind: Kind,
    project: &ProjectId,
    action: Action,
    error: Option<&SeError>,
) -> Result<()> {
    let files = se_proc::NativeStateFiles::open(home).map_err(native)?;
    let mut retry =
        AcquisitionRetry::new(std::time::Instant::now() + std::time::Duration::from_secs(1));
    let directory = home.join(if kind == Kind::Claude {
        "adoption-status"
    } else {
        "codex-adoption-status"
    });
    let target = path(home, project, action, kind);
    if kind == Kind::Claude && error.is_none() && files.readback(&target).map_err(native)?.is_none()
    {
        return Ok(());
    }
    files.prepare_directory(&directory).map_err(native)?;
    let previous = acquire(&target, &mut retry)?;
    let registration = if kind == Kind::Codex {
        read_for(home, kind)?
    } else {
        None
    };
    let discovery = registration.as_ref().and_then(|r| r.discovery);
    let installation = registration.as_ref().and_then(|r| r.installation.clone());
    if kind == Kind::Codex
        && error.is_none()
        && read_attempt(&files, home, project, action, kind)?.is_some_and(|a| {
            a.refusal.is_none() && a.discovery == discovery && a.installation == installation
        })
    {
        return Ok(());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| invalid(&e.to_string()))?;
    let attempt = Attempt {
        schema: 1,
        discovery,
        installation,
        project: project.clone(),
        action,
        observed_at: se_core::ops::receipt::timestamp(
            i64::try_from(now.as_micros())
                .map_err(|_| invalid("representable observation clock"))?,
        )?,
        refusal: error.map(|e| format!("[{}]: {}", e.code().as_str(), e.body.message())),
    };
    let bytes =
        serde_json::to_vec(&attempt).map_err(|_| invalid("serializable hook observation"))?;
    if bytes.len() > MAX_BYTES {
        return Err(invalid("hook observation within 64 KiB"));
    }
    if let Some(mut previous) = previous {
        let hash = previous.sha256().map_err(native)?;
        return previous.replace(hash, &bytes).map_err(native);
    }
    // Successful hooks need no file until an earlier refusal exists.
    if error.is_none() && kind == Kind::Claude {
        return Ok(());
    }
    let mut staged = files.create_staging(&directory).map_err(native)?;
    staged.file.write_all(&bytes).map_err(io)?;
    staged.file.sync_all().map_err(io)?;
    drop(staged.file);
    match files.publish_no_replace(&staged.path, &target) {
        Ok(()) => Ok(()),
        Err(error) if error.code == se_proc::StateFileErrorCode::AlreadyExists => {
            if let Some(file) = acquire(&staged.path, &mut retry)? {
                file.remove(digest(&bytes)).map_err(native)?;
            }
            // A concurrent completion was retained. Retry with a fresh pin;
            // the final successful replacement is the last recorded attempt.
            let mut previous = acquire(&target, &mut retry)?
                .ok_or_else(|| invalid("the concurrent hook observation"))?;
            let hash = previous.sha256().map_err(native)?;
            previous.replace(hash, &bytes).map_err(native)
        }
        Err(error) => Err(native(error)),
    }
}

// Native file pins serialize edits in their parent directory. Overlapping
// lifecycle events must wait for that acquisition, not lose a refusal merely
// because another event is clearing its own diagnostic. Mutations never retry.
fn acquire(path: &Path, retry: &mut AcquisitionRetry) -> Result<Option<se_proc::OwnedFile>> {
    loop {
        match retry
            .acquire(|| se_proc::OwnedFile::open(path))
            .map_err(|error| error.into_public(native))?
        {
            Acquisition::Ready(file) => return Ok(file),
            Acquisition::Wait(wait) => std::thread::sleep(wait),
        }
    }
}

fn read_attempt(
    files: &se_proc::NativeStateFiles,
    home: &Path,
    project: &ProjectId,
    action: Action,
    kind: Kind,
) -> Result<Option<Attempt>> {
    let Some(file) = files
        .readback(&path(home, project, action, kind))
        .map_err(native)?
    else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    let attempt: Attempt = crate::client::wire::decode_json(&bytes, MAX_BYTES)?;
    if attempt.schema != 1 || &attempt.project != project || attempt.action != action {
        return Err(invalid("the exact project and hook observation"));
    }
    Ok(Some(attempt))
}

/// Shared by offline CLI and hosted CLI/MCP status, with no new status schema.
pub fn observe(home: &Path, output: &mut StatusOutput) {
    for kind in Kind::ALL {
        observe_for(home, output, kind);
    }
}
fn observe_for(home: &Path, output: &mut StatusOutput, kind: Kind) {
    let name = if kind == Kind::Claude {
        "Claude"
    } else {
        "Codex"
    };
    let prefix = format!("{name} adoption ");
    let se_types::Read::Present { value: selected } = &output.project else {
        return;
    };
    if output.removal.is_some() {
        return;
    }
    let project = selected.id.clone();
    output
        .pending
        .retain(|fact| !fact.what.starts_with(&prefix));
    let (files, registration) = match (|| {
        let Some(registration) = read_for(home, kind)? else {
            return Ok(None);
        };
        if !registration.projects.iter().any(|p| p.project == project) {
            return Ok(None);
        }
        se_proc::NativeStateFiles::open(home)
            .map(|files| Some((files, registration)))
            .map_err(native)
    })() {
        Ok(Some(files)) => files,
        Ok(None) => return,
        Err(error) => {
            output.pending.push(PendingFact { what: format!("{name} adoption registration"), since: None,
                detail: format!("Adoption registration is unreadable: {error}. Restore access to this data home's protected registration before repeating adoption setup.") });
            return;
        }
    };
    if kind == Kind::Codex
        && let Some(fact) = codex_pending(home, &registration, &project)
    {
        output.pending.push(fact);
    }
    let remedy = || {
        let command = AgentCommand::home_argument(home).and_then(|home| {
            AgentCommand::from_argv(vec![
                "se".into(),
                "--home".into(),
                home.into(),
                "init".into(),
                "--repo".into(),
                selected.root.clone(),
                "--adopt".into(),
                "--provider".into(),
                kind.name().into(),
            ])
        });
        match command {
            Some(command) => format!("Restore access to the named source, run `{}` in your own terminal, then restart {} in this folder. Provider work was allowed to continue; capture and mail are unconfirmed.", command.command, kind.label()),
            None => "Restore access to the named source, then repeat the original adoption setup in your own terminal and restart the provider in this folder. Capture and mail are unconfirmed.".into(),
        }
    };
    for action in Action::ALL {
        match read_attempt(&files, home, &project, action, kind) {
            Ok(Some(Attempt {
                observed_at,
                refusal: Some(reason),
                ..
            })) => output.pending.push(PendingFact {
                what: format!("{name} adoption {}", action.name()),
                since: Some(observed_at.clone()),
                detail: format!(
                    "Latest {name} hook attempt at {observed_at} was refused {reason}. {remedy}",
                    name = action.name(),
                    remedy = remedy()
                ),
            }),
            Ok(_) => (),
            Err(error) => output.pending.push(PendingFact {
                what: format!("{name} adoption {} observation", action.name()),
                since: None,
                detail: format!("Adoption outcome is unreadable: {error}. {}", remedy()),
            }),
        }
    }
}

/// File installation is never a hook-execution witness.
pub fn witnessed(home: &Path, kind: Kind, project: &ProjectId) -> Result<bool> {
    let Some(registration) = read_for(home, kind)? else {
        return Ok(false);
    };
    if registration.discovery.is_none()
        || !registration
            .projects
            .iter()
            .any(|p| &p.project == project && p.discovery == registration.discovery)
        || Some(discovery_stamp(&registration)?) != registration.discovery
    {
        return Ok(false);
    }
    let files = se_proc::NativeStateFiles::open(home).map_err(native)?;
    for action in Action::ALL {
        if let Some(attempt) = read_attempt(&files, home, project, action, kind)?
            && attempt.refusal.is_none()
            && attempt.discovery == registration.discovery
            && attempt.installation == registration.installation
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn codex_pending(
    home: &Path,
    registration: &Registration,
    project: &ProjectId,
) -> Option<PendingFact> {
    let observed = witnessed(home, Kind::Codex, project);
    if matches!(observed, Ok(true)) {
        return None;
    }
    let detail = match observed {
                Err(error) => format!("Hook execution observation is unavailable: {error}. Capture and mail are unconfirmed."),
                _ => match discovery_stamp(registration) {
                    Err(error) => format!("Provider configuration or executable could not be observed: {error}. Capture and mail are unconfirmed."),
                    Ok(stamp) if Some(stamp) != registration.discovery || !registration.projects.iter().any(|p|&p.project == project && p.discovery == Some(stamp)) => format!("Codex has not discovered the current integration configuration or executable: {}. Repeat adoption setup; capture and mail are unconfirmed.", registration.discovery_refusal.as_deref().unwrap_or("provider discovery must be repeated")),
                    Ok(_) => "Codex discovered and trusted the installed hooks; no authenticated hook run has been witnessed yet. Start Codex directly in this project.".into(),
                }
            };
    Some(PendingFact {
        what: "Codex adoption hook execution".into(),
        since: None,
        detail,
    })
}
