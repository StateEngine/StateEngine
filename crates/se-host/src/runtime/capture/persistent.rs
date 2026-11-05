//! Owner-protected recovery metadata for a previously trusted bind. A hook
//! never creates this file or replaces its native path/incarnation.
use super::*;
use se_core::store_error::store_error;
use se_store::RuntimeLease;
use std::{
    io::{Read as _, Write as _},
    path::Path,
};
const DIRECTORY: &str = "transcripts";
const MAX_BYTES: usize = 256 * 1024;
#[derive(serde::Serialize, serde::Deserialize)]
enum Schema {
    #[serde(rename = "se.transcript-binding/v1")]
    V1,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: Schema,
    project: se_types::ProjectId,
    agent: se_types::AgentId,
    session: se_types::SessionId,
    conversation: se_types::ProviderSessionId,
    source: se_store::RecordId,
    path: se_types::NativePath,
    file_identity: se_types::Sha256,
}
impl Record {
    fn from_source(source: &BoundTranscript) -> Self {
        let binding = &source.binding;
        Self {
            schema: Schema::V1,
            project: binding.identity.project.clone(),
            agent: binding.identity.agent.clone(),
            session: binding.identity.session.clone(),
            conversation: binding.conversation.clone(),
            source: source.source,
            path: binding.path.clone(),
            file_identity: binding.file_identity,
        }
    }
    fn open(self) -> Result<BoundTranscript> {
        let path = self.path.to_local()?;
        let pin=se_proc::NativeSourcePin::open(&path).map_err(native_error)?
            .ok_or_else(||se_core::scope::unreadable("trusted capture binding","the previously adopted native file is absent; preserve its old committed cursor"))?;
        if se_types::Sha256::from_bytes(pin.identity()) != self.file_identity {
            return Err(se_core::scope::unreadable(
                "trusted capture binding",
                "the previously adopted file incarnation changed; an explicit trusted rebind is required",
            ));
        }
        Ok(BoundTranscript {
            binding: crate::TranscriptPin {
                identity: crate::SessionIdentity {
                    project: self.project,
                    agent: self.agent,
                    session: self.session,
                },
                conversation: self.conversation,
                path: self.path,
                file_identity: self.file_identity,
            },
            source: self.source,
            pin,
            queue: Default::default(),
            tools: Default::default(),
        })
    }
}
fn directory(lease: &HostLease) -> Result<std::path::PathBuf> {
    let path = lease.files.0.root().join(DIRECTORY);
    lease
        .files()
        .prepare_directory(&path)
        .map_err(|error| store_error(&error))?;
    Ok(path)
}
fn read(lease: &HostLease, path: &Path) -> Result<Option<Vec<u8>>> {
    let file = match lease
        .files()
        .readback(path)
        .map_err(|error| store_error(&error))?
    {
        Read::Present { value } => value,
        Read::Absent { .. } => return Ok(None),
        other => {
            return se_core::scope::require_present(other, "protected transcript binding", "Restore access to the original protected transcript binding in this data home; preserve the trusted file identity and committed capture cursor.")
                .map(|_: std::fs::File| None);
        }
    };
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            se_core::scope::unreadable("protected transcript binding", &error.to_string())
                .with_cause(error)
        })?;
    if bytes.len() > MAX_BYTES {
        return Err(SeError::too_large(
            "protected transcript binding",
            MAX_BYTES,
            bytes.len(),
        ));
    }
    Ok(Some(bytes))
}
pub(super) fn publish(lease: &HostLease, source: &BoundTranscript) -> Result<()> {
    let directory = directory(lease)?;
    let path = directory.join(format!("{}.json", source.binding.identity.session));
    let bytes = serde_json::to_vec(&Record::from_source(source)).map_err(|error| {
        se_core::scope::unreadable("transcript binding codec", &error.to_string())
    })?;
    if bytes.len() > MAX_BYTES {
        return Err(SeError::too_large(
            "protected transcript binding",
            MAX_BYTES,
            bytes.len(),
        ));
    }
    if let Some(prior) = read(lease, &path)? {
        return same(&prior, &bytes);
    }
    let staging = lease
        .files()
        .create_staging(&directory)
        .map_err(|error| store_error(&error))?;
    let mut file = staging.file;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            se_core::scope::unreadable("publish transcript binding", &error.to_string())
                .with_cause(error)
        })?;
    drop(file);
    match lease.files().publish_no_replace(&staging.path, &path) {
        Ok(()) => (),
        Err(error) if error.code == se_store::StoreErrorCode::AlreadyExists => {
            let winner = read(lease, &path)?.ok_or_else(|| {
                se_core::scope::unreadable(
                    "transcript binding race",
                    "published winner disappeared",
                )
            })?;
            let match_result = same(&winner, &bytes);
            let expected = sha2::Sha256::digest(&bytes).into();
            lease
                .files()
                .remove_owned(&staging.path, expected)
                .map_err(|error| store_error(&error))?;
            match_result?;
        }
        Err(error) => return Err(store_error(&error)),
    }
    let observed = read(lease, &path)?.ok_or_else(|| {
        se_core::scope::unreadable(
            "transcript binding publication",
            "protected readback is absent",
        )
    })?;
    same(&observed, &bytes)
}
fn same(a: &[u8], b: &[u8]) -> Result<()> {
    if a != b {
        return Err(se_core::scope::unreadable(
            "trusted transcript rebind",
            "the exact original protected binding must remain unchanged; a hook cannot rotate it",
        ));
    }
    Ok(())
}
pub(super) fn restore(
    context: &ExecutionContext,
    lease: &HostLease,
    bindings: &TranscriptBindings,
    deadline: &Deadline,
) -> Result<CaptureRestoreReport> {
    let mut report = CaptureRestoreReport::default();
    let paths = directory(lease).and_then(|directory| {
        lease
            .files()
            .list_owned(&directory, bindings.maximum)
            .map_err(|error| store_error(&error))
    });
    let paths = match paths {
        Ok(paths) => paths,
        Err(error) => {
            bindings.quarantine(None, error.body.clone())?;
            report.unavailable.push(CaptureUnavailable {
                session: None,
                error: error.body,
            });
            return Ok(report);
        }
    };
    for path in paths {
        deadline.remaining()?;
        let session: Option<SessionId> = path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .and_then(|v| v.strip_suffix(".json"))
            .and_then(|v| v.parse().ok());
        let result = (|| -> Result<()> {
            let session = session.as_ref().ok_or_else(|| {
                SeError::invalid(
                    "capture recovery metadata",
                    "an exact session.json file in the protected binding directory",
                )
            })?;
            restore_session(context, lease, bindings, session, deadline)
        })();
        match result {
            Ok(()) => report.restored += 1,
            Err(error) => {
                bindings.quarantine(session.clone(), error.body.clone())?;
                report.unavailable.push(CaptureUnavailable {
                    session,
                    error: error.body,
                });
            }
        }
    }
    Ok(report)
}

pub(super) fn restore_session(
    context: &ExecutionContext,
    lease: &HostLease,
    bindings: &TranscriptBindings,
    session: &SessionId,
    deadline: &Deadline,
) -> Result<()> {
    deadline.remaining()?;
    let path = directory(lease)?.join(format!("{session}.json"));
    let bytes = read(lease, &path)?.ok_or_else(|| {
        se_core::scope::unreadable(
            "capture restoration",
            "the original protected binding is absent",
        )
    })?;
    let record: Record = serde_json::from_slice(&bytes).map_err(|error| {
        se_core::scope::unreadable("protected transcript binding", &error.to_string())
    })?;
    if &record.session != session {
        return Err(SeError::invalid(
            "transcript binding filename",
            "the exact protected session identifier",
        ));
    }
    let mut source = record.open()?;
    source::validate(context, &mut source, deadline)?;
    bindings.insert(source, None)
}
