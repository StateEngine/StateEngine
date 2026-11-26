//! The private per-login custody record of a shared Codex server: written
//! whole at every launch checkpoint, read back strictly, removed once retired.
use super::*;
use std::io::Write;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub version: u16,
    pub login: NativePath,
    pub checkpoint: Checkpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_sandbox: Option<String>,
}

impl LaunchCoordinator {
    pub(super) fn codex_checkpoint(&self, kind: CheckpointKind) -> Result<Checkpoint> {
        let (lifecycle, publication) = match &kind {
            CheckpointKind::Reservation(v) => {
                (v.lifecycle.clone(), RootPublication::NoChildCreated)
            }
            CheckpointKind::Scope(v) => (
                v.reservation.lifecycle.clone(),
                RootPublication::Unpublished,
            ),
            CheckpointKind::Root(v) => (
                v.scope.reservation.lifecycle.clone(),
                RootPublication::Identified,
            ),
            CheckpointKind::Process(v) => (v.lifecycle.clone(), RootPublication::Identified),
            CheckpointKind::Exit { witness, .. } => (
                witness.lifecycle.clone(),
                match witness.root {
                    se_proc::RootWitness::NoChildCreated => RootPublication::NoChildCreated,
                    se_proc::RootWitness::UnpublishedScope
                    | se_proc::RootWitness::PinnedUnpublished { .. } => {
                        RootPublication::Unpublished
                    }
                    se_proc::RootWitness::Identified { .. } => RootPublication::Identified,
                },
            ),
            _ => {
                return Err(error(
                    "Codex shared server checkpoint",
                    "a native reservation, scope, root, process or exit is required",
                ));
            }
        };
        Ok(Checkpoint {
            format_version: 1,
            lifecycle,
            // The server belongs to the person whose login it serves.
            principal: CheckpointPrincipal::Human(self.human.clone()),
            session: None,
            root_identity: publication,
            checkpoint: kind,
        })
    }

    pub(super) async fn read_codex_record(
        &self,
        path: &Path,
        deadline: &Deadline,
    ) -> Result<Option<Record>> {
        let path = path.to_owned();
        let directory = self.options.home.join("codex-servers");
        self.store
            .pool
            .run_owned(deadline, move || {
                let bytes = match std::fs::read(&path) {
                    Ok(bytes) => bytes,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                    Err(e) => {
                        return Err(refusal(&path, &format!("the record is unreadable: {e}")));
                    }
                };
                if bytes.len() > RECORD_BYTES {
                    return Err(refusal(&path, "the record exceeds its size bound"));
                }
                let record: Record = serde_json::from_slice(&bytes)
                    .map_err(|e| refusal(&path, &format!("the record is unreadable: {e}")))?;
                se_proc::encode_checkpoint(&record.checkpoint).map_err(|e| {
                    refusal(&path, &format!("the record's custody is invalid: {e:?}"))
                })?;
                // A record is checked against its own login, never against the
                // login this process's environment happens to select.
                let login = record.login.to_local().ok();
                if record.version != RECORD_VERSION
                    || login
                        .as_deref()
                        .map(|login| record_path(&directory, login))
                        .as_deref()
                        != Some(path.as_path())
                {
                    return Err(refusal(
                        &path,
                        "the record's version or login does not match its file",
                    ));
                }
                Ok(Some(record))
            })
            .await
    }

    /// Write the record whole and in place of the previous one.
    pub(super) async fn save_codex_record(
        &self,
        path: &Path,
        record: &Record,
        deadline: &Deadline,
    ) -> Result<()> {
        let bytes = serde_json::to_vec(record).map_err(|e| error("Codex server record", e))?;
        let path = path.to_owned();
        self.store
            .pool
            .run_owned(deadline, move || {
                let directory = path
                    .parent()
                    .ok_or_else(|| error("Codex server record", "a parent directory"))?;
                let files = se_proc::NativeStateFiles::create(directory)
                    .map_err(|e| error("Codex server record directory", e))?;
                // An existing record is replaced against the exact bytes read
                // back here; a first record is published without replacing.
                if let Some(mut current) =
                    se_proc::OwnedFile::open(&path).map_err(|e| error("Codex server record", e))?
                {
                    let expected = current
                        .sha256()
                        .map_err(|e| error("Codex server record", e))?;
                    return current
                        .replace(expected, &bytes)
                        .map_err(|e| error("Codex server record", e));
                }
                let mut staging = files
                    .create_staging(directory)
                    .map_err(|e| error("Codex server record", e))?;
                // Publication flushes the staged data before moving its name.
                staging
                    .file
                    .write_all(&bytes)
                    .map_err(|e| error("Codex server record", e))?;
                drop(staging.file);
                files
                    .publish_no_replace(&staging.path, &path)
                    .map_err(|e| error("Codex server record", e))
            })
            .await
    }
}

pub(super) fn checkpoint_source(checkpoint: &Checkpoint) -> Result<CheckpointSource> {
    Ok(match &checkpoint.checkpoint {
        CheckpointKind::Reservation(v) => CheckpointSource::Reservation(v.clone()),
        CheckpointKind::Scope(v) => CheckpointSource::Scope(v.clone()),
        CheckpointKind::Root(v) => CheckpointSource::Root(v.clone()),
        CheckpointKind::Process(v) => CheckpointSource::Process(v.clone()),
        _ => return Err(error("Codex shared server", "an unretired checkpoint")),
    })
}

pub(super) fn remove_record(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(refusal(path, &format!("the record cannot be removed: {e}"))),
    }
}

pub(super) fn refusal(path: &Path, reason: &str) -> se_types::SeError {
    crate::codex_rpc::incompatible(
        &format!("{reason} ({})", path.display()),
        "Stop every Codex agent, make sure no StateEngine-started Codex app-server is still running, then remove that record and relaunch.",
    )
}

/// Where the record for one login lives: named by that login's digest.
pub(super) fn record_path(directory: &Path, login: &Path) -> PathBuf {
    let name = se_types::hex_lower(&Sha256::digest(login.as_os_str().as_encoded_bytes()));
    directory.join(format!("{name}.json"))
}

impl LaunchCoordinator {
    pub(super) fn codex_record(&self, login: &Path) -> PathBuf {
        record_path(&self.options.home.join("codex-servers"), login)
    }

    /// Every record under the state home, whichever login each names.
    pub(super) async fn codex_records(&self, deadline: &Deadline) -> Result<Vec<PathBuf>> {
        let directory = self.options.home.join("codex-servers");
        self.store
            .pool
            .run_owned(deadline, move || match std::fs::read_dir(&directory) {
                Ok(entries) => {
                    let mut paths = Vec::new();
                    for entry in entries {
                        let path = entry
                            .map_err(|e| {
                                refusal(&directory, &format!("the records cannot be listed: {e}"))
                            })?
                            .path();
                        if path.extension().is_some_and(|ext| ext == "json") {
                            paths.push(path);
                        }
                    }
                    paths.sort();
                    Ok(paths)
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
                Err(e) => Err(refusal(
                    &directory,
                    &format!("the records cannot be listed: {e}"),
                )),
            })
            .await
    }
}
