//! Disk-backed project catalogue and coalesced FIFO. Idle projects retain no
//! native handles or in-memory registration; one bounded directory page is read
//! when work arrives, never on an idle timer.
use se_atlas::model::{IndexSummary, RootRegistration};
use se_proc::{NativeStateFiles, OwnedFile};
use se_types::{ProjectId, Result, SeError};
use sha2::{Digest, Sha256};
use std::{
    fs::ReadDir,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_BYTES: usize = 131_072;
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublishedRoot {
    pub registration: RootRegistration,
    pub summary: Option<IndexSummary>,
}
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ticket {
    pub project: ProjectId,
    order: u64,
    token: [u8; 16],
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Project {
    project: ProjectId,
    roots: Vec<PublishedRoot>,
}
pub(crate) struct ProjectWork {
    directory: PathBuf,
    queue: PathBuf,
    lock: Mutex<()>,
}
pub(crate) struct Scan {
    files: NativeStateFiles,
    entries: ReadDir,
    best: Option<Ticket>,
}
impl ProjectWork {
    /// Installation does no IO. The first after-ready activity creates the
    /// protected derived catalogue beside (not inside) the Atlas cache home.
    pub(crate) fn new(directory: PathBuf) -> Self {
        Self {
            queue: directory.with_file_name("atlas-work"),
            directory,
            lock: Mutex::new(()),
        }
    }
    pub(crate) fn request(&self, project: &ProjectId) -> Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| failure("work queue mutex poisoned"))?;
        let files = existing_or_create(&self.queue)?;
        let before = read_ticket(&files, project)?;
        let order = match &before {
            Some((_, ticket)) => ticket.order,
            None => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(failure)?
                .as_nanos()
                .try_into()
                .map_err(failure)?,
        };
        let mut token = [0; 16];
        se_proc::fill_entropy(&mut token).map_err(failure)?;
        let bytes = serde_json::to_vec(&Ticket {
            project: project.clone(),
            order,
            token,
        })
        .map_err(failure)?;
        publish(
            &files,
            project,
            before.map(|(bytes, _)| bytes).as_deref(),
            &bytes,
        )
    }
    pub(crate) fn register(
        &self,
        project: &ProjectId,
        roots: Vec<RootRegistration>,
    ) -> Result<bool> {
        let mut changed = false;
        self.update(project, |entry| {
            changed = entry.roots.len() != roots.len()
                || roots
                    .iter()
                    .any(|new| !entry.roots.iter().any(|old| same(&old.registration, new)));
            if changed {
                let mut previous = std::mem::take(&mut entry.roots);
                entry.roots = roots
                    .into_iter()
                    .map(|registration| {
                        let summary = previous
                            .iter()
                            .position(|old| same(&old.registration, &registration))
                            .and_then(|index| previous.swap_remove(index).summary);
                        PublishedRoot {
                            registration,
                            summary,
                        }
                    })
                    .collect();
            }
            Ok(())
        })?;
        if changed {
            self.request(project)?;
        }
        Ok(changed)
    }
    pub(crate) fn roots(&self, project: &ProjectId) -> Result<Vec<PublishedRoot>> {
        Ok(self
            .read(project)?
            .map_or_else(Vec::new, |entry| entry.roots))
    }
    pub(crate) fn publish(
        &self,
        registration: &RootRegistration,
        summary: IndexSummary,
    ) -> Result<()> {
        self.update(&registration.project, |entry| {
            if let Some(root) = entry
                .roots
                .iter_mut()
                .find(|root| same(&root.registration, registration))
            {
                root.summary = Some(summary);
            }
            Ok(())
        })
    }
    pub(crate) fn complete(&self, ticket: &Ticket) -> Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| failure("work queue mutex poisoned"))?;
        let Some(files) = open(&self.queue)? else {
            return Ok(());
        };
        let Some((bytes, mut current)) = read_ticket(&files, &ticket.project)? else {
            return Ok(());
        };
        if &current != ticket {
            // Activity that arrived during this job needs another pass, behind
            // already queued projects. A continuously busy project cannot keep
            // its original FIFO position and starve every later request.
            current.order = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(failure)?
                .as_nanos()
                .try_into()
                .map_err(failure)?;
            let next = serde_json::to_vec(&current).map_err(failure)?;
            publish(&files, &ticket.project, Some(&bytes), &next)?;
            return Ok(());
        }
        let path = files
            .root()
            .join(format!("{}.json", ticket.project.as_str()));
        OwnedFile::open(&path)
            .map_err(failure)?
            .ok_or_else(|| failure("queued request disappeared"))?
            .remove(Sha256::digest(bytes).into())
            .map_err(failure)?;
        if files.readback(&path).map_err(failure)?.is_some() {
            return Err(failure("completed request still present"));
        }
        Ok(())
    }
    pub(crate) fn scan(&self) -> Result<Option<Scan>> {
        let Some(files) = open(&self.queue)? else {
            return Ok(None);
        };
        let entries = std::fs::read_dir(files.root()).map_err(failure)?;
        Ok(Some(Scan {
            files,
            entries,
            best: None,
        }))
    }
    fn read(&self, project: &ProjectId) -> Result<Option<Project>> {
        let Some(files) = open(&self.directory)? else {
            return Ok(None);
        };
        read(&files, project).map(|entry| entry.map(|(_, value)| value))
    }
    fn update(
        &self,
        project: &ProjectId,
        mutate: impl FnOnce(&mut Project) -> Result<()>,
    ) -> Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| failure("catalogue mutex poisoned"))?;
        let files = existing_or_create(&self.directory)?;
        let old = read(&files, project)?;
        let (before, mut entry) = old.map_or_else(
            || {
                (
                    None,
                    Project {
                        project: project.clone(),
                        roots: Vec::new(),
                    },
                )
            },
            |(bytes, entry)| (Some(bytes), entry),
        );
        mutate(&mut entry)?;
        let bytes = serde_json::to_vec(&entry).map_err(failure)?;
        if bytes.len() > MAX_BYTES {
            return Err(failure(
                "one project's catalogue exceeds 131072 bytes; retained its previous metadata",
            ));
        }
        if before.as_deref() == Some(bytes.as_slice()) {
            return Ok(());
        }
        publish(&files, project, before.as_deref(), &bytes)?;
        Ok(())
    }
}
impl Scan {
    /// Return None while a finite page is unfinished; Some(None) is an observed
    /// empty queue, not a swallowed IO/decoding failure.
    pub(crate) fn page(&mut self) -> Result<Option<Option<Ticket>>> {
        for _ in 0..32 {
            let Some(entry) = self.entries.next() else {
                return Ok(Some(self.best.take()));
            };
            let entry = entry.map_err(failure)?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| failure("non-UTF-8 catalogue entry"))?;
            // A crash may leave an unpublished native staging file. It conveys
            // no project/work claim and is preserved for owner diagnosis.
            if name.starts_with(".se-stage-") {
                continue;
            }
            let project = ProjectId::from_legacy(
                name.strip_suffix(".json")
                    .ok_or_else(|| failure("unknown catalogue entry preserved"))?,
            )?;
            let Some((_, work)) = read_ticket(&self.files, &project)? else {
                continue;
            };
            if self
                .best
                .as_ref()
                .is_none_or(|best| (work.order, &work.project) < (best.order, &best.project))
            {
                self.best = Some(work);
            }
        }
        Ok(None)
    }
}
fn same(a: &RootRegistration, b: &RootRegistration) -> bool {
    a.project == b.project
        && a.root == b.root
        && a.canonical_source_root == b.canonical_source_root
        && a.cache == b.cache
}
fn read(files: &NativeStateFiles, project: &ProjectId) -> Result<Option<(Vec<u8>, Project)>> {
    let path = files.root().join(format!("{}.json", project.as_str()));
    let Some(file) = files.readback(&path).map_err(failure)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(failure)?;
    if bytes.len() > MAX_BYTES {
        return Err(failure("oversized project catalogue"));
    }
    let value: Project = serde_json::from_slice(&bytes).map_err(failure)?;
    if &value.project != project
        || value.roots.iter().any(|root| {
            &root.registration.project != project
                || root.summary.as_ref().is_some_and(|summary| {
                    &summary.project != project || summary.root != root.registration.root
                })
        })
    {
        return Err(failure("project catalogue scope mismatch"));
    }
    Ok(Some((bytes, value)))
}
fn read_ticket(files: &NativeStateFiles, project: &ProjectId) -> Result<Option<(Vec<u8>, Ticket)>> {
    let Some(bytes) = read_bytes(files, project, 512)? else {
        return Ok(None);
    };
    let ticket: Ticket = serde_json::from_slice(&bytes).map_err(failure)?;
    if &ticket.project != project {
        return Err(failure("queued request project mismatch"));
    }
    Ok(Some((bytes, ticket)))
}
fn read_bytes(
    files: &NativeStateFiles,
    project: &ProjectId,
    maximum: usize,
) -> Result<Option<Vec<u8>>> {
    let path = files.root().join(format!("{}.json", project.as_str()));
    let Some(file) = files.readback(&path).map_err(failure)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(failure)?;
    if bytes.len() > maximum {
        return Err(failure("oversized project metadata/work request"));
    }
    Ok(Some(bytes))
}
fn publish(
    files: &NativeStateFiles,
    project: &ProjectId,
    before: Option<&[u8]>,
    bytes: &[u8],
) -> Result<()> {
    if before == Some(bytes) {
        return Ok(());
    }
    let path = files.root().join(format!("{}.json", project.as_str()));
    if let Some(before) = before {
        OwnedFile::open(&path)
            .map_err(failure)?
            .ok_or_else(|| failure("project metadata disappeared"))?
            .replace(Sha256::digest(before).into(), bytes)
            .map_err(failure)?;
    } else {
        let mut stage = files.create_staging(files.root()).map_err(failure)?;
        stage.file.write_all(bytes).map_err(failure)?;
        drop(stage.file);
        files
            .publish_no_replace(&stage.path, &path)
            .map_err(failure)?;
    }
    let actual = read_bytes(files, project, MAX_BYTES)?
        .ok_or_else(|| failure("published project metadata absent"))?;
    if actual != bytes {
        return Err(failure("project metadata publication readback differs"));
    }
    Ok(())
}
fn existing_or_create(path: &Path) -> Result<NativeStateFiles> {
    match open(path)? {
        Some(files) => Ok(files),
        None => NativeStateFiles::create(path).map_err(failure),
    }
}
fn open(path: &Path) -> Result<Option<NativeStateFiles>> {
    match NativeStateFiles::open(path) {
        Ok(files) => Ok(Some(files)),
        Err(error)
            if error
                .source
                .as_ref()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(failure(error)),
    }
}
fn failure(error: impl std::fmt::Display) -> SeError {
    se_core::scope::unreadable("Atlas project catalogue/work queue", &error.to_string())
}
