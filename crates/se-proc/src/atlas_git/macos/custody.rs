//! Protected cleanup custody is published before repository bytes can execute.
use super::{
    identity::{ProcessPin, State},
    invalid,
};
use crate::{NativeStateFiles, source_root::NativeSourceRoot, state_files::effects::OwnedFile};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub(super) const NAME: &str = ".git-custody.json";
const RECORD_BYTES: usize = 16_384;
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub schema: u8,
    pub nonce: [u8; 32],
    pub control_identity: [u8; 32],
    pub host: ProcessPin,
    pub supervisor: ProcessPin,
    pub git: ProcessPin,
}
impl Record {
    fn validate(&self, root: &NativeSourceRoot) -> io::Result<()> {
        if self.schema != 1
            || self.nonce == [0; 32]
            || root.physical_identity()? != self.control_identity
        {
            return Err(invalid(
                "Git cleanup custody differs from its protected control root",
            ));
        }
        // These receipts must describe three distinct processes of this user and boot.
        // SAFETY: read-only process-local UID query.
        let uid = unsafe { libc::geteuid() };
        let boot = &self.host.boot;
        for pin in [&self.host, &self.supervisor, &self.git] {
            if pin.pid == 0
                || pin.pid > i32::MAX as u32
                || pin.uid != uid
                || &pin.boot != boot
                || !matches!(pin.birth, se_types::StartIdentity::Macos { .. })
            {
                return Err(invalid("Git cleanup record has an invalid native receipt"));
            }
        }
        if self.host.pid == self.supervisor.pid
            || self.host.pid == self.git.pid
            || self.supervisor.pid == self.git.pid
        {
            return Err(invalid("Git cleanup record conflates its ownership tree"));
        }
        Ok(())
    }
}
pub(super) struct Custody {
    root: NativeSourceRoot,
    path: PathBuf,
    record: Record,
    digest: [u8; 32],
}
fn sync_root(path: &Path) -> io::Result<()> {
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    root.sync_all()
}
impl Custody {
    pub(super) fn publish(control: &Path, record: Record) -> io::Result<Self> {
        let root = NativeSourceRoot::open(control)?;
        record.validate(&root)?;
        let files = NativeStateFiles::open(control).map_err(io::Error::other)?;
        let bytes = serde_json::to_vec(&record).map_err(io::Error::other)?;
        if bytes.len() > RECORD_BYTES {
            return Err(invalid("Git cleanup custody exceeds its fixed bound"));
        }
        let mut stage = files.create_staging(control).map_err(io::Error::other)?;
        stage.file.write_all(&bytes)?;
        stage.file.sync_all()?;
        files
            .publish_no_replace(&stage.path, &control.join(NAME))
            .map_err(io::Error::other)?;
        root.check()?;
        sync_root(control)?;
        root.check()?;
        let published = Self::open(control)?
            .ok_or_else(|| invalid("published Git cleanup record is absent"))?;
        if published.digest != <[u8; 32]>::from(Sha256::digest(&bytes)) {
            return Err(invalid("published Git cleanup custody changed on readback"));
        }
        Ok(published)
    }
    pub(super) fn open(control: &Path) -> io::Result<Option<Self>> {
        let root = NativeSourceRoot::open(control)?;
        let files = NativeStateFiles::open(control).map_err(io::Error::other)?;
        let Some(file) = files
            .readback(&control.join(NAME))
            .map_err(io::Error::other)?
        else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.take(RECORD_BYTES as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > RECORD_BYTES {
            return Err(invalid("Git cleanup custody exceeds its read bound"));
        }
        let record: Record = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        record.validate(&root)?;
        root.check()?;
        Ok(Some(Self {
            root,
            path: control.to_owned(),
            record,
            digest: Sha256::digest(bytes).into(),
        }))
    }
    pub(super) fn retire(&self, deadline: Instant) -> io::Result<()> {
        for pin in [&self.record.git, &self.record.supervisor] {
            if pin.state(deadline)? == State::Alive {
                return Err(invalid("Git cleanup custody still names a live process"));
            }
        }
        self.root.check()?;
        let path = self.path.join(NAME);
        let owned = OwnedFile::open(&path)
            .map_err(io::Error::other)?
            .ok_or_else(|| invalid("retained Git cleanup custody disappeared"))?;
        owned.remove(self.digest).map_err(io::Error::other)?;
        sync_root(&self.path)?;
        self.root.check()
    }
    pub(super) fn reconcile(self) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_millis(200);
        if self.record.host.state(deadline)? == State::Alive {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Git cleanup belongs to a live host",
            ));
        }
        // Git first, then its supervisor. These are external instances: observe
        // exit/absence, never claim waitpid ownership of a non-child.
        self.record.git.terminate(deadline)?;
        self.record.supervisor.terminate(deadline)?;
        loop {
            if self.record.git.state(deadline)? != State::Alive
                && self.record.supervisor.state(deadline)? != State::Alive
            {
                return self.retire(deadline);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Git recovery could not observe both exits",
                ));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// An intent precedes process creation. If its full receipt never arrives,
/// recovery refuses rather than inventing an absent child from an unknown PID.
pub(super) struct Intent {
    root: NativeSourceRoot,
    path: PathBuf,
    digest: [u8; 32],
    host: ProcessPin,
    nonce: [u8; 32],
}
impl Intent {
    pub(super) const NAME: &str = ".git-intent.json";
    pub(super) fn publish(control: &Path, host: &ProcessPin, nonce: [u8; 32]) -> io::Result<Self> {
        let root = NativeSourceRoot::open(control)?;
        let files = NativeStateFiles::open(control).map_err(io::Error::other)?;
        let bytes = serde_json::to_vec(&(1u8, nonce, host, root.physical_identity()?))
            .map_err(io::Error::other)?;
        let mut stage = files.create_staging(control).map_err(io::Error::other)?;
        stage.file.write_all(&bytes)?;
        stage.file.sync_all()?;
        let path = control.join(Self::NAME);
        files
            .publish_no_replace(&stage.path, &path)
            .map_err(io::Error::other)?;
        sync_root(control)?;
        root.check()?;
        let published = Self::open(control)?
            .ok_or_else(|| invalid("published Git creation intent is absent"))?;
        if published.digest != <[u8; 32]>::from(Sha256::digest(bytes)) {
            return Err(invalid("Git creation intent changed on readback"));
        }
        Ok(published)
    }
    pub(super) fn open(control: &Path) -> io::Result<Option<Self>> {
        let root = NativeSourceRoot::open(control)?;
        let files = NativeStateFiles::open(control).map_err(io::Error::other)?;
        let path = control.join(Self::NAME);
        let Some(file) = files.readback(&path).map_err(io::Error::other)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.take(RECORD_BYTES as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > RECORD_BYTES {
            return Err(invalid("Git creation intent exceeds its read bound"));
        }
        let (schema, nonce, host, identity): (u8, [u8; 32], ProcessPin, [u8; 32]) =
            serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        // SAFETY: read-only native effective-user query.
        if schema != 1
            || nonce == [0; 32]
            || host.uid != unsafe { libc::geteuid() }
            || host.pid == 0
            || host.pid > i32::MAX as u32
            || !matches!(host.birth, se_types::StartIdentity::Macos { .. })
            || identity != root.physical_identity()?
        {
            return Err(invalid(
                "Git creation intent differs from its protected root",
            ));
        }
        root.check()?;
        Ok(Some(Self {
            root,
            path,
            digest: Sha256::digest(bytes).into(),
            host,
            nonce,
        }))
    }
    pub(super) fn matches(&self, custody: &Custody) -> io::Result<()> {
        self.root.check()?;
        custody.root.check()?;
        if self.nonce != custody.record.nonce
            || self.root.physical_identity()? != custody.record.control_identity
        {
            return Err(invalid("Git custody differs from its creation intent"));
        }
        self.host.verify(&custody.record.host)
    }
    /// Only the owner that proved its complete tree gone may retire this intent.
    pub(super) fn retire(&self) -> io::Result<()> {
        self.root.check()?;
        OwnedFile::open(&self.path)
            .map_err(io::Error::other)?
            .ok_or_else(|| invalid("Git creation intent disappeared"))?
            .remove(self.digest)
            .map_err(io::Error::other)?;
        sync_root(
            self.path
                .parent()
                .ok_or_else(|| invalid("Git intent has no parent"))?,
        )?;
        self.root.check()
    }
}
