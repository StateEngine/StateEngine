//! An exclusive private Git directory: repository configuration is never loaded.
use super::*;
use crate::source_root::{NativeFileRevision, NativeSourceRoot};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::Write,
};

pub(super) struct Control {
    path: std::path::PathBuf,
    root: NativeSourceRoot,
    files: Vec<(&'static str, NativeFileRevision)>,
    retired: bool,
}
impl Control {
    pub(super) fn create(path: &Path, sha256: bool) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(invalid("private Git control path must be absolute"));
        }
        let builder = DirBuilder::new();
        #[cfg(unix)]
        let builder = {
            let mut builder = builder;
            builder.mode(0o700);
            builder
        };
        builder.create(path)?;
        let mut result = Self {
            path: path.into(),
            root: NativeSourceRoot::open(path)?,
            files: Vec::new(),
            retired: false,
        };
        for name in ["objects", "refs"] {
            builder.create(path.join(name))?;
        }
        result.file("HEAD", b"ref: refs/heads/atlas-read-only\n")?;
        result.file("config",if sha256 {b"[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectFormat = sha256\n"}else{b"[core]\nrepositoryformatversion = 0\nbare = true\n"})?;
        Ok(result)
    }
    fn file(&mut self, name: &'static str, bytes: &[u8]) -> io::Result<()> {
        self.root.check()?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(self.path.join(name))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        self.files
            .push((name, crate::source_root::observe_file_revision(&file)?));
        self.root.check()
    }
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
    pub(super) fn root(&self) -> &NativeSourceRoot {
        &self.root
    }
    pub(super) fn check(&self) -> io::Result<()> {
        self.root.check()?;
        for (name, revision) in &self.files {
            let file = self
                .root
                .open_relative(name)?
                .ok_or_else(|| invalid("private Git control file disappeared"))?;
            if &file.revision()? != revision {
                return Err(invalid("private Git control file changed"));
            }
        }
        Ok(())
    }
    pub(super) fn close(&mut self) -> io::Result<()> {
        self.check()?;
        for (name, _) in self.files.drain(..) {
            fs::remove_file(self.path.join(name))?;
        }
        for name in ["objects", "refs"] {
            fs::remove_dir(self.path.join(name))?;
        }
        self.root.check()?;
        fs::remove_dir(&self.path)?;
        if self.path.try_exists()? {
            return Err(invalid(
                "private Git control cleanup did not retire its name",
            ));
        }
        self.retired = true;
        Ok(())
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        if !self.retired
            && let Err(error) = self.close()
        {
            eprintln!(
                "private Git control cleanup refused at {}: {error}",
                self.path.display()
            );
        }
    }
}
