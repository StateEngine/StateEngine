//! Exact Mach-O imports plus the active OS cache, never a directory read grant.
use super::{clock::Expiry, invalid, macho};
use crate::{NativeExecutableInvocation, NativeExecutablePin};
use std::{
    collections::BTreeSet,
    ffi::{CStr, CString},
    io,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};
unsafe extern "C" {
    fn _dyld_shared_cache_contains_path(path: *const libc::c_char) -> bool;
    fn dyld_shared_cache_file_path() -> *const libc::c_char;
}
pub(super) struct Runtime {
    pins: Vec<NativeExecutableInvocation>,
    names: BTreeSet<PathBuf>,
}
impl Runtime {
    pub(super) fn discover(image: &Path, expiry: Expiry) -> io::Result<Self> {
        let mut result = Self {
            pins: Vec::new(),
            names: BTreeSet::new(),
        };
        let mut pending = vec![image.to_owned()];
        let mut cache = false;
        while let Some(path) = pending.pop() {
            expiry.remaining()?;
            let name = CString::new(path.as_os_str().as_bytes())
                .map_err(|_| invalid("Git runtime path contains NUL"))?;
            // SAFETY: bounded, terminated absolute name; this query loads no code.
            if unsafe { _dyld_shared_cache_contains_path(name.as_ptr()) } {
                if result.names.len() >= 96 {
                    return Err(invalid("Git runtime closure exceeds 96 names"));
                }
                result.names.insert(path);
                cache = true;
                continue;
            }
            let path = path.canonicalize()?;
            if result.names.contains(&path) {
                continue;
            }
            let pin = result.pin(&path)?;
            pending.extend(macho::dependencies(pin.retained_file(), expiry)?);
            result.pins.push(pin);
        }
        if cache {
            result.cache(expiry)?
        }
        result.check()?;
        Ok(result)
    }
    fn pin(&mut self, path: &Path) -> io::Result<NativeExecutableInvocation> {
        if self.names.len() >= 96 {
            return Err(invalid("Git runtime closure exceeds 96 names"));
        }
        let pin = NativeExecutablePin::open(path)
            .map_err(io::Error::other)?
            .ok_or_else(|| invalid("Git runtime image is absent"))?
            .prepare()
            .map_err(io::Error::other)?;
        self.names.insert(path.to_owned());
        Ok(pin)
    }
    fn cache(&mut self, expiry: Expiry) -> io::Result<()> {
        // SAFETY: dyld owns the process-lifetime terminated cache pathname.
        let raw = unsafe { dyld_shared_cache_file_path() };
        if raw.is_null() {
            return Err(invalid("active Git OS cache path is unavailable"));
        }
        // SAFETY: non-null native dyld string from the preceding query.
        let bytes = unsafe { CStr::from_ptr(raw) }.to_bytes();
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err(invalid("OS cache path exceeds its bound"));
        }
        let path = Path::new(std::ffi::OsStr::from_bytes(bytes)).canonicalize()?;
        let parent = path
            .parent()
            .ok_or_else(|| invalid("OS cache has no directory"))?;
        let name = path
            .file_name()
            .ok_or_else(|| invalid("OS cache has no filename"))?
            .as_bytes();
        let mut prefix = name.to_vec();
        prefix.push(b'.');
        let mut found = false;
        for (index, entry) in std::fs::read_dir(parent)?.enumerate() {
            expiry.remaining()?;
            if index >= 4096 {
                return Err(invalid("OS cache directory exceeds its inventory bound"));
            }
            let entry = entry?;
            let filename = entry.file_name();
            if filename.as_bytes() != name && !filename.as_bytes().starts_with(&prefix) {
                continue;
            }
            if !entry.file_type()?.is_file() {
                return Err(invalid("OS cache member is not a regular file"));
            }
            use std::os::unix::fs::MetadataExt;
            let metadata = entry.metadata()?;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(invalid(
                    "OS cache member is not protected by the system owner",
                ));
            }
            found |= filename.as_bytes() == name;
            let pin = self.pin(&entry.path())?;
            self.pins.push(pin);
        }
        if !found {
            return Err(invalid("active OS cache was absent from its directory"));
        }
        Ok(())
    }
    pub(super) fn check(&self) -> io::Result<()> {
        for pin in &self.pins {
            pin.validate().map_err(io::Error::other)?
        }
        Ok(())
    }
    pub(super) fn names(&self) -> impl Iterator<Item = &Path> {
        self.names.iter().map(PathBuf::as_path)
    }
}
