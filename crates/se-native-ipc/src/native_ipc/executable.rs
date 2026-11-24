//! A process-local qualification key for one directly invoked native image.
use super::{IpcNativeErrorCode, IpcNativeResult, error, image, refuse};
use std::{
    fs::OpenOptions,
    io::{Read, Seek},
    path::{Path, PathBuf},
};

/// File facts only, never authentication, policy or a running process proof.
/// Native revisions or a digest under continuous writer exclusion detect edits.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecutableStamp {
    path: PathBuf,
    image: image::ImageKey,
    content: Option<se_types::Sha256>,
}
impl ExecutableStamp {
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Aliases and scripts deliberately have no reusable qualification key.
    /// Unavailable revisions require bounded content proof or a retained native pin.
    /// Every observation opens and reads the image; unreadability is an error.
    pub fn observe(path: &Path) -> IpcNativeResult<Option<Self>> {
        if !path.is_absolute() {
            return Err(refuse(
                IpcNativeErrorCode::Unreadable,
                "executable stamp requires an absolute path",
            ));
        }
        if crate::canonicalize_path(path).map_err(|e| error("resolve qualification image", e))?
            != path
        {
            return Ok(None);
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = options
            .open(path)
            .map_err(|e| error("open qualification image", e))?;
        let before = file
            .metadata()
            .map_err(|e| error("read qualification metadata", e))?;
        if !before.is_file() {
            return Ok(None);
        }
        let stamp = image::key(&file, &before)?;
        let mut magic = [0; 4];
        match file.read_exact(&mut magic) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(error("read qualification image header", e)),
        }
        let native = if cfg!(windows) {
            magic.starts_with(b"MZ")
        } else if cfg!(target_os = "macos") {
            matches!(
                magic,
                [0xfe, 0xed, 0xfa, 0xce | 0xcf]
                    | [0xce | 0xcf, 0xfa, 0xed, 0xfe]
                    | [0xca, 0xfe, 0xba, 0xbe | 0xbf]
                    | [0xbe | 0xbf, 0xba, 0xfe, 0xca]
            )
        } else {
            magic == *b"\x7fELF"
        };
        if !native {
            return Ok(None);
        }
        let content = if stamp.reusable() {
            None
        } else {
            file.rewind()
                .map_err(|e| error("rewind qualification image", e))?;
            let held = file
                .try_clone()
                .map_err(|e| error("clone qualification image", e))?;
            let bound = super::proof_bound(std::time::Duration::from_secs(30));
            Some(image::hash_image(held, &bound)?)
        };
        // Reopen the selected path as well as the retained file: a replacement
        // must not inherit the successful qualification of the old inode.
        let current = options
            .open(path)
            .map_err(|e| error("reopen qualification image", e))?;
        let after = file
            .metadata()
            .map_err(|e| error("reobserve qualification image", e))?;
        let selected = current
            .metadata()
            .map_err(|e| error("reobserve qualification path", e))?;
        if image::key(&file, &after)? != stamp
            || image::key(&current, &selected)? != stamp
            || crate::canonicalize_path(path).map_err(|e| error("recheck qualification path", e))?
                != path
        {
            return Err(refuse(
                IpcNativeErrorCode::PeerChanged,
                "executable changed during qualification observation",
            ));
        }
        Ok(Some(Self {
            path: path.to_owned(),
            image: stamp,
            content,
        }))
    }
}
