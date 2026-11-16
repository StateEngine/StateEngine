//! A measured image proof transferred only over an owned inherited bootstrap.
use super::{image, *};
use std::fs::{File, OpenOptions};

/// This is a speed aid, never authority or a process identity. The launching
/// parent measures it and retains its file pin until the child has adopted it.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InheritedImageProof {
    stamp: image::ImageKey,
    digest: Sha256,
}

/// Retain this pin for the lifetime of any inherited cached image proof.
/// Windows excludes writers while both processes transfer their native pins.
pub struct InheritedImagePin {
    _file: File,
}

fn open(path: &Path) -> IpcNativeResult<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ};
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE);
    }
    options
        .open(path)
        .map_err(|e| error("pin inherited image", e))
}

impl InheritedImageProof {
    pub fn measure(path: &Path, bound: &IpcIoBound) -> IpcNativeResult<(Self, InheritedImagePin)> {
        let file = open(path)?;
        let before = file
            .metadata()
            .map_err(|e| error("read inherited image", e))?;
        let stamp = image::key(&file, &before)?;
        let digest = hash_image(
            file.try_clone()
                .map_err(|e| error("retain measured image", e))?,
            bound,
        )?;
        let after = file
            .metadata()
            .map_err(|e| error("reobserve inherited image", e))?;
        if image::key(&file, &after)? != stamp {
            return Err(refuse(
                IpcNativeErrorCode::PeerChanged,
                "image changed during parent measurement",
            ));
        }
        Ok((Self { stamp, digest }, InheritedImagePin { _file: file }))
    }

    /// Call only with a proof from the launching parent's inherited channel.
    /// No discovery file or ambient hint can supply this digest. Native peer
    /// birth, principal, image pin and per-launch capability still authenticate.
    pub fn adopt(&self, path: &Path, bound: &IpcIoBound) -> IpcNativeResult<InheritedImagePin> {
        bound
            .remaining()
            .map_err(|e| error("inherited image deadline", e))?;
        let file = open(path)?;
        let metadata = file
            .metadata()
            .map_err(|e| error("read inherited image pin", e))?;
        if !metadata.is_file() || image::key(&file, &metadata)? != self.stamp {
            return Err(refuse(
                IpcNativeErrorCode::PeerChanged,
                "inherited image differs from the parent's measured pin",
            ));
        }
        image::remember(self.stamp.clone(), self.digest)?;
        Ok(InheritedImagePin { _file: file })
    }
}
