//! Bounded envelope carried by the inherited anonymous pipe, never a pathname.
use super::*;
use sha2::{Digest, Sha256};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
pub(super) struct Frame {
    pub handles: [u64; 5],
    pub parent: UninstallProcessIdentity,
    pub target: FileId,
    pub helper: FileId,
    pub digest: [u8; 32],
    pub nonce: [u8; 32],
    pub deadline: u64,
    pub root: PathBuf,
    pub cleanup_root: PathBuf,
    pub directory: Option<staging::DirectoryCustody>,
    pub helper_path: PathBuf,
    pub plan: Vec<u8>,
}
impl Frame {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut data = b"SEUNINST2".to_vec();
        for value in self.handles {
            data.extend(value.to_le_bytes());
        }
        data.extend(self.parent.pid.to_le_bytes());
        data.extend(self.parent.creation_filetime.to_le_bytes());
        for file in [self.target, self.helper] {
            data.extend(file.volume.to_le_bytes());
            data.extend(file.index);
        }
        data.extend(self.digest);
        data.extend(self.nonce);
        data.extend(self.deadline.to_le_bytes());
        for path in [
            &self.parent.image,
            &self.root,
            &self.cleanup_root,
            &self.helper_path,
        ] {
            let units: Vec<_> = path.as_os_str().encode_wide().collect();
            if !path.is_absolute() || units.len() > 32760 || units.contains(&0) {
                return Err(refuse("encode uninstall envelope", "invalid native path"));
            }
            data.extend((units.len() as u32).to_le_bytes());
            for unit in units {
                data.extend(unit.to_le_bytes());
            }
        }
        let directory = serde_json::to_vec(&self.directory)
            .map_err(|e| error("encode uninstall directory custody", io::Error::other(e)))?;
        data.extend((directory.len() as u32).to_le_bytes());
        data.extend(directory);
        if self.plan.is_empty() || self.plan.len() > 1024 * 1024 {
            return Err(refuse(
                "encode uninstall envelope",
                "core plan must be 1 byte to 1 MiB",
            ));
        }
        data.extend((self.plan.len() as u32).to_le_bytes());
        data.extend(&self.plan);
        let digest = Sha256::digest(&data);
        data.extend(digest);
        Ok(data)
    }
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() > 2 * 1024 * 1024 || data.len() < 41 {
            return Err(refuse(
                "authenticate uninstall envelope",
                "envelope size out of bounds",
            ));
        }
        let (body, expected) = data.split_at(data.len() - 32);
        if Sha256::digest(body).as_slice() != expected {
            return Err(refuse(
                "authenticate uninstall envelope",
                "envelope digest mismatch",
            ));
        }
        let mut input = Reader(body);
        if input.take(9)? != b"SEUNINST2" {
            return Err(refuse(
                "authenticate uninstall envelope",
                "unsupported native envelope",
            ));
        }
        let mut handles = [0; 5];
        for handle in &mut handles {
            *handle = input.u64()?;
        }
        for (i, handle) in handles.iter().enumerate() {
            if *handle == 0 || handles[..i].contains(handle) {
                return Err(refuse(
                    "authenticate uninstall envelope",
                    "invalid or duplicate inherited handle",
                ));
            }
        }
        let pid = input.u32()?;
        let creation_filetime = input.u64()?;
        let mut file = || -> Result<FileId> {
            Ok(FileId {
                volume: input.u64()?,
                index: input.array()?,
            })
        };
        let target = file()?;
        let helper = file()?;
        let digest = input.array()?;
        let nonce = input.array()?;
        let deadline = input.u64()?;
        let image = input.path()?;
        let root = input.path()?;
        let cleanup_root = input.path()?;
        let helper_path = input.path()?;
        let directory_size = input.u32()? as usize;
        if directory_size > 256 * 1024 {
            return Err(refuse(
                "read uninstall directory custody",
                "record capacity exceeded",
            ));
        }
        let directory = serde_json::from_slice(input.take(directory_size)?)
            .map_err(|e| error("read uninstall directory custody", io::Error::other(e)))?;
        let size = input.u32()? as usize;
        if size == 0 || size > 1024 * 1024 {
            return Err(refuse(
                "authenticate uninstall envelope",
                "core plan size out of bounds",
            ));
        }
        let plan = input.take(size)?.to_vec();
        if !input.0.is_empty() {
            return Err(refuse(
                "authenticate uninstall envelope",
                "trailing envelope bytes",
            ));
        }
        Ok(Self {
            handles,
            parent: UninstallProcessIdentity {
                pid,
                creation_filetime,
                image,
            },
            target,
            helper,
            digest,
            nonce,
            deadline,
            root,
            cleanup_root,
            directory,
            helper_path,
            plan,
        })
    }
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        if count > self.0.len() {
            return Err(refuse("read uninstall envelope", "truncated envelope"));
        }
        let (value, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| refuse("read uninstall envelope", "truncated fixed field"))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn path(&mut self) -> Result<PathBuf> {
        let size = self.u32()? as usize;
        if size > 32760 {
            return Err(refuse(
                "read uninstall envelope",
                "native path capacity exceeded",
            ));
        }
        let units: Vec<_> = self
            .take(size * 2)?
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        let path: PathBuf = std::ffi::OsString::from_wide(&units).into();
        if !path.is_absolute() || path.as_os_str().encode_wide().any(|c| c == 0) {
            return Err(refuse(
                "read uninstall envelope",
                "invalid native absolute path",
            ));
        }
        Ok(path)
    }
}
