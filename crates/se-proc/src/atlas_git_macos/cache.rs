//! Custody for OS-reported cache data, separate from executable ancestry pins.
use super::{clock::Expiry, invalid};
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
};

// Native sys/stat.h ABI values not exposed by libc.
const SF_RESTRICTED: u32 = 0x0008_0000;
const SF_NOUNLINK: u32 = 0x0010_0000;

#[derive(Eq, PartialEq)]
struct ContentStamp {
    length: libc::off_t,
    modified: (libc::time_t, libc::c_long),
    changed: (libc::time_t, libc::c_long),
}
#[derive(Eq, PartialEq)]
struct Stamp {
    device: libc::dev_t,
    inode: libc::ino_t,
    owner: (libc::uid_t, libc::gid_t),
    mode: libc::mode_t,
    flags: u32,
    content: Option<ContentStamp>,
}
struct Node {
    file: File,
    stamp: Stamp,
}
struct Member {
    name: CString,
    node: Node,
}
pub(super) struct CachePins {
    directory: PathBuf,
    ancestry: Vec<Node>,
    members: Vec<Member>,
}

fn stamp(file: &File, regular: bool) -> io::Result<Stamp> {
    // SAFETY: initialized native metadata output for this retained descriptor.
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: live descriptor and exact writable native stat storage.
    if unsafe { libc::fstat(file.as_raw_fd(), &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let expected = if regular {
        libc::S_IFREG
    } else {
        libc::S_IFDIR
    };
    if value.st_mode & libc::S_IFMT != expected || value.st_uid != 0 {
        return Err(invalid(
            "OS cache custody requires a root-owned native object",
        ));
    }
    if regular && (value.st_mode & 0o022 != 0 || value.st_flags & SF_RESTRICTED == 0) {
        return Err(invalid(
            "OS cache file requires non-writable mode and SF_RESTRICTED",
        ));
    }
    // SAFETY: initialized native volume output for the retained descriptor.
    let mut volume: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: live descriptor and exact writable native statfs storage.
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut volume) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if volume.f_owner != 0
        || volume.f_flags & libc::MNT_LOCAL as u32 == 0
        || volume.f_flags & libc::MNT_IGNORE_OWNERSHIP as u32 != 0
    {
        return Err(invalid(
            "OS cache requires a root-mounted local ownership-enforcing filesystem",
        ));
    }
    Ok(Stamp {
        device: value.st_dev,
        inode: value.st_ino,
        owner: (value.st_uid, value.st_gid),
        mode: value.st_mode,
        flags: value.st_flags,
        content: regular.then_some(ContentStamp {
            length: value.st_size,
            modified: (value.st_mtime, value.st_mtime_nsec),
            changed: (value.st_ctime, value.st_ctime_nsec),
        }),
    })
}
fn node(file: File, regular: bool) -> io::Result<Node> {
    Ok(Node {
        stamp: stamp(&file, regular)?,
        file,
    })
}
fn open_at(parent: &File, name: &CString, regular: bool) -> io::Result<File> {
    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | if regular { 0 } else { libc::O_DIRECTORY };
    // SAFETY: retained parent, one terminated leaf name, no following links or mutations.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful openat transferred one owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn walk(path: &Path, expiry: Expiry) -> io::Result<Vec<Node>> {
    expiry.remaining()?;
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(invalid("OS cache requires a bounded absolute directory"));
    }
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    let mut result = vec![node(root, false)?];
    let mut protected_edge = false;
    for component in path.components().skip(1) {
        expiry.remaining()?;
        if result.len() >= 64 {
            return Err(invalid("OS cache ancestry exceeds 64 retained directories"));
        }
        let Component::Normal(name) = component else {
            return Err(invalid(
                "OS cache ancestry requires physical normal components",
            ));
        };
        let name =
            CString::new(name.as_bytes()).map_err(|_| invalid("OS cache name contains NUL"))?;
        let parent = result
            .last()
            .ok_or_else(|| invalid("OS cache lost its retained root"))?;
        let next = node(open_at(&parent.file, &name, false)?, false)?;
        if protected_edge && next.stamp.flags & SF_RESTRICTED == 0 {
            return Err(invalid(
                "OS cache strict descendants of SF_NOUNLINK require SF_RESTRICTED",
            ));
        }
        if parent.stamp.mode & 0o022 != 0 {
            if protected_edge
                || parent.stamp.mode & 0o002 == 0
                || next.stamp.flags & SF_NOUNLINK == 0
            {
                return Err(invalid(
                    "OS cache writable-parent edge requires one root-owned SF_NOUNLINK child",
                ));
            }
            protected_edge = true;
        }
        if protected_edge && next.stamp.mode & 0o022 != 0 {
            return Err(invalid(
                "OS cache below SF_NOUNLINK requires non-writable directories",
            ));
        }
        result.push(next);
    }
    if result.last().is_none_or(|n| n.stamp.mode & 0o022 != 0) {
        return Err(invalid("OS cache directory is writable"));
    }
    Ok(result)
}
impl CachePins {
    pub(super) fn open(directory: &Path, expiry: Expiry) -> io::Result<Self> {
        Ok(Self {
            directory: directory.to_owned(),
            ancestry: walk(directory, expiry)?,
            members: Vec::new(),
        })
    }
    pub(super) fn pin(&mut self, path: &Path, expiry: Expiry) -> io::Result<()> {
        expiry.remaining()?;
        if path.parent() != Some(self.directory.as_path()) {
            return Err(invalid("OS cache member escaped its retained directory"));
        }
        let name = path
            .file_name()
            .ok_or_else(|| invalid("OS cache member has no leaf name"))?;
        let name = CString::new(name.as_bytes())
            .map_err(|_| invalid("OS cache member name contains NUL"))?;
        let parent = self
            .ancestry
            .last()
            .ok_or_else(|| invalid("OS cache lost directory custody"))?;
        let held = node(open_at(&parent.file, &name, true)?, true)?;
        self.members.push(Member { name, node: held });
        Ok(())
    }
    pub(super) fn check(&self, expiry: Expiry) -> io::Result<()> {
        let fresh = walk(&self.directory, expiry)?;
        if self.ancestry.len() != fresh.len() {
            return Err(invalid("OS cache ancestry changed before release"));
        }
        for (held, named) in self.ancestry.iter().zip(&fresh) {
            expiry.remaining()?;
            if stamp(&held.file, false)? != held.stamp || named.stamp != held.stamp {
                return Err(invalid(
                    "OS cache directory identity or protection changed before release",
                ));
            }
        }
        let parent = fresh
            .last()
            .ok_or_else(|| invalid("OS cache lost its reobserved directory"))?;
        for member in &self.members {
            expiry.remaining()?;
            let named = open_at(&parent.file, &member.name, true)?;
            if stamp(&member.node.file, true)? != member.node.stamp
                || stamp(&named, true)? != member.node.stamp
            {
                return Err(invalid(
                    "OS cache file identity, content stamp or SF_RESTRICTED changed before release",
                ));
            }
        }
        expiry.remaining()?;
        Ok(())
    }
}
