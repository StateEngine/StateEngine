use super::*;
use std::{
    fs,
    io::Read,
    os::unix::{ffi::OsStringExt, fs::MetadataExt},
    path::{Path, PathBuf},
};

fn bytes(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = fs::File::open(path).map_err(|e| native("open native owner fact", e))?;
    let mut data = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|e| native("read native owner fact", e))?;
    if data.len() > limit {
        return Err(refuse(
            "read native owner fact",
            "native fact capacity exceeded",
        ));
    }
    Ok(data)
}
pub(super) fn boot() -> Result<BootIdentity> {
    let data = bytes(Path::new("/proc/sys/kernel/random/boot_id"), 64)?;
    let digits: Vec<_> = data
        .iter()
        .copied()
        .filter(|c| *c != b'-' && !c.is_ascii_whitespace())
        .collect();
    if digits.len() != 32 {
        return Err(refuse("read boot identity", "malformed boot UUID"));
    }
    let mut boot_id = [0; 16];
    for (i, pair) in digits.chunks_exact(2).enumerate() {
        let hex = |c: u8| -> Result<u8> {
            match c {
                b'0'..=b'9' => Ok(c - b'0'),
                b'a'..=b'f' => Ok(c - b'a' + 10),
                _ => Err(refuse("read boot identity", "malformed boot UUID")),
            }
        };
        boot_id[i] = hex(pair[0])? * 16 + hex(pair[1])?;
    }
    Ok(BootIdentity::Linux { boot_id })
}
pub(super) fn stamp(pid: ProcessId, boot: &BootIdentity) -> Result<ProcessStamp> {
    if pid.0 == 0 || pid.0 > i32::MAX as u32 {
        return Err(refuse("read owner ancestry", "invalid process ID"));
    }
    let data = bytes(Path::new(&format!("/proc/{}/stat", pid.0)), 4096)?;
    // Linux comm may contain whitespace and ')' characters, including non-UTF8.
    let end = data
        .windows(2)
        .rposition(|p| p == b") ")
        .ok_or_else(|| refuse("read owner ancestry", "malformed proc stat"))?;
    if matches!(data.get(end + 2), Some(b'Z' | b'X' | b'x')) {
        return Err(refuse("read owner ancestry", "process has exited"));
    }
    let fields: Vec<_> = data[end + 2..]
        .split(u8::is_ascii_whitespace)
        .filter(|p| !p.is_empty())
        .collect();
    let number = |index: usize| -> Result<u64> {
        fields
            .get(index)
            .and_then(|s| std::str::from_utf8(s).ok())
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| refuse("read owner ancestry", "invalid or truncated proc stat"))
    };
    let process = |index| -> Result<ProcessId> {
        u32::try_from(number(index)?)
            .map(ProcessId)
            .map_err(|_| refuse("read owner ancestry", "native PID overflow"))
    };
    Ok(ProcessStamp {
        pid,
        parent: process(1)?,
        group: process(2)?,
        session: process(3)?,
        boot: boot.clone(),
        start: StartIdentity::Linux {
            start_ticks: number(19)?,
        },
    })
}
pub(super) fn owner(pid: ProcessId) -> Result<NativeOwner> {
    let data = bytes(Path::new(&format!("/proc/{}/status", pid.0)), 65536)?;
    let mut lines = data
        .split(|b| *b == b'\n')
        .filter_map(|line| line.strip_prefix(b"Uid:"));
    let line = lines
        .next()
        .ok_or_else(|| refuse("read target owner", "native UID record absent"))?;
    if lines.next().is_some() {
        return Err(refuse("read target owner", "duplicate native UID record"));
    }
    let values: Vec<_> = line
        .split(u8::is_ascii_whitespace)
        .filter(|s| !s.is_empty())
        .collect();
    if values.len() != 4 {
        return Err(refuse("read target owner", "invalid native UID record"));
    }
    let number = |value: &[u8]| -> Result<u32> {
        std::str::from_utf8(value)
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| refuse("read target owner", "invalid native UID"))
    };
    Ok(NativeOwner::Unix {
        real_uid: number(values[0])?,
        effective_uid: number(values[1])?,
    })
}
fn unescape(value: &[u8]) -> Result<PathBuf> {
    let mut bytes = Vec::new();
    let mut index = 0;
    while index < value.len() {
        if value[index] == b'\\' {
            let escaped = value
                .get(index + 1..index + 4)
                .ok_or_else(|| refuse("read cgroup mount", "truncated mount escape"))?;
            bytes.push(match escaped {
                b"040" => b' ',
                b"011" => b'\t',
                b"012" => b'\n',
                b"134" => b'\\',
                _ => return Err(refuse("read cgroup mount", "invalid mount escape")),
            });
            index += 4;
        } else {
            bytes.push(value[index]);
            index += 1;
        }
    }
    let path = PathBuf::from(std::ffi::OsString::from_vec(bytes));
    if !path.is_absolute()
        || path.components().any(|c| {
            !matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(refuse("read cgroup mount", "non-normal absolute path"));
    }
    Ok(path)
}
pub(super) fn in_cgroup(pid: ProcessId, root: &Path, device: u64, inode: u64) -> Result<bool> {
    let before = bytes(Path::new(&format!("/proc/{}/cgroup", pid.0)), 65536)?;
    let mut lines = before
        .split(|c| *c == b'\n')
        .filter_map(|line| line.strip_prefix(b"0::"));
    let relative = unescape(
        lines
            .next()
            .ok_or_else(|| refuse("read cgroup membership", "cgroup v2 membership absent"))?,
    )?;
    if lines.next().is_some() {
        return Err(refuse(
            "read cgroup membership",
            "duplicate cgroup v2 membership",
        ));
    }
    let mounts = bytes(Path::new("/proc/self/mountinfo"), 4 * 1024 * 1024)?;
    let mut locations = Vec::new();
    for line in mounts.split(|c| *c == b'\n') {
        let Some(split) = line.windows(3).position(|p| p == b" - ") else {
            continue;
        };
        if !line[split + 3..].starts_with(b"cgroup2 ") {
            continue;
        }
        let fields: Vec<_> = line[..split].split(|c| *c == b' ').collect();
        if fields.len() < 6 {
            return Err(refuse("read cgroup mount", "truncated cgroup2 mount"));
        }
        let mount_root = unescape(fields[3])?;
        let mount_point = unescape(fields[4])?;
        if let Ok(suffix) = relative.strip_prefix(&mount_root) {
            locations.push(mount_point.join(suffix));
        }
    }
    if locations.is_empty() {
        return Err(refuse(
            "read cgroup mount",
            "cannot resolve native cgroup membership",
        ));
    }
    match fs::symlink_metadata(root) {
        Ok(meta) if meta.is_dir() && meta.dev() == device && meta.ino() == inode => {}
        Ok(_) => {
            return Err(refuse(
                "read managed cgroup",
                "recorded native cgroup object changed",
            ));
        }
        Err(e) => return Err(native("read managed cgroup", e)),
    }
    // Compare actual objects, not lexical mount paths: cgroup mounts may have
    // aliases or a non-root mount root. An invisible record is unresolved, not
    // evidence that its processes disappeared in another mount namespace.
    let mut found = false;
    for location in locations {
        for ancestor in location.ancestors() {
            let meta = fs::symlink_metadata(ancestor)
                .map_err(|e| native("read native cgroup ancestry", e))?;
            if !meta.is_dir() {
                return Err(refuse(
                    "read native cgroup ancestry",
                    "non-directory cgroup ancestor",
                ));
            }
            if meta.dev() == device && meta.ino() == inode {
                found = true;
                break;
            }
        }
    }
    if bytes(Path::new(&format!("/proc/{}/cgroup", pid.0)), 65536)? != before {
        return Err(refuse(
            "recheck cgroup membership",
            "membership changed during observation",
        ));
    }
    Ok(found)
}
