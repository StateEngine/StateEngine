//! Bounded native-architecture load commands; no executable code is loaded here.
use super::{clock::Expiry, invalid};
use std::{fs::File, io, os::unix::fs::FileExt, path::PathBuf};

const MAX_METADATA: usize = 262_144;
#[cfg(target_arch = "aarch64")]
const CPU: u32 = 0x0100_000c;
#[cfg(target_arch = "x86_64")]
const CPU: u32 = 0x0100_0007;
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
const CPU: u32 = 0;
fn read(file: &File, offset: u64, length: usize, expiry: Expiry) -> io::Result<Vec<u8>> {
    expiry.remaining()?;
    let file_length = file.metadata()?.len();
    if length > MAX_METADATA
        || offset
            .checked_add(length as u64)
            .is_none_or(|end| end > file_length)
    {
        return Err(invalid("Git Mach-O metadata is outside its bounded file"));
    }
    let mut bytes = vec![0; length];
    file.read_exact_at(&mut bytes, offset)?;
    expiry.remaining()?;
    Ok(bytes)
}
fn number(bytes: &[u8], offset: usize, width: usize, big: bool) -> io::Result<u64> {
    let value = bytes
        .get(offset..offset + width)
        .ok_or_else(|| invalid("truncated Git Mach-O scalar"))?;
    Ok(value.iter().enumerate().fold(0, |out, (index, byte)| {
        out | (u64::from(*byte) << (8 * if big { width - index - 1 } else { index }))
    }))
}
fn slice(file: &File, expiry: Expiry) -> io::Result<(u64, u64)> {
    let bytes = read(file, 0, 8, expiry)?;
    let magic = number(&bytes, 0, 4, true)?;
    if magic == 0xcffa_edfe {
        return Ok((0, file.metadata()?.len()));
    }
    let width = match magic {
        0xcafe_babe => 20,
        0xcafe_babf => 32,
        _ => return Err(invalid("Git requires a native 64-bit Mach-O image")),
    };
    let count = number(&bytes, 4, 4, true)? as usize;
    if count == 0 || count > 32 || CPU == 0 {
        return Err(invalid(
            "Git universal architecture table exceeds its profile",
        ));
    }
    let entries = read(file, 8, count * width, expiry)?;
    let mut selected = None;
    for entry in entries.chunks_exact(width) {
        if number(entry, 0, 4, true)? != u64::from(CPU) {
            continue;
        }
        if selected.is_some() {
            return Err(invalid("ambiguous native Git universal slice"));
        }
        let scalar = if width == 20 { 4 } else { 8 };
        let offset = number(entry, 8, scalar, true)?;
        let length = number(entry, 8 + scalar, scalar, true)?;
        let file_length = file.metadata()?.len();
        if offset < 8 + (count * width) as u64
            || length < 32
            || offset
                .checked_add(length)
                .is_none_or(|end| end > file_length)
        {
            return Err(invalid("Git universal slice is outside the image"));
        }
        selected = Some((offset, length));
    }
    selected.ok_or_else(|| invalid("Git has no qualified native architecture slice"))
}
fn path(command: &[u8], minimum: usize, absolute: bool) -> io::Result<PathBuf> {
    let offset = number(command, 8, 4, false)? as usize;
    if offset < minimum {
        return Err(invalid("Git load-command name overlaps its header"));
    }
    let bytes = command
        .get(offset..)
        .ok_or_else(|| invalid("Git load-command name is outside its command"))?;
    let end = bytes
        .iter()
        .position(|b| *b == 0)
        .filter(|end| *end > 0 && *end <= 4096)
        .ok_or_else(|| invalid("Git load-command name is not a bounded string"))?;
    let text =
        std::str::from_utf8(&bytes[..end]).map_err(|_| invalid("Git runtime path is not UTF-8"))?;
    let result = PathBuf::from(text);
    // Relative and @rpath images require a separately qualified resolution policy.
    if absolute
        && (!result.is_absolute()
            || result
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir)))
    {
        return Err(invalid(
            "Git runtime closure requires absolute dependency paths",
        ));
    }
    Ok(result)
}
pub(super) fn dependencies(file: &File, expiry: Expiry) -> io::Result<Vec<PathBuf>> {
    let (offset, length) = slice(file, expiry)?;
    let header = read(file, offset, 32, expiry)?;
    if number(&header, 0, 4, false)? != 0xfeed_facf
        || number(&header, 4, 4, false)? != u64::from(CPU)
        || CPU == 0
    {
        return Err(invalid(
            "Git runtime image is not native little-endian Mach-O64",
        ));
    }
    let count = number(&header, 16, 4, false)? as usize;
    let size = number(&header, 20, 4, false)? as usize;
    if count > 512 || size > MAX_METADATA || 32 + size as u64 > length {
        return Err(invalid(
            "Git Mach-O load commands exceed the qualified profile",
        ));
    }
    let commands = read(file, offset + 32, size, expiry)?;
    let mut used = 0;
    let mut result = Vec::new();
    for _ in 0..count {
        let tail = commands
            .get(used..)
            .ok_or_else(|| invalid("Git load-command offset overflow"))?;
        let kind = number(tail, 0, 4, false)? as u32;
        let size = number(tail, 4, 4, false)? as usize;
        if size < 8 || !size.is_multiple_of(8) {
            return Err(invalid("Git load-command size is invalid"));
        }
        let command = tail
            .get(..size)
            .ok_or_else(|| invalid("Git load command is truncated"))?;
        match kind {
            0x0c | 0x20 | 0x8000_0018 | 0x8000_001f | 0x8000_0023 => {
                result.push(path(command, 24, true)?);
            }
            0x0e => result.push(path(command, 12, true)?),
            0x8000_001c => {
                // Validate this metadata but grant no search directory. Every
                // dependency must still name an absolute, individually pinned image.
                path(command, 12, false)?;
            }
            _ => (),
        }
        if result.len() > 64 {
            return Err(invalid("Git runtime dependency count exceeds 64"));
        }
        used += size;
    }
    if used != commands.len() {
        return Err(invalid(
            "Git Mach-O command count does not cover its metadata",
        ));
    }
    Ok(result)
}
