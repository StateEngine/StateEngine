//! Bounded ELF dependency discovery for the closed native helper. Libraries are
//! granted by retained inode, never by a broad system-directory permission.
use super::*;
use std::{fs::File, os::unix::fs::FileExt, path::PathBuf};
fn bytes(file: &File, offset: u64, length: usize) -> io::Result<Vec<u8>> {
    if length > 65_536 {
        return Err(invalid("Git ELF metadata exceeds its bounded profile"));
    }
    let mut out = vec![0; length];
    file.read_exact_at(&mut out, offset)?;
    Ok(out)
}
fn number(bytes: &[u8], offset: usize, size: usize) -> io::Result<u64> {
    let slice = bytes
        .get(offset..offset + size)
        .ok_or_else(|| invalid("truncated Git ELF metadata"))?;
    let mut value = [0; 8];
    value[..size].copy_from_slice(slice);
    Ok(u64::from_le_bytes(value))
}
fn string(bytes: &[u8], offset: usize) -> io::Result<String> {
    let tail = bytes
        .get(offset..)
        .ok_or_else(|| invalid("invalid Git ELF string offset"))?;
    let end = tail
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| invalid("unterminated Git ELF string"))?;
    if end > 4096 {
        return Err(invalid("Git ELF dependency name exceeds its bound"));
    }
    std::str::from_utf8(&tail[..end])
        .map(str::to_owned)
        .map_err(|_| invalid("non-UTF8 Git ELF dependency"))
}
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(super) fn dependencies(path: &Path) -> io::Result<Vec<PathBuf>> {
    let file = File::open(path)?;
    let h = bytes(&file, 0, 64)?;
    if h.get(..6) != Some(b"\x7fELF\x02\x01") {
        return Err(invalid(
            "Git helper requires a native little-endian ELF64 image",
        ));
    }
    let offset = number(&h, 32, 8)?;
    let width = number(&h, 54, 2)? as usize;
    let count = number(&h, 56, 2)? as usize;
    if width != 56 || count > 64 {
        return Err(invalid("Git ELF program-header bound exceeded"));
    }
    let headers = bytes(&file, offset, width * count)?;
    let mut interpreter = None;
    let mut dynamic = Vec::new();
    for p in headers.chunks_exact(width) {
        match number(p, 0, 4)? {
            2 => {
                dynamic = bytes(
                    &file,
                    number(p, 8, 8)?,
                    number(p, 32, 8)?
                        .try_into()
                        .map_err(|_| invalid("Git ELF dynamic size overflow"))?,
                )?
            }
            3 => {
                interpreter = Some(PathBuf::from(string(
                    &bytes(&file, number(p, 8, 8)?, number(p, 32, 8)? as usize)?,
                    0,
                )?))
            }
            _ => (),
        }
    }
    let mut table = None;
    let mut size = None;
    let mut needed = Vec::new();
    for d in dynamic.chunks_exact(16) {
        let value = number(d, 8, 8)?;
        match number(d, 0, 8)? {
            0 => break,
            1 => {
                if needed.len() == 32 {
                    return Err(invalid("Git ELF dependency count exceeds 32"));
                }
                needed.push(value);
            }
            5 => table = Some(value),
            10 => size = Some(value),
            // Non-system search paths require a separately qualified helper.
            15 | 29 => {
                return Err(invalid(
                    "Git ELF custom library search paths are not qualified",
                ));
            }
            _ => (),
        }
    }
    let mut result = interpreter.into_iter().collect::<Vec<_>>();
    if needed.is_empty() {
        return Ok(result);
    }
    let address = table.ok_or_else(|| invalid("Git ELF has no dynamic string table"))?;
    let size = size.ok_or_else(|| invalid("Git ELF has no dynamic string-table size"))?;
    let mut table_offset = None;
    for p in headers.chunks_exact(width) {
        if number(p, 0, 4)? == 1 {
            let start = number(p, 16, 8)?;
            let length = number(p, 32, 8)?;
            if address >= start && address - start <= length && size <= length - (address - start) {
                table_offset = Some(
                    number(p, 8, 8)?
                        .checked_add(address - start)
                        .ok_or_else(|| invalid("Git ELF string offset overflow"))?,
                );
            }
        }
    }
    let strings = bytes(
        &file,
        table_offset.ok_or_else(|| invalid("Git ELF strings are outside file segments"))?,
        size.try_into()
            .map_err(|_| invalid("Git ELF string size overflow"))?,
    )?;
    for offset in needed {
        let name = string(
            &strings,
            offset
                .try_into()
                .map_err(|_| invalid("Git ELF name offset overflow"))?,
        )?;
        if name.is_empty() || name.contains('/') {
            return Err(invalid("Git ELF dependency must be a system library name"));
        }
        #[cfg(target_arch = "x86_64")]
        const MULTIARCH: &str = "x86_64-linux-gnu";
        #[cfg(target_arch = "aarch64")]
        const MULTIARCH: &str = "aarch64-linux-gnu";
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        const MULTIARCH: &str = "unsupported";
        let mut found = None;
        for directory in [
            format!("/lib/{MULTIARCH}"),
            format!("/usr/lib/{MULTIARCH}"),
            "/lib64".into(),
            "/usr/lib64".into(),
            "/lib".into(),
            "/usr/lib".into(),
        ] {
            let candidate = Path::new(&directory).join(&name);
            match candidate.canonicalize() {
                Ok(path) => {
                    found = Some(path);
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(e) => return Err(e),
            }
        }
        result.push(found.ok_or_else(|| {
            invalid("Git ELF dependency is outside qualified system library paths")
        })?);
    }
    Ok(result)
}
