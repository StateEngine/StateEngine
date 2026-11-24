//! Read-only parser for Git's binary `.git/index` (v2/v3/v4) and `TREE` cache.
//!
//! Returns `None` for any unsupported index version, SHA-256 object format,
//! unmerged/assume-unchanged/skip-worktree/intent-to-add entry, symlink or
//! submodule entry, or malformed byte layout so the caller falls back to
//! `libgit2`.

#[derive(Clone, Copy)]
pub(super) struct Timestamp {
    pub(super) sec: u32,
    pub(super) nsec: u32,
}

pub(super) struct IndexEntry {
    pub(super) ctime: Timestamp,
    pub(super) mtime: Timestamp,
    #[cfg(unix)]
    pub(super) dev: u32,
    #[cfg(unix)]
    pub(super) ino: u32,
    #[cfg(unix)]
    pub(super) uid: u32,
    #[cfg(unix)]
    pub(super) gid: u32,
    #[cfg(unix)]
    pub(super) mode: u32,
    pub(super) file_size: u32,
    path_range: PathRange,
}

#[derive(Clone, Copy)]
enum PathRange {
    Raw(usize, usize),
    Arena(usize, usize),
}

pub(super) struct ParsedIndex {
    pub(super) entries: Vec<IndexEntry>,
    v4_arena: Vec<u8>,
    pub(super) root_tree_oid: Option<[u8; 20]>,
}

impl ParsedIndex {
    pub(super) fn path<'a>(&'a self, raw: &'a [u8], entry: &IndexEntry) -> Option<&'a str> {
        let bytes = match entry.path_range {
            PathRange::Raw(start, end) => raw.get(start..end)?,
            PathRange::Arena(start, end) => self.v4_arena.get(start..end)?,
        };
        std::str::from_utf8(bytes).ok()
    }
}

pub(super) fn parse_index(bytes: &[u8]) -> Option<ParsedIndex> {
    if bytes.len() < 32 || &bytes[0..4] != b"DIRC" {
        return None;
    }
    let version = read_u32(bytes, 4)?;
    if !matches!(version, 2..=4) {
        return None;
    }
    let count = read_u32(bytes, 8)? as usize;
    let body_end = bytes.len().checked_sub(20)?;
    if sha1_digest(&bytes[..body_end]) != bytes[body_end..] {
        return None;
    }
    let mut pos = 12usize;
    let mut entries = Vec::with_capacity(count.min(65_536));
    let mut v4_arena = Vec::new();
    let mut prev_path = Vec::<u8>::new();

    for _ in 0..count {
        let entry = parse_entry(
            bytes,
            body_end,
            version,
            &mut pos,
            &mut v4_arena,
            &mut prev_path,
        )?;
        entries.push(entry);
    }

    let root_tree_oid = parse_root_tree_oid(bytes, pos, body_end, count);
    Some(ParsedIndex {
        entries,
        v4_arena,
        root_tree_oid,
    })
}

fn parse_entry(
    bytes: &[u8],
    body_end: usize,
    version: u32,
    pos: &mut usize,
    v4_arena: &mut Vec<u8>,
    prev_path: &mut Vec<u8>,
) -> Option<IndexEntry> {
    let entry_start = *pos;
    if entry_start + 62 > body_end {
        return None;
    }
    let ctime = Timestamp {
        sec: read_u32(bytes, entry_start)?,
        nsec: read_u32(bytes, entry_start + 4)?,
    };
    let mtime = Timestamp {
        sec: read_u32(bytes, entry_start + 8)?,
        nsec: read_u32(bytes, entry_start + 12)?,
    };
    #[cfg(unix)]
    let dev = read_u32(bytes, entry_start + 16)?;
    #[cfg(unix)]
    let ino = read_u32(bytes, entry_start + 20)?;
    let mode = read_u32(bytes, entry_start + 24)?;
    #[cfg(unix)]
    let uid = read_u32(bytes, entry_start + 28)?;
    #[cfg(unix)]
    let gid = read_u32(bytes, entry_start + 32)?;
    let file_size = read_u32(bytes, entry_start + 36)?;
    let flags = read_u16(bytes, entry_start + 60)?;
    *pos = entry_start + 62;

    // Bail on unmerged (stage != 0), assume-unchanged, or non-regular-file entries.
    if (flags & 0x3000) != 0 || (flags & 0x8000) != 0 || (mode & 0o170000) != 0o100000 {
        return None;
    }
    if (flags & 0x4000) != 0 {
        if version < 3 || *pos + 2 > body_end {
            return None;
        }
        let ext_flags = read_u16(bytes, *pos)?;
        *pos += 2;
        // Bail on skip-worktree (0x4000) or intent-to-add (0x2000).
        if (ext_flags & 0x6000) != 0 {
            return None;
        }
    }

    let path_range = if version == 4 {
        parse_v4_path(bytes, body_end, pos, v4_arena, prev_path)?
    } else {
        parse_v2_path(bytes, body_end, entry_start, pos)?
    };

    Some(IndexEntry {
        ctime,
        mtime,
        #[cfg(unix)]
        dev,
        #[cfg(unix)]
        ino,
        #[cfg(unix)]
        uid,
        #[cfg(unix)]
        gid,
        #[cfg(unix)]
        mode,
        file_size,
        path_range,
    })
}

fn parse_v2_path(
    bytes: &[u8],
    body_end: usize,
    entry_start: usize,
    pos: &mut usize,
) -> Option<PathRange> {
    let nul = bytes[*pos..body_end].iter().position(|&b| b == 0)?;
    let path_start = *pos;
    let path_end = *pos + nul;
    validate_path(&bytes[path_start..path_end])?;
    *pos = path_end + 1;
    let pad = (8 - ((*pos - entry_start) % 8)) % 8;
    *pos = pos.checked_add(pad)?;
    if *pos > body_end {
        return None;
    }
    Some(PathRange::Raw(path_start, path_end))
}

fn parse_v4_path(
    bytes: &[u8],
    body_end: usize,
    pos: &mut usize,
    v4_arena: &mut Vec<u8>,
    prev_path: &mut Vec<u8>,
) -> Option<PathRange> {
    let mut strip = 0usize;
    loop {
        let byte = *bytes.get(*pos)?;
        *pos += 1;
        strip = strip
            .checked_shl(7)?
            .checked_add(usize::from(byte & 0x7f))?;
        if (byte & 0x80) == 0 {
            break;
        }
        strip = strip.checked_add(1)?;
    }
    let nul = bytes[*pos..body_end].iter().position(|&b| b == 0)?;
    let suffix = &bytes[*pos..*pos + nul];
    *pos += nul + 1;
    let keep = prev_path.len().checked_sub(strip)?;
    prev_path.truncate(keep);
    prev_path.extend_from_slice(suffix);
    validate_path(prev_path)?;
    let start = v4_arena.len();
    v4_arena.extend_from_slice(prev_path);
    Some(PathRange::Arena(start, v4_arena.len()))
}

fn validate_path(raw: &[u8]) -> Option<()> {
    let path = std::str::from_utf8(raw).ok()?;
    if path.is_empty() || path.contains('\\') || path.starts_with('/') {
        return None;
    }
    Some(())
}

fn parse_root_tree_oid(
    bytes: &[u8],
    mut pos: usize,
    body_end: usize,
    count: usize,
) -> Option<[u8; 20]> {
    while pos + 8 <= body_end {
        let sig = &bytes[pos..pos + 4];
        let ext_len = read_u32(bytes, pos + 4)? as usize;
        pos += 8;
        if pos + ext_len > body_end {
            break;
        }
        if sig == b"TREE" {
            let ext = &bytes[pos..pos + ext_len];
            if ext.first() != Some(&0) {
                return None;
            }
            let rest = &ext[1..];
            let sp = rest.iter().position(|&b| b == b' ')?;
            let entry_count = std::str::from_utf8(&rest[..sp]).ok()?.parse::<i64>().ok()?;
            if entry_count != count as i64 {
                return None;
            }
            let nl = rest[sp + 1..].iter().position(|&b| b == b'\n')?;
            let oid_start = sp + 1 + nl + 1;
            if oid_start + 20 > rest.len() {
                return None;
            }
            let mut oid = [0u8; 20];
            oid.copy_from_slice(&rest[oid_start..oid_start + 20]);
            return Some(oid);
        }
        pos += ext_len;
    }
    None
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let mut chunks = data.chunks_exact(64);
    for block in &mut chunks {
        if let Ok(block) = <&[u8; 64]>::try_from(block) {
            sha1_compress(&mut h, block);
        }
    }
    let rem = chunks.remainder();
    let mut tail = [0u8; 128];
    tail[..rem.len()].copy_from_slice(rem);
    tail[rem.len()] = 0x80;
    let total_len = if rem.len() < 56 { 64 } else { 128 };
    let bit_len = (data.len() as u64).wrapping_mul(8);
    tail[total_len - 8..total_len].copy_from_slice(&bit_len.to_be_bytes());
    let first: &[u8; 64] = tail[..64].try_into().unwrap_or(&[0u8; 64]);
    sha1_compress(&mut h, first);
    if total_len == 128 {
        let second: &[u8; 64] = tail[64..128].try_into().unwrap_or(&[0u8; 64]);
        sha1_compress(&mut h, second);
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn sha1_compress(h: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for (i, word) in w.iter_mut().take(16).enumerate() {
        *word = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *h;
    for (i, &wi) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999u32),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1u32),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdcu32),
            _ => (b ^ c ^ d, 0xca62_c1d6u32),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
}
