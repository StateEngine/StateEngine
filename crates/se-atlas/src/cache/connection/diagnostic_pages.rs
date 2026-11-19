//! Probe-only WAL-frame attribution; never part of the product branch.
use rusqlite::Connection;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
static START: OnceLock<Instant> = OnceLock::new();
static SAMPLES: AtomicUsize = AtomicUsize::new(0);

pub(super) fn should_sample() -> bool {
    START.get_or_init(Instant::now).elapsed() >= Duration::from_secs(60)
        && SAMPLES.fetch_add(1, Ordering::Relaxed) < 8
}

pub(super) fn sample(db: &Connection, path: &Path, before: u64) -> Result<String, String> {
    let wal_path = path.with_file_name("atlas.db-wal");
    let mut wal = File::open(wal_path).map_err(|e| format!("open wal: {e}"))?;
    let end = wal.metadata().map_err(|e| format!("stat wal: {e}"))?.len();
    if end < 32 {
        return Err(format!("wal too short: {end}"));
    }
    let mut header = [0; 32];
    wal.read_exact(&mut header)
        .map_err(|e| format!("read header: {e}"))?;
    let magic = u32::from_be_bytes(header[..4].try_into().map_err(|_| "magic length")?);
    let page_size = u32::from_be_bytes(header[8..12].try_into().map_err(|_| "page size length")?);
    if !matches!(magic, 0x377f0682 | 0x377f0683) || page_size != 4096 {
        return Err(format!(
            "unexpected wal header magic={magic:x} page_size={page_size}"
        ));
    }
    let start = if before < 32 || before > end {
        32
    } else {
        before
    };
    let stride = u64::from(page_size) + 24;
    if (start - 32) % stride != 0 || (end - start) % stride != 0 {
        return Err(format!(
            "unaligned wal offsets before={before} start={start} end={end}"
        ));
    }
    let mut pages = Vec::new();
    let mut offset = start;
    while offset < end {
        wal.seek(SeekFrom::Start(offset))
            .map_err(|e| format!("seek: {e}"))?;
        let mut frame = [0; 24];
        wal.read_exact(&mut frame)
            .map_err(|e| format!("read frame: {e}"))?;
        pages.push(u32::from_be_bytes(
            frame[..4].try_into().map_err(|_| "frame length")?,
        ));
        offset += stride;
    }
    let mut mapping = HashMap::new();
    let mut statement = db
        .prepare("SELECT pageno,name FROM dbstat")
        .map_err(|e| format!("prepare dbstat: {e}"))?;
    let mut rows = statement
        .query([])
        .map_err(|e| format!("query dbstat: {e}"))?;
    while let Some(row) = rows.next().map_err(|e| format!("dbstat row: {e}"))? {
        if mapping.len() >= 20_000 {
            return Err("dbstat page map exceeds 20000 pages".into());
        }
        let page: u32 = row.get(0).map_err(|e| format!("page number: {e}"))?;
        let name: String = row.get(1).map_err(|e| format!("structure name: {e}"))?;
        mapping.insert(page, name);
    }
    let mut groups = BTreeMap::<String, u64>::new();
    let unique = pages.iter().copied().collect::<HashSet<_>>().len();
    for page in &pages {
        *groups
            .entry(
                mapping
                    .get(page)
                    .cloned()
                    .unwrap_or_else(|| "<unmapped>".into()),
            )
            .or_default() += 1;
    }
    Ok(format!(
        "before={before} after={end} frames={} unique_pages={unique} page_map={} groups={groups:?}",
        pages.len(),
        mapping.len()
    ))
}
