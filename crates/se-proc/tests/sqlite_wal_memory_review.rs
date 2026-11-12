//! A short WAL frame must initialize the rest of a database-sized cache page.
//! This binary has one test: SQLite's global page allocator is configured only
//! while no connection exists, and restored after every connection is closed.
use rusqlite::{Connection, ffi};
use std::{ffi::c_int, fs, path::Path};
#[path = "../../test-support/directory.rs"]
mod directory;
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn checksum(bytes: &[u8], mut sum: [u32; 2]) -> [u32; 2] {
    for chunk in bytes.chunks_exact(8) {
        let a = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let b = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
        sum[0] = sum[0].wrapping_add(a).wrapping_add(sum[1]);
        sum[1] = sum[1].wrapping_add(b).wrapping_add(sum[0]);
    }
    sum
}
fn words(out: &mut Vec<u8>, values: &[u32]) {
    for value in values {
        out.extend_from_slice(&value.to_be_bytes());
    }
}
fn short_wal(path: &Path) -> Check {
    let mut header = Vec::new();
    // Little-endian WAL checksums; all on-disk header words are big-endian.
    words(&mut header, &[0x377f0682, 3_007_000, 512, 0, 19, 23]);
    let initial = checksum(&header, [0, 0]);
    words(&mut header, &initial);
    let mut frame = Vec::new();
    words(&mut frame, &[2, 2, 19, 23]);
    let mut page = [0u8; 512];
    page[..10].copy_from_slice(&[13, 0, 0, 0, 1, 0, 100, 0, 0, 100]);
    // One table-leaf cell at 100: 3003-byte record, rowid 1, three-byte
    // record header, and serial type 6012 (a 3000-byte BLOB). The declared
    // payload fits a 4096-byte DB page, but only its prefix exists in this WAL.
    page[100..106].copy_from_slice(&[0x97, 0x3b, 1, 3, 0xae, 0x7c]);
    page[106..].fill(0x5a);
    let sum = checksum(&page, checksum(&frame[..8], initial));
    words(&mut frame, &sum);
    header.extend(frame);
    header.extend(page);
    fs::write(path, header)?;
    Ok(())
}

struct SeededCache {
    memory: Vec<u64>,
}
impl SeededCache {
    fn install() -> Check<Self> {
        let mut overhead: c_int = 0;
        // SAFETY: this test binary has one test and all fixture connections
        // have closed. HDRSZ writes one live integer; no allocator is active.
        unsafe {
            assert_eq!(ffi::sqlite3_shutdown(), ffi::SQLITE_OK);
            assert_eq!(
                ffi::sqlite3_config(ffi::SQLITE_CONFIG_PCACHE_HDRSZ, &mut overhead),
                ffi::SQLITE_OK
            );
        }
        let slot = (4096 + usize::try_from(overhead)?).div_ceil(8) * 8;
        let mut cache = Self {
            memory: vec![0xa5a5_a5a5_a5a5_a5a5; slot / 8 * 32],
        };
        // SAFETY: u64 gives the required alignment; 32 complete slots remain
        // retained through SQLite shutdown in Drop. No connection is open yet.
        let configured = unsafe {
            ffi::sqlite3_config(
                ffi::SQLITE_CONFIG_PAGECACHE,
                cache.memory.as_mut_ptr().cast::<std::ffi::c_void>(),
                c_int::try_from(slot)?,
                32_i32,
            )
        };
        assert_eq!(configured, ffi::SQLITE_OK);
        Ok(cache)
    }
}
impl Drop for SeededCache {
    fn drop(&mut self) {
        // SAFETY: the connection was declared after this guard and therefore
        // closes first, including unwinding. If shutdown nevertheless refuses,
        // retain memory rather than leave SQLite with a dangling allocator.
        let closed = unsafe { ffi::sqlite3_shutdown() };
        if closed != ffi::SQLITE_OK {
            std::mem::forget(std::mem::take(&mut self.memory));
            eprintln!("SQLite allocator retained after incomplete shutdown: {closed}");
            return;
        }
        // SAFETY: successful shutdown above leaves no outstanding allocation.
        // A null buffer restores SQLite's default allocation configuration.
        let reset = unsafe {
            ffi::sqlite3_config(
                ffi::SQLITE_CONFIG_PAGECACHE,
                std::ptr::null_mut::<std::ffi::c_void>(),
                0_i32,
                0_i32,
            )
        };
        assert_eq!(reset, ffi::SQLITE_OK);
    }
}

#[test]
fn shorter_wal_frame_cannot_disclose_seeded_page_cache_memory() -> Check {
    let root = directory::private_directory()?;
    let path = root.join("memory.db");
    {
        let db = Connection::open(&path)?;
        db.execute_batch(
            "PRAGMA page_size=4096; PRAGMA journal_mode=WAL;
             CREATE TABLE payload(b BLOB);
             INSERT INTO payload VALUES(zeroblob(3000));
             PRAGMA wal_checkpoint(TRUNCATE);",
        )?;
        let page: i64 = db.query_row(
            "SELECT rootpage FROM sqlite_schema WHERE name='payload'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(page, 2, "fixture table was not on the crafted frame page");
    }
    short_wal(&root.join("memory.db-wal"))?;
    let cache = SeededCache::install()?;
    let db = Connection::open(&path)?;
    let (length, prefix, tail): (i64, Vec<u8>, Vec<u8>) = db.query_row(
        "SELECT length(b), substr(b,1,4), substr(b,600,64) FROM payload",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(length, 3000);
    assert_eq!(prefix, vec![0x5a; 4], "crafted WAL was not consumed");
    assert_eq!(tail.len(), 64);
    assert!(
        tail.iter().all(|byte| *byte == 0),
        "short WAL frame exposed page-cache bytes; seeded marker observed: {}",
        tail.iter().all(|byte| *byte == 0xa5)
    );
    drop(db);
    drop(cache);
    Ok(())
}
