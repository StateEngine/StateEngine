//! The parallel cold builder. Up to eight workers read through the shared
//! custody and extract; one writer commits at most 500 files or 250 ms per
//! transaction, so readers can query every committed batch. Each worker
//! re-verifies its scan's custody after every claim, before handing the
//! claim's files to the writer, so no batch publishes an unverified read; a
//! custody failure stops the build and clears what it committed.
//!
//! Files are numbered by sorted path before reading, so import targets get
//! ids at once. Postings accumulate in memory as compact varints and are
//! written once, sorted, in chunked transactions when the build ends; until
//! then readers find committed files through `file_tok` (see [`super::read`]).
use super::{
    Store, history, varint,
    write::{self, FileRecord},
};
use crate::{
    IndexError, Result,
    custody::{GuardedRead, GuardedReads, IndexSourceRoot},
    extract::{
        self,
        covers::{self, CoverFile, CoverGraph},
        flags,
        imports::Resolver,
        tokens,
    },
    walk::{self, WalkOptions},
};
use rusqlite::{Connection, Transaction, params};
use std::{
    collections::HashMap,
    io,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender},
    },
    thread,
    time::{Duration, Instant},
};

const CLAIM: usize = 16;
const MAX_WORKERS: usize = 8;
const FINISH_CHUNK: usize = 4_096;

#[derive(Clone, Debug)]
pub struct BuildOptions {
    pub walk: WalkOptions,
    /// Zero picks `min(cores, 8)`.
    pub workers: usize,
    pub batch_files: usize,
    pub batch_time: Duration,
}

impl Default for BuildOptions {
    fn default() -> Self {
        Self {
            walk: WalkOptions::default(),
            workers: 0,
            batch_files: 500,
            batch_time: Duration::from_millis(250),
        }
    }
}

/// What one cold build saw, counted by outcome.
#[derive(Clone, Debug, Default)]
pub struct BuildReport {
    pub discovered: usize,
    pub indexed: usize,
    pub absent: usize,
    pub denied: usize,
    /// Files custody refused: links, devices, Windows short-name aliases.
    pub refused: usize,
    pub read_failed: usize,
    pub extract_failed: usize,
    pub binary: usize,
    pub minified: usize,
    pub walk_denied: u32,
    pub ignored: u32,
    pub links: u32,
    pub unnameable: u32,
    pub unreadable_ignore_files: u32,
    pub vanished_dirs: u32,
    pub unreadable_dirs: u32,
    pub refused_dirs: u32,
    pub tokens: usize,
    pub batches: usize,
    pub discovery_complete: bool,
    pub elapsed: Duration,
}

enum Outcome {
    Indexed(i64, Box<FileRecord>),
    Absent,
    Denied,
    Refused,
    ReadFailed,
    ScanFailed(io::Error),
}

impl Store {
    /// Replace the code index with a fresh build of `root`.
    pub fn cold_build(
        &mut self,
        root: &IndexSourceRoot,
        options: &BuildOptions,
    ) -> Result<BuildReport> {
        let discovery = walk::discover(root, &options.walk)?;
        self.cold_build_with_discovery(root, options, discovery)
    }

    /// Replace the code index with a fresh build using an already-completed discovery.
    pub fn cold_build_with_discovery(
        &mut self,
        root: &IndexSourceRoot,
        options: &BuildOptions,
        discovery: walk::Discovery,
    ) -> Result<BuildReport> {
        let started = Instant::now();
        let paths = &discovery.files;
        let resolver = Resolver::new(paths.iter().map(String::as_str));
        let ids: HashMap<&str, i64> = paths
            .iter()
            .zip(1i64..)
            .map(|(p, id)| (p.as_str(), id))
            .collect();
        clear_index(self.connection_mut())?;
        let workers = match options.workers {
            0 => thread::available_parallelism()
                .map_or(4, |n| n.get())
                .min(MAX_WORKERS),
            n => n.min(MAX_WORKERS),
        };
        let next = AtomicUsize::new(0);
        let (sender, receiver) = mpsc::sync_channel(256);
        let mut writer = ColdWriter::new(self.connection_mut(), options);
        let consumed = thread::scope(|scope| {
            for _ in 0..workers {
                let sender = sender.clone();
                let (next, resolver, ids) = (&next, &resolver, &ids);
                scope.spawn(move || work(root, paths, next, resolver, ids, sender));
            }
            drop(sender);
            writer.consume(receiver)
        });
        if let Some(error) = consumed? {
            // Lost custody: publish nothing further, and leave no partial
            // build looking current.
            drop(writer);
            clear_index(self.connection_mut())?;
            return Err(IndexError::Io(error));
        }
        writer.finish(discovery.complete)?;
        Ok(BuildReport {
            discovered: paths.len(),
            walk_denied: discovery.denied,
            ignored: discovery.ignored,
            links: discovery.links,
            unnameable: discovery.unnameable,
            unreadable_ignore_files: discovery.unreadable_ignore_files,
            vanished_dirs: discovery.vanished_dirs,
            unreadable_dirs: discovery.unreadable_dirs,
            refused_dirs: discovery.refused_dirs,
            discovery_complete: discovery.complete,
            elapsed: started.elapsed(),
            ..std::mem::take(&mut writer.report)
        })
    }
}

fn clear_index(conn: &mut Connection) -> Result<()> {
    let tx = conn.transaction()?;
    write::clear_index(&tx)?;
    tx.commit()?;
    Ok(())
}

fn work(
    root: &IndexSourceRoot,
    paths: &[String],
    next: &AtomicUsize,
    resolver: &Resolver,
    ids: &HashMap<&str, i64>,
    sender: SyncSender<Outcome>,
) {
    let mut outcomes = Vec::with_capacity(CLAIM);
    loop {
        let start = next.fetch_add(CLAIM, Ordering::Relaxed);
        if start >= paths.len() {
            return;
        }
        let verified = root.begin_reads().and_then(|mut reads| {
            for (path, id) in paths[start..(start + CLAIM).min(paths.len())]
                .iter()
                .zip(start as i64 + 1..)
            {
                // Extraction contains its own panics; this guards the rest of
                // the per-file path so one file can never take down the host.
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    read_one(&mut reads, path, id, resolver, ids)
                }))
                .unwrap_or(Outcome::ReadFailed);
                outcomes.push(outcome);
            }
            reads.finish()
        });
        if let Err(error) = verified {
            let _ = sender.send(Outcome::ScanFailed(error));
            return;
        }
        for outcome in outcomes.drain(..) {
            if sender.send(outcome).is_err() {
                return;
            }
        }
    }
}

fn read_one(
    reads: &mut GuardedReads<'_>,
    path: &str,
    id: i64,
    resolver: &Resolver,
    ids: &HashMap<&str, i64>,
) -> Outcome {
    match reads.read(path) {
        Ok(GuardedRead::Source(source)) => {
            let extracted = extract::extract(path, &source.bytes, source.prefix_only);
            let mut record = FileRecord::new(path, &source, extracted);
            let resolve = |s: &_| {
                resolver
                    .resolve(path, s)
                    .and_then(|t| ids.get(t.as_str()).copied())
            };
            record.targets = record.extracted.imports.iter().map(resolve).collect();
            Outcome::Indexed(id, Box::new(record))
        }
        Ok(GuardedRead::Absent) => Outcome::Absent,
        Ok(GuardedRead::Denied) => Outcome::Denied,
        Ok(GuardedRead::Refused) => Outcome::Refused,
        Err(_) => Outcome::ReadFailed,
    }
}

struct ColdWriter<'c> {
    conn: &'c mut Connection,
    batch_files: usize,
    batch_time: Duration,
    vocab: Vocab,
    covers: Vec<CoverFile>,
    report: BuildReport,
}

impl<'c> ColdWriter<'c> {
    fn new(conn: &'c mut Connection, options: &BuildOptions) -> Self {
        Self {
            conn,
            batch_files: options.batch_files.max(1),
            batch_time: options.batch_time,
            vocab: Vocab::default(),
            covers: Vec::new(),
            report: BuildReport::default(),
        }
    }

    /// Drain the workers, committing bounded batches. A custody failure
    /// reported by any worker stops at once, before another batch commits;
    /// dropping the receiver stops the other workers.
    fn consume(&mut self, receiver: Receiver<Outcome>) -> Result<Option<io::Error>> {
        let mut batch: Vec<(i64, Box<FileRecord>)> = Vec::new();
        let mut opened = Instant::now();
        loop {
            let wait = self.batch_time.saturating_sub(opened.elapsed());
            match receiver.recv_timeout(wait) {
                Ok(Outcome::Indexed(id, record)) => {
                    if batch.is_empty() {
                        opened = Instant::now();
                    }
                    batch.push((id, record));
                }
                Ok(Outcome::Absent) => self.report.absent += 1,
                Ok(Outcome::Denied) => self.report.denied += 1,
                Ok(Outcome::Refused) => self.report.refused += 1,
                Ok(Outcome::ReadFailed) => self.report.read_failed += 1,
                Ok(Outcome::ScanFailed(error)) => return Ok(Some(error)),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            if !batch.is_empty()
                && (batch.len() >= self.batch_files || opened.elapsed() >= self.batch_time)
            {
                self.flush(&mut batch)?;
                opened = Instant::now();
            }
        }
        if !batch.is_empty() {
            self.flush(&mut batch)?;
        }
        Ok(None)
    }

    fn flush(&mut self, batch: &mut Vec<(i64, Box<FileRecord>)>) -> Result<()> {
        let tx = self.conn.transaction()?;
        for (id, record) in batch.drain(..) {
            write_record(&tx, &mut self.vocab, id, &record)?;
            count(&mut self.report, record.extracted.flags);
            let mut targets: Vec<i64> = record.targets.iter().flatten().copied().collect();
            targets.sort_unstable();
            targets.dedup();
            self.covers.push(CoverFile {
                id,
                path: record.path,
                flags: record.extracted.flags,
                targets,
            });
        }
        self.vocab.publish(&tx)?;
        tx.commit()?;
        self.report.batches += 1;
        Ok(())
    }

    /// Publish postings, df, trigrams and covering tests in bounded
    /// transactions, then retire the cold watermark.
    fn finish(&mut self, complete: bool) -> Result<()> {
        write_postings_chunked(self.conn, &mut self.vocab.postings)?;
        write_grams_chunked(self.conn, &self.vocab.ids)?;
        let graph = MemoryGraph::new(&self.covers);
        for chunk in self.covers.chunks(FINISH_CHUNK) {
            let tx = self.conn.transaction()?;
            for file in chunk {
                write::insert_covers(&tx, &covers::covers_for(file, &graph)?)?;
            }
            tx.commit()?;
        }
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE imp SET target_file=NULL WHERE target_file IS NOT NULL AND target_file NOT IN (SELECT id FROM files)",
            [],
        )?;
        tx.execute(
            "UPDATE meta SET discovery_complete=?1 WHERE singleton=1",
            [complete],
        )?;
        history::record_rebuild(&tx, self.covers.len())?;
        write::set_state(&tx, &serde_json::json!({}))?;
        tx.commit()?;
        self.report.tokens = self.vocab.ids.len();
        self.conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        Ok(())
    }
}

fn count(report: &mut BuildReport, file_flags: u32) {
    report.indexed += 1;
    report.extract_failed += usize::from(file_flags & flags::EXTRACT_FAILED != 0);
    report.binary += usize::from(file_flags & flags::BINARY != 0);
    report.minified += usize::from(file_flags & flags::MINIFIED != 0);
}

fn write_record(
    tx: &Transaction<'_>,
    vocab: &mut Vocab,
    id: i64,
    record: &FileRecord,
) -> Result<()> {
    write::upsert_file(tx, Some(id), record)?;
    let mut pairs = Vec::with_capacity(record.extracted.tokens.len());
    for (token, tf) in &record.extracted.tokens {
        let tok = vocab.intern(token);
        pairs.push((tok, *tf));
        if let Some(buffer) = vocab.postings.get_mut((tok - 1) as usize) {
            varint::put(buffer, id as u64);
            varint::put(buffer, u64::from(*tf));
        }
    }
    pairs.sort_unstable();
    tx.prepare_cached("INSERT INTO file_tok(file, toks) VALUES (?1, ?2)")?
        .execute(params![id, varint::encode_pairs(&pairs)?])?;
    write::insert_symbols(tx, id, record, |name| Ok(vocab.intern(name)))?;
    write::replace_imports(tx, id, record)
}

/// The build's vocabulary. Ids are assigned as tokens are first seen; each
/// batch inserts its new rows sorted by token, which keeps the token indexes
/// densely packed.
#[derive(Default)]
struct Vocab {
    ids: HashMap<String, i64>,
    /// Per vocab id (index `id - 1`): unsorted varint `(file, tf)` pairs.
    postings: Vec<Vec<u8>>,
    fresh: Vec<(String, i64)>,
}

impl Vocab {
    fn intern(&mut self, token: &str) -> i64 {
        if let Some(id) = self.ids.get(token) {
            return *id;
        }
        let id = self.ids.len() as i64 + 1;
        self.ids.insert(token.to_owned(), id);
        self.postings.push(Vec::new());
        self.fresh.push((token.to_owned(), id));
        id
    }

    fn publish(&mut self, tx: &Transaction<'_>) -> Result<()> {
        self.fresh.sort_unstable();
        let mut insert =
            tx.prepare_cached("INSERT INTO vocab(id, tok, compact, df) VALUES (?1, ?2, ?3, 0)")?;
        for (token, id) in self.fresh.drain(..) {
            insert.execute(params![id, token, tokens::compact(&token)])?;
            write::index_new_token(tx, id, &token, false)?;
        }
        Ok(())
    }
}

fn write_postings_chunked(conn: &mut Connection, postings: &mut [Vec<u8>]) -> Result<()> {
    for (i, chunk) in postings.chunks_mut(FINISH_CHUNK).enumerate() {
        let tx = conn.transaction()?;
        let mut ins = tx.prepare_cached("INSERT INTO vocab_post(tok, postings) VALUES (?1, ?2)")?;
        let mut df = tx.prepare_cached("UPDATE vocab SET df=?2 WHERE id=?1")?;
        for (off, raw) in chunk.iter_mut().enumerate() {
            let (mut pairs, mut pos) = (Vec::new(), 0);
            while pos < raw.len() {
                let file = varint::get(raw, &mut pos)? as i64;
                let tf = u32::try_from(varint::get(raw, &mut pos)?).unwrap_or(u32::MAX);
                pairs.push((file, tf));
            }
            *raw = Vec::new();
            pairs.sort_unstable();
            pairs.dedup_by_key(|pair| pair.0);
            if !pairs.is_empty() {
                let tok = (i * FINISH_CHUNK + off) as i64 + 1;
                ins.execute(params![tok, varint::encode_pairs(&pairs)?])?;
                df.execute(params![tok, pairs.len() as i64])?;
            }
        }
        drop((ins, df));
        tx.commit()?;
    }
    Ok(())
}

fn write_grams_chunked(conn: &mut Connection, vocab: &HashMap<String, i64>) -> Result<()> {
    let mut grams: HashMap<u32, Vec<i64>> = HashMap::new();
    for (token, id) in vocab.iter().filter(|(t, _)| tokens::is_gram_token(t)) {
        for gram in tokens::trigrams(token) {
            grams.entry(gram).or_default().push(*id);
        }
    }
    // Key order fills the WITHOUT ROWID pages densely.
    let mut grams: Vec<_> = grams.into_iter().collect();
    grams.sort_unstable_by_key(|(gram, _)| *gram);
    for chunk in grams.chunks_mut(FINISH_CHUNK) {
        let tx = conn.transaction()?;
        let mut ins = tx.prepare_cached("INSERT INTO gram(g, toks) VALUES (?1, ?2)")?;
        for (gram, ids) in chunk.iter_mut() {
            ids.sort_unstable();
            ids.dedup();
            ins.execute(params![*gram, varint::encode_ids(ids)?])?;
            *ids = Vec::new();
        }
        drop(ins);
        tx.commit()?;
    }
    Ok(())
}

/// The in-memory file graph of one cold build.
struct MemoryGraph<'a> {
    files: HashMap<i64, &'a CoverFile>,
    paths: HashMap<&'a str, i64>,
}

impl<'a> MemoryGraph<'a> {
    fn new(files: &'a [CoverFile]) -> Self {
        Self {
            files: files.iter().map(|file| (file.id, file)).collect(),
            paths: files
                .iter()
                .map(|file| (file.path.as_str(), file.id))
                .collect(),
        }
    }
}

impl CoverGraph for MemoryGraph<'_> {
    fn file(&self, id: i64) -> Result<Option<CoverFile>> {
        Ok(self.files.get(&id).map(|file| (*file).clone()))
    }

    fn id_of(&self, path: &str) -> Result<Option<i64>> {
        Ok(self.paths.get(path).copied())
    }
}
