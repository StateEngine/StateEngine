//! Lazy compaction: the single writer folds `post_delta` into `vocab_post`
//! and `vocab.df`, and `gram_delta` into `gram`, a bounded number of tokens
//! per transaction in id order.
use super::{Store, varint};
use crate::Result;
use rusqlite::{OptionalExtension, Transaction, params};
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub struct CompactPolicy {
    /// Compact once `post_delta` holds more rows than this.
    pub max_delta_rows: u64,
    /// ...or once the writer is idle this long with more than `idle_rows`.
    pub idle_after: Duration,
    pub idle_rows: u64,
    pub tokens_per_transaction: usize,
    /// Tokens in more files than this wait for `hot_min_deltas` changes.
    pub hot_df: i64,
    pub hot_min_deltas: usize,
}

impl Default for CompactPolicy {
    fn default() -> Self {
        Self {
            max_delta_rows: 16_384,
            idle_after: Duration::from_secs(2),
            idle_rows: 2_000,
            tokens_per_transaction: 500,
            hot_df: 500,
            hot_min_deltas: 8,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompactReport {
    pub tokens: usize,
    pub deferred: usize,
    pub grams: usize,
    pub transactions: usize,
}

impl Store {
    /// Whether the policy calls for compaction after `idle` without writes.
    /// Only rows a non-forced `compact_deltas` would fold count, so deferred
    /// hot tokens can never keep this true while compaction folds nothing.
    pub fn compaction_due(&self, policy: &CompactPolicy, idle: Duration) -> Result<bool> {
        let rows: i64 = self.connection().query_row(
            "SELECT coalesce(sum(d.n), 0) FROM
               (SELECT tok, count(*) AS n FROM post_delta GROUP BY tok) d
               LEFT JOIN vocab v ON v.id = d.tok
             WHERE coalesce(v.df, 0) <= ?1 OR d.n >= ?2",
            params![
                policy.hot_df,
                i64::try_from(policy.hot_min_deltas).unwrap_or(i64::MAX)
            ],
            |row| row.get(0),
        )?;
        let rows = rows.max(0) as u64;
        Ok(rows > policy.max_delta_rows || (idle >= policy.idle_after && rows > policy.idle_rows))
    }

    /// Fold deltas into the base tables. `force` also folds deferred hot
    /// tokens, leaving both delta tables empty.
    pub fn compact_deltas(&mut self, policy: &CompactPolicy, force: bool) -> Result<CompactReport> {
        let mut report = CompactReport::default();
        let mut cursor = 0i64;
        let per_transaction = policy.tokens_per_transaction.max(1);
        loop {
            let tx = self.connection_mut().transaction()?;
            let tokens = next_keys(
                &tx,
                "SELECT DISTINCT tok FROM post_delta WHERE tok > ?1 ORDER BY tok LIMIT ?2",
                cursor,
                per_transaction,
            )?;
            let Some(last) = tokens.last().copied() else {
                break;
            };
            for tok in tokens {
                if fold_token(&tx, tok, policy, force)? {
                    report.tokens += 1;
                } else {
                    report.deferred += 1;
                }
            }
            tx.commit()?;
            report.transactions += 1;
            cursor = last;
        }
        cursor = i64::MIN;
        loop {
            let tx = self.connection_mut().transaction()?;
            let grams = next_keys(
                &tx,
                "SELECT DISTINCT g FROM gram_delta WHERE g > ?1 ORDER BY g LIMIT ?2",
                cursor,
                per_transaction,
            )?;
            let Some(last) = grams.last().copied() else {
                break;
            };
            for gram in grams {
                fold_gram(&tx, gram)?;
                report.grams += 1;
            }
            tx.commit()?;
            report.transactions += 1;
            cursor = last;
        }
        Ok(report)
    }
}

fn next_keys(tx: &Transaction<'_>, sql: &str, after: i64, limit: usize) -> Result<Vec<i64>> {
    let mut select = tx.prepare_cached(sql)?;
    let rows = select.query_map(params![after, limit as i64], |row| row.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Merge one token's deltas into its base postings. `false` when deferred.
fn fold_token(tx: &Transaction<'_>, tok: i64, policy: &CompactPolicy, force: bool) -> Result<bool> {
    let mut select =
        tx.prepare_cached("SELECT file, tf FROM post_delta WHERE tok=?1 ORDER BY file")?;
    let deltas = select
        .query_map([tok], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let df: i64 = tx
        .prepare_cached("SELECT df FROM vocab WHERE id=?1")?
        .query_row([tok], |row| row.get(0))
        .optional()?
        .unwrap_or(0);
    if !force && df > policy.hot_df && deltas.len() < policy.hot_min_deltas {
        return Ok(false);
    }
    let base = super::read::base_postings(tx, tok)?;
    let merged = super::read::apply_deltas(base, &deltas);
    if merged.is_empty() {
        tx.prepare_cached("DELETE FROM vocab_post WHERE tok=?1")?
            .execute([tok])?;
    } else {
        tx.prepare_cached("INSERT OR REPLACE INTO vocab_post(tok, postings) VALUES (?1, ?2)")?
            .execute(params![tok, varint::encode_pairs(&merged)?])?;
    }
    tx.prepare_cached("UPDATE vocab SET df=?2 WHERE id=?1")?
        .execute(params![tok, merged.len() as i64])?;
    tx.prepare_cached("DELETE FROM post_delta WHERE tok=?1")?
        .execute([tok])?;
    Ok(true)
}

fn fold_gram(tx: &Transaction<'_>, gram: i64) -> Result<()> {
    let mut ids = super::read::gram_base(tx, gram)?;
    let mut select = tx.prepare_cached("SELECT tok FROM gram_delta WHERE g=?1")?;
    for id in select.query_map([gram], |row| row.get::<_, i64>(0))? {
        ids.push(id?);
    }
    ids.sort_unstable();
    ids.dedup();
    tx.prepare_cached("INSERT OR REPLACE INTO gram(g, toks) VALUES (?1, ?2)")?
        .execute(params![gram, varint::encode_ids(&ids)?])?;
    tx.prepare_cached("DELETE FROM gram_delta WHERE g=?1")?
        .execute([gram])?;
    Ok(())
}
