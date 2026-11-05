//! Unknown bytes and confirmed absence never share an update path. Call within
//! one finite cache write, after root-validated source observation by the host.
use super::*;
use crate::{cache::write, lifecycle::*, model::*, scope::Scope};
use rusqlite::{OptionalExtension, params};
use se_types::code::AtlasText;

type Previous = (i64, Option<i64>, bool, Option<Vec<u8>>);
pub enum UnparsedObservation<'a> {
    Hashed {
        identity: &'a FileIdentity,
        content_hash: ContentHash,
        cold: bool,
        reason: CoverageReason,
    },
    Deferred {
        identity: &'a FileIdentity,
        reason: CoverageReason,
    },
    Failed(&'a se_types::ErrorBody),
}
/// Preserve the last good semantic baseline without inventing a content hash,
/// zero-byte file or code edit when a source read could not observe the bytes.
pub fn unparsed(
    sql: &SqlView<'_>,
    scope: &Scope,
    path: &RelativePath,
    language: Option<Language>,
    observation: UnparsedObservation<'_>,
    serial: u64,
) -> AtlasResult<Generation> {
    let file = scope.file_id(path);
    let previous: Option<Previous> = sql
        .prepare(
            "SELECT id,last_good_generation,coverage_json='\"Indexed\"',indexed_hash FROM files WHERE key=?1",
        )?
        .query_row([file.0.as_slice()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .optional()
        .map_err(cache_error)?;
    let generation = unsigned(
        sql,
        "SELECT index_generation+1 FROM meta WHERE singleton=1",
        [],
    )?;
    let (identity, observed_hash, reason, diagnostic, cold) = match observation {
        UnparsedObservation::Hashed {
            identity,
            content_hash,
            cold,
            reason,
        } => (Some(identity), Some(content_hash), reason, None, cold),
        UnparsedObservation::Deferred { identity, reason } => {
            (Some(identity), None, reason, None, true)
        }
        UnparsedObservation::Failed(error) => (
            None,
            None,
            CoverageReason::ReadFailure,
            Some(error.clone()),
            true,
        ),
    };
    if let Some(current) = observed_hash
        && !cold
    {
        batch::observe_file(sql, file, path)?;
        let prior = previous
            .as_ref()
            .and_then(|p| p.3.as_ref())
            .map(|bytes| {
                bytes
                    .as_slice()
                    .try_into()
                    .map(ContentHash)
                    .map_err(|_| cache_error("invalid indexed hash"))
            })
            .transpose()?;
        if prior != Some(current) {
            batch::stage(
                sql,
                diff::Fact {
                    file,
                    symbol: None,
                    path: path.clone(),
                    span: None,
                    kind: ChangeKind::FileOnly,
                    previous: prior,
                    current: Some(current),
                    baseline_reset: false,
                },
            )?;
        }
    }
    let baseline = previous.as_ref().and_then(|p| p.1);
    let coverage = if let Some(baseline) = baseline {
        FileCoverage::Stale {
            reason,
            last_good_generation: Generation(u64::try_from(baseline).map_err(cache_error)?),
            observed_hash,
            diagnostic,
        }
    } else if let Some(error) = diagnostic {
        FileCoverage::Failed { error }
    } else {
        FileCoverage::Deferred { reason }
    };
    let identity_bytes = identity
        .map(serde_json::to_vec)
        .transpose()
        .map_err(cache_error)?;
    if previous.is_some() {
        execute(
            sql,
            "UPDATE files SET observed_hash=?6,bytes=?2,identity=?3,coverage_json=?4,last_code_generation=?5 WHERE key=?1",
            params![
                file.0.as_slice(),
                identity.map(|id| n(id.size)),
                identity_bytes,
                json(&coverage)?,
                n(generation),
                observed_hash.as_ref().map(|hash| hash.0.as_slice())
            ],
        )?;
    } else {
        execute(
            sql,
            "INSERT INTO files(key,path,path_key,language,indexed_hash,observed_hash,bytes,identity,coverage_json,last_good_generation,last_code_generation,last_author_generation,baseline_reset) VALUES(?1,?2,?2,?3,NULL,?8,?4,?5,?6,NULL,?7,0,0)",
            params![
                file.0.as_slice(),
                path.as_str(),
                language.map(|l| format!("{l:?}")),
                identity.map(|id| n(id.size)),
                identity_bytes,
                json(&coverage)?,
                n(generation),
                observed_hash.as_ref().map(|hash| hash.0.as_slice())
            ],
        )?;
    }
    if let Some((row, _, was_indexed, _)) = previous {
        if was_indexed {
            file::invalidate(sql, row, serial)?;
        }
        crate::cache::reference_counts::outgoing(sql, row)?;
        execute(
            sql,
            "UPDATE refs SET accuracy='NameOnly',target=NULL WHERE file=?1",
            [row],
        )?;
        execute(
            sql,
            "UPDATE imports SET target_symbol=NULL,resolution='NameOnly' WHERE file=?1",
            [row],
        )?;
    }
    advance(sql, generation, serial)?;
    Ok(Generation(generation))
}

/// A no-follow source open must have independently confirmed absence immediately
/// before this transaction. Read errors must call unparsed instead.
pub fn removed(
    sql: &SqlView<'_>,
    scope: &Scope,
    path: &RelativePath,
    cold: bool,
    serial: u64,
) -> AtlasResult<bool> {
    let file = scope.file_id(path);
    let previous: Option<(i64, Option<Vec<u8>>, String)> = sql
        .prepare("SELECT id,indexed_hash,coverage_json FROM files WHERE key=?1")?
        .query_row([file.0.as_slice()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .optional()
        .map_err(cache_error)?;
    let Some((row, hash, coverage)) = previous else {
        return Ok(false);
    };
    let hash = hash
        .map(|v| {
            v.try_into()
                .map(ContentHash)
                .map_err(|_| cache_error("invalid indexed hash"))
        })
        .transpose()?;
    if !cold {
        batch::observe_file(sql, file, path)?;
        diff::retire(
            sql,
            row,
            file,
            path,
            diff::Baseline {
                hash,
                reset: coverage != "\"Indexed\"",
                cold: false,
            },
            |fact| batch::stage(sql, fact),
        )?;
    }
    queue_candidates(sql, path, serial)?;
    file::invalidate(sql, row, serial)?;
    write::delete_file(sql, file)?;
    let generation = unsigned(
        sql,
        "SELECT index_generation+1 FROM meta WHERE singleton=1",
        [],
    )?;
    advance(sql, generation, serial)?;
    Ok(true)
}
/// Retire a deliberately excluded file without claiming its source was removed.
/// The caller must establish the current ignore policy before this transaction.
/// Candidate importers are queued before deleting their former target, including
/// unresolved ambiguous candidates that have no target_file binding yet.
pub fn excluded(
    sql: &SqlView<'_>,
    scope: &Scope,
    path: &RelativePath,
    serial: u64,
) -> AtlasResult<bool> {
    let file = scope.file_id(path);
    let row: Option<i64> = sql
        .prepare("SELECT id FROM files WHERE key=?1")?
        .query_row([file.0.as_slice()], |r| r.get(0))
        .optional()
        .map_err(cache_error)?;
    let Some(row) = row else { return Ok(false) };
    queue_candidates(sql, path, serial)?;
    file::invalidate(sql, row, serial)?;
    write::delete_file(sql, file)?;
    let generation = unsigned(
        sql,
        "SELECT index_generation+1 FROM meta WHERE singleton=1",
        [],
    )?;
    advance(sql, generation, serial)?;
    Ok(true)
}
fn queue_candidates(sql: &SqlView<'_>, path: &RelativePath, serial: u64) -> AtlasResult<()> {
    execute(
        sql,
        "INSERT INTO pending_paths(path_key,serial) SELECT DISTINCT f.path_key,?1 FROM import_candidates c JOIN imports i ON i.id=c.import_id JOIN files f ON f.id=i.file WHERE c.path_key=?2 AND f.path_key<>?2 ON CONFLICT(path_key) DO UPDATE SET serial=max(serial,excluded.serial)",
        params![n(serial), path.as_str()],
    )?;
    Ok(())
}
fn advance(sql: &SqlView<'_>, generation: u64, serial: u64) -> AtlasResult<()> {
    execute(
        sql,
        "UPDATE meta SET index_generation=?1,observed_serial=max(observed_serial,?2) WHERE singleton=1",
        params![n(generation), n(serial)],
    )?;
    Ok(())
}
