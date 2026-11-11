//! Keep compact metadata identities while the bounded source scan runs.
use super::candidates::{Candidate, Kind};
use super::*;
struct Entry {
    file: i64,
    rowid: i64,
    kind: Kind,
    tier: u8,
    lexical: f64,
    related: bool,
}
pub(super) struct Pool {
    entries: Vec<Entry>,
    pub truncated: bool,
}
impl Pool {
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub fn collect(
        env: &QueryEnv<'_>,
        sql: &SqlView<'_>,
        snapshot: &Snapshot,
        query: &FindQuery,
        mode: SearchMode,
        end: Instant,
    ) -> AtlasResult<Self> {
        let mut pool = Self {
            entries: Vec::new(),
            truncated: false,
        };
        // Literal metadata belongs to the same file window as live source.
        // Global name probes spend the first window's deadline before source
        // progress, and their 128-file cap demotes later indexed symbols.
        if query.kind != SearchKind::Code || query.regex || mode == SearchMode::Literal {
            return Ok(pool);
        }
        if mode == SearchMode::Related {
            let candidates = super::related::collect(env, sql, snapshot, query, end)?;
            pool.truncated = candidates.truncated;
            for candidate in candidates.values {
                let file = match candidate.kind {
                    Kind::Symbol => symbol_by_id(sql, candidate.rowid)?.1,
                    Kind::File => candidate.rowid,
                    _ => continue,
                };
                pool.insert(Entry {
                    file,
                    rowid: candidate.rowid,
                    kind: candidate.kind,
                    tier: candidate.tier,
                    lexical: candidate.lexical,
                    related: candidate.related,
                });
            }
            return Ok(pool);
        }
        // Names are much smaller than symbols. Probe their indexed symbol list
        // without sorting every matching symbol by activity before the live scan.
        for plan in super::candidate_sql::plans(query, mode)? {
            if !matches!(plan.kind, Kind::Symbol | Kind::File) {
                continue;
            }
            if Instant::now() >= end {
                pool.truncated = true;
                break;
            }
            let (condition, _) = plan
                .sql
                .split_once(" WHERE ")
                .and_then(|(_, s)| s.rsplit_once(" ORDER BY "))
                .ok_or_else(|| cache_error("invalid source metadata plan"))?;
            let from = if plan.kind == Kind::Symbol {
                if plan.lexical {
                    "symbols s JOIN names n ON n.id=s.name JOIN symbol_fts ON symbol_fts.rowid=s.id"
                } else {
                    "names n CROSS JOIN symbols s INDEXED BY symbols_name ON s.name=n.id"
                }
            } else {
                "files f"
            };
            let (id, file) = if plan.kind == Kind::Symbol {
                ("s.id", "s.file")
            } else {
                ("f.id", "f.id")
            };
            let score = if plan.lexical {
                ",bm25(symbol_fts)"
            } else {
                ",0.0"
            };
            let statement =
                format!("SELECT {id},{file}{score} FROM {from} WHERE {condition} LIMIT 513");
            let mut ids = Vec::new();
            {
                let mut statement = sql.prepare(&statement)?;
                let mut rows = statement
                    .query(rusqlite::params_from_iter(plan.values))
                    .map_err(cache_error)?;
                while let Some(row) = rows.next().map_err(cache_error)? {
                    ids.push((
                        get::<i64>(row, 0)?,
                        get::<i64>(row, 1)?,
                        get::<f64>(row, 2)?,
                    ));
                }
            }
            if ids.len() > 512 {
                ids.pop();
                pool.truncated = true;
            }
            for (rowid, file, bm25) in ids {
                if !bm25.is_finite() || bm25 > 0.0 {
                    return Err(cache_error("invalid source metadata BM25 score"));
                }
                if Instant::now() >= end {
                    pool.truncated = true;
                    break;
                }
                if plan.kind == Kind::Symbol && plan.tier == 2 {
                    let (_, name) = super::candidates::metadata(sql, plan.kind, rowid)?;
                    if !crate::rank::split_matches(&name, query.query.as_str()) {
                        continue;
                    }
                }
                pool.insert(Entry {
                    file,
                    rowid,
                    kind: plan.kind,
                    tier: plan.tier,
                    lexical: if bm25 < 0.0 { -bm25 } else { 0.0 },
                    related: false,
                });
            }
        }
        Ok(pool)
    }
    fn insert(&mut self, entry: Entry) {
        if let Some(old) = self.entries.iter_mut().find(|e| e.file == entry.file) {
            if entry.tier < old.tier {
                *old = entry;
            }
            return;
        }
        if self.entries.len() == 128 {
            self.truncated = true;
            return;
        }
        self.entries.push(entry);
    }
    pub fn best(
        &self,
        env: &QueryEnv<'_>,
        sql: &SqlView<'_>,
        snapshot: &Snapshot,
        file: &FileRow,
        query: &FindQuery,
        mode: SearchMode,
    ) -> AtlasResult<Option<(CodeHit, u8, f64, bool)>> {
        if query.kind == SearchKind::Code && !query.regex && mode == SearchMode::Literal {
            return literal_best(sql, file, query.query.as_str());
        }
        let Some(entry) = self.entries.iter().find(|e| e.file == file.rowid) else {
            return Ok(None);
        };
        let (key, tie) = super::candidates::metadata(sql, entry.kind, entry.rowid)?;
        let candidate = Candidate {
            kind: entry.kind,
            rowid: entry.rowid,
            tier: entry.tier,
            key,
            tie,
            activity: crate::rank::Activity::default(),
            precomputed_last: None,
            lexical: entry.lexical,
            related: entry.related,
        };
        if let Some(hit) = super::find::materialize(env, sql, snapshot, &candidate, query, mode)?
            && let HitTarget::Code(code) = hit.target
        {
            return Ok(Some((code, entry.tier, entry.lexical, entry.related)));
        }
        Ok(None)
    }
}

fn literal_best(
    sql: &SqlView<'_>,
    file: &FileRow,
    text: &str,
) -> AtlasResult<Option<(CodeHit, u8, f64, bool)>> {
    let smart = text.chars().any(char::is_uppercase);
    let (name, needle) = if smart {
        ("n.text", "?2")
    } else {
        ("lower(n.text)", "lower(?2)")
    };
    // Resolve only this file, and materialize its winning symbol in the same
    // statement. Re-reading symbol/name/parent/file rows discards the already
    // admitted file and amplifies cold IO inside the source scan allowance.
    let statement = format!(
        "SELECT s.key,n.text,s.kind,s.start_byte,s.end_byte,s.start_line,s.start_column,s.end_line,s.end_column,CASE WHEN {name}={needle} THEN 1 WHEN instr({name},{needle})=1 THEN 2 ELSE 4 END AS tier FROM symbols s INDEXED BY symbols_file JOIN names n ON n.id=s.name WHERE s.file=?1 AND instr({name},{needle})>0 ORDER BY tier,s.start_byte,s.id LIMIT 1"
    );
    let mut statement = sql.prepare(&statement)?;
    let mut rows = statement.query((file.rowid, text)).map_err(cache_error)?;
    let mut best = rows
        .next()
        .map_err(cache_error)?
        .map(|row| {
            let tier = get::<u8>(row, 9)?;
            let mut pointer = file.pointer.clone();
            pointer.span = Some(span(row, 3)?);
            let hit = CodeHit {
                pointer,
                symbol: Some(SymbolId(blob(row, 0)?)),
                name: get(row, 1)?,
                kind: Some(tag(get(row, 2)?)?),
                method: match tier {
                    1 => FindMethod::ExactName,
                    2 => FindMethod::SplitIdentifier,
                    _ => FindMethod::MetadataFts,
                },
                accuracy: None,
            };
            Ok::<_, se_types::SeError>((hit, tier, 0.0, false))
        })
        .transpose()?;
    let path_match = if smart {
        file.pointer.path.as_str().contains(text)
    } else {
        file.pointer
            .path
            .as_str()
            .to_ascii_lowercase()
            .contains(&text.to_ascii_lowercase())
    };
    if path_match && best.as_ref().is_none_or(|(_, tier, _, _)| *tier > 3) {
        best = Some((
            CodeHit {
                pointer: file.pointer.clone(),
                symbol: None,
                name: file.pointer.path.as_str().to_owned(),
                kind: None,
                method: FindMethod::MetadataFts,
                accuracy: None,
            },
            3,
            0.0,
            false,
        ));
    }
    Ok(best)
}
