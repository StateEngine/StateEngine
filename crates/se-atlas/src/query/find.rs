use super::candidates::{Candidate, Kind};
use super::*;
use rusqlite::params;
impl QueryReader<'_> {
    /// Compact consumers fit the actual rendered page as well as its typed
    /// representation. Moving a whole hit behind the cursor preserves progress.
    pub fn find_compact(
        &self,
        query: &FindQuery,
        max_bytes: usize,
        explain: bool,
    ) -> AtlasResult<Answer<Read<SearchResults>>> {
        if !(1024..=32768).contains(&max_bytes) {
            return Err(cache_error(
                "compact search budget must be 1024..32768 bytes",
            ));
        }
        let mut reader = self.clone();
        reader.compact = Some((max_bytes, explain));
        reader.find(query)
    }
    pub fn find(&self, query: &FindQuery) -> AtlasResult<Answer<Read<SearchResults>>> {
        query.scope.validate()?;
        if query.regex
            && (!matches!(
                query.kind,
                SearchKind::All | SearchKind::Code | SearchKind::Text
            ) || query.mode.is_some_and(|mode| mode != SearchMode::Literal))
        {
            return Err(se_types::SeError::invalid(
                "Atlas regular expression",
                "a live-source query (all/code/text) with automatic or literal mode; metadata records use the text modes",
            ));
        }
        if matches!(
            query.kind,
            SearchKind::Text | SearchKind::All | SearchKind::Code
        ) || query.regex
        {
            return self.find_text(query);
        }
        let end = deadline(query.budget)?;
        let digest = cursor::digest(&(
            "find",
            crate::rank::VERSION,
            query.kind,
            &query.query,
            &query.scope,
            query.mode,
            query.order,
            query.full,
            &self.viewer,
        ))?;
        let answer = self.cache.read(end, |sql| {
            let snapshot = self.snapshot(sql)?;
            let previous = query
                .next
                .as_ref()
                .map(PositionCursor::decode)
                .transpose()?;
            let mut ranking = self.clone();
            ranking.now_unix_ms = previous
                .as_ref()
                .map(PositionCursor::ranking_time)
                .transpose()?
                .unwrap_or(self.now_unix_ms);
            let after = previous
                .as_ref()
                .map(|p| {
                    if p.last_key.integers.len() != 3 {
                        return Err(cursor::invalid("invalid find continuation mode"));
                    }
                    super::modes::from_key(p.last_key.integers.get(2))?;
                    let key = Key {
                        integers: p.last_key.integers[..2].to_vec(),
                        bytes: p.last_key.bytes.clone(),
                    };
                    validate_key(&key)?;
                    Ok(key)
                })
                .transpose()?;
            let advanced = previous
                .as_ref()
                .map(|p| p.validate(&snapshot.index, "find", digest))
                .transpose()?
                .unwrap_or(false);
            let initial = query
                .mode
                .unwrap_or_else(|| super::modes::automatic(query.query.as_str()));
            let mut mode = previous
                .as_ref()
                .map(|p| super::modes::from_key(p.last_key.integers.get(2)))
                .transpose()?
                .unwrap_or(initial);
            let mut collected = super::candidates::collect(
                &ranking,
                sql,
                &snapshot,
                query,
                mode,
                end - (query.budget.work / 4).min(Duration::from_millis(3)),
            )?;
            if query.mode.is_none()
                && previous.is_none()
                && collected.values.is_empty()
                && !collected.truncated
            {
                for next in [
                    if initial == SearchMode::Exact {
                        SearchMode::Literal
                    } else {
                        SearchMode::Broad
                    },
                    SearchMode::Broad,
                    SearchMode::Related,
                ] {
                    if mode == next {
                        continue;
                    }
                    mode = next;
                    collected = super::candidates::collect(
                        &ranking,
                        sql,
                        &snapshot,
                        query,
                        mode,
                        end - (query.budget.work / 4).min(Duration::from_millis(3)),
                    )?;
                    if !collected.values.is_empty() || collected.truncated {
                        break;
                    }
                }
            }
            let mut items = Vec::with_capacity(query.budget.max_results as usize);
            let mut bytes = 0;
            let mut bodies = 0;
            let mut body_omitted = 0;
            let mut last = None;
            let mut more = false;
            let mut files = Vec::<(FileId, u8)>::new();
            for candidate in collected.values {
                let key = key(&candidate, query.order);
                if after.as_ref().is_some_and(|p| compare(&key, p).is_le()) {
                    continue;
                }
                let Some(mut hit) = materialize(self, sql, &snapshot, &candidate, query, mode)?
                else {
                    continue;
                };
                if let HitTarget::Code(code) = &hit.target
                    && files
                        .iter()
                        .any(|(file, n)| *file == code.pointer.file && *n >= 3)
                {
                    continue;
                }

                if query.full {
                    hit.body = match &mut hit.target {
                        HitTarget::Code(code) => super::body::source(self, &mut code.pointer, end)?,
                        HitTarget::Record(record) => match self.records.body(
                            &snapshot.index.project,
                            &self.viewer,
                            &record.pointer,
                            Some(&query.query),
                        )? {
                            Read::Present { value } => Some(value),
                            Read::Absent { .. } => None,
                            Read::Unknown { what } => return Err(cache_error(what)),
                            Read::Unreadable { source, reason, .. } => {
                                return Err(cache_error(format!("{source}: {reason}")));
                            }
                        },
                        HitTarget::Commit(_) => None,
                    };
                    if hit
                        .body
                        .as_ref()
                        .is_some_and(|body| bodies + body.text.len() > 12 * 1024)
                    {
                        hit.body = None;
                        body_omitted += 1;
                    } else if let Some(body) = &hit.body {
                        bodies += body.text.len();
                    } else {
                        body_omitted += 1;
                    }
                }
                let mut cost = size(&hit)?;
                let max = if query.full {
                    query.budget.max_bytes.min(12 * 1024)
                } else {
                    query.budget.max_bytes
                } as usize;
                if hit.body.is_some() && bytes + cost + size(&snapshot.index)? + 1600 > max {
                    hit.body = None;
                    body_omitted += 1;
                    cost = size(&hit)?;
                }
                if items.len() == query.budget.max_results as usize
                    || bytes + cost + size(&snapshot.index)? + 1600 > max
                {
                    more = true;
                    break;
                }
                if let HitTarget::Code(code) = &hit.target {
                    if let Some((_, n)) = files.iter_mut().find(|(id, _)| *id == code.pointer.file)
                    {
                        *n += 1;
                    } else {
                        files.push((code.pointer.file, 1));
                    }
                }
                bytes += cost;
                items.push(hit);
                last = Some(key);
            }
            if more && items.is_empty() {
                return Err(capacity("Atlas search response bytes", 1, 0));
            }
            let next = if more {
                let mut key = last.ok_or_else(|| cache_error("missing search continuation"))?;
                key.integers.push(super::modes::key(mode));
                Some(
                    PositionCursor::new(&snapshot.index, "find", digest, key, None)?
                        .with_ranking_time(ranking.now_unix_ms)
                        .encode()?,
                )
            } else {
                None
            };
            let output = SearchResults {
                mode,
                fallback_from: (mode != initial).then_some(initial),
                page: page(
                    &snapshot,
                    items,
                    query.budget,
                    next,
                    collected.truncated || advanced || !snapshot.negative_complete(),
                    bytes,
                    query.next.as_ref(),
                )?,
                truncated_candidates: if collected.truncated { None } else { Some(0) },
                full: query.full,
                text: None,
                bodies_omitted: body_omitted,
            };
            output.validate()?;
            check_output(
                snapshot.answer(Read::Present { value: output }, advanced),
                QueryBudget {
                    max_bytes: if query.full {
                        query.budget.max_bytes.min(12 * 1024)
                    } else {
                        query.budget.max_bytes
                    },
                    ..query.budget
                },
            )
        })?;
        super::freshness::finish(self, answer, query.budget, end)
    }
}
pub(super) fn materialize(
    reader: &QueryReader<'_>,
    sql: &SqlView<'_>,
    snapshot: &Snapshot,
    candidate: &Candidate,
    query: &FindQuery,
    mode: SearchMode,
) -> AtlasResult<Option<SearchHit>> {
    let target = match candidate.kind {
        Kind::Symbol => {
            let (symbol, file_id) = symbol_by_id(sql, candidate.rowid)?;
            let symbol = symbol.value;
            let mut pointer = file_by_id(sql, file_id)?.pointer;
            pointer.span = Some(symbol.span);
            HitTarget::Code(CodeHit {
                pointer,
                symbol: Some(symbol.id),
                name: symbol.name,
                kind: Some(symbol.kind),
                method: match candidate.tier {
                    1 => FindMethod::ExactName,
                    2 => FindMethod::SplitIdentifier,
                    _ => FindMethod::MetadataFts,
                },
                accuracy: None,
            })
        }
        Kind::File => {
            let mut stmt =
                sql.prepare(&format!("SELECT {FILE_COLUMNS} FROM files f WHERE f.id=?1"))?;
            let mut rows = stmt.query([candidate.rowid]).map_err(cache_error)?;
            let row = rows
                .next()
                .map_err(cache_error)?
                .ok_or_else(|| cache_error("file candidate disappeared in snapshot"))?;
            let pointer = file(row, 0)?.pointer;
            let name = pointer.path.as_str().to_owned();
            HitTarget::Code(CodeHit {
                pointer,
                symbol: None,
                name,
                kind: None,
                method: FindMethod::MetadataFts,
                accuracy: None,
            })
        }
        Kind::Record => {
            let pointer = super::candidates::record_pointer(sql, candidate.rowid)?;
            match reader.records.read(
                &snapshot.index.project,
                &reader.viewer,
                &pointer,
                Some(&query.query),
            )? {
                Read::Present { value } if value.pointer == pointer && value.line.len() <= 160 => {
                    HitTarget::Record(value)
                }
                Read::Absent { .. } => return Ok(None),
                _ => return Err(cache_error("record authority became unavailable")),
            }
        }
        Kind::Commit => {
            let mut stmt =
                sql.prepare("SELECT oid,author,author_unix_ms,subject FROM commits WHERE id=?1")?;
            let mut rows = stmt.query(params![candidate.rowid]).map_err(cache_error)?;
            let row = rows
                .next()
                .map_err(cache_error)?
                .ok_or_else(|| cache_error("commit candidate disappeared"))?;
            let bytes: Vec<u8> = get(row, 0)?;
            let oid = match bytes.len() {
                20 => GitObjectId::Sha1(bytes.try_into().map_err(|_| cache_error("invalid SHA1"))?),
                32 => GitObjectId::Sha256(
                    bytes
                        .try_into()
                        .map_err(|_| cache_error("invalid SHA256"))?,
                ),
                _ => return Err(cache_error("invalid commit oid length")),
            };
            HitTarget::Commit(CommitHit {
                oid,
                author: get(row, 1)?,
                author_unix_ms: get(row, 2)?,
                subject: get(row, 3)?,
            })
        }
    };
    Ok(Some(SearchHit {
        target,
        reason: HitReason {
            mode,
            match_tier: candidate.tier,
            last_touch_unix_ms: candidate.activity.last,
            edited_by: candidate.activity.edited_by.clone(),
            cited_messages: candidate.activity.cited_messages,
            text_only: false,
            related: candidate.related,
        },
        rank_version: crate::rank::VERSION,
        body: None,
    }))
}
pub(super) fn key(candidate: &Candidate, order: SearchOrder) -> Key {
    let order = match order {
        SearchOrder::Relevance => u64::MAX - candidate.activity.score.to_bits(),
        SearchOrder::Recency => {
            u64::MAX - super::linked::time_key(candidate.activity.last.unwrap_or(i64::MIN))
        }
    };
    let tie = candidate.tie.to_lowercase();
    let mut end = tie.len().min(64);
    while !tie.is_char_boundary(end) {
        end -= 1;
    }
    // Activity remains first within each tier. BM25 breaks ties before names,
    // using FTS5's corpus term rarity rather than an OR-match approximation.
    let mut bytes = (u64::MAX - candidate.lexical.to_bits())
        .to_be_bytes()
        .to_vec();
    bytes.extend(&tie.as_bytes()[..end]);
    bytes.push(0);
    bytes.extend(blake3::hash(tie.as_bytes()).as_bytes());
    bytes.extend(blake3::hash(&candidate.key).as_bytes());
    Key {
        integers: vec![u64::from(candidate.tier), order],
        bytes,
    }
}
pub(super) fn compare(a: &Key, b: &Key) -> std::cmp::Ordering {
    a.integers.cmp(&b.integers).then(a.bytes.cmp(&b.bytes))
}

pub(super) fn validate_key(key: &Key) -> AtlasResult<()> {
    if key.integers.len() != 2
        || !(1..=5).contains(&key.integers[0])
        || !(73..=137).contains(&key.bytes.len())
    {
        return Err(cursor::invalid("invalid ranked search ordering key"));
    }
    let name_end = key.bytes.len() - 65;
    if key.bytes[name_end] != 0 || std::str::from_utf8(&key.bytes[8..name_end]).is_err() {
        return Err(cursor::invalid("invalid search tie-break key"));
    }
    Ok(())
}
