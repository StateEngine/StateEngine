//! Text pages recompute one bounded matching-file window, then advance by file.
//! A cursor holds only its window start and last ranked result, never source bytes.
use super::candidates::{Candidate, Kind};
use super::text_files::{FileCandidate, file_window};
use super::text_rank::{Hit, RankedWindow};
use super::*;
const MAX_MATCHING_FILES: usize = 200;
// The one-second source query also pays for authoritative hit metadata,
// compact rendering and the final native cache-custody check. Reserve one
// quarter for those steps rather than spending nearly the entire snapshot on IO.
pub(super) const FINALIZE_ALLOWANCE: Duration = Duration::from_millis(250);
impl QueryReader<'_> {
    pub(super) fn text_mode(
        &self,
        query: &FindQuery,
        mode: SearchMode,
        initial: SearchMode,
        end: Instant,
    ) -> AtlasResult<Answer<Read<SearchResults>>> {
        let work_end = end - FINALIZE_ALLOWANCE;
        let source = self.source;
        let digest = cursor::digest(&(
            "text",
            crate::rank::VERSION,
            query.kind,
            &query.query,
            &query.scope,
            query.mode,
            query.order,
            query.regex,
            query.full,
            &self.viewer,
        ))?;
        let answer = self.cache.read(end, |sql| {
            let mut snapshot = self.snapshot(sql)?;
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
            let pinned = previous.as_ref().and_then(|p| p.text_window.clone());
            let advanced = previous
                .as_ref()
                .map(|p| p.validate(&snapshot.index, "text", digest))
                .transpose()?
                .unwrap_or(false);
            let start = previous
                .as_ref()
                .map(|p| p.last_key.clone())
                .unwrap_or(Key {
                    integers: vec![0, 0, 0, 0, 0, super::modes::key(mode)],
                    bytes: vec![0; 16],
                });
            if start.integers.len() != 6
                || start.integers[0] > 1
                || start.integers[2] > 1
                || start.bytes.len() < 16
                || start.bytes.len() > 282
            {
                return Err(cursor::invalid("invalid text window key"));
            }
            let after = (start.integers[2] == 1).then(|| Key {
                integers: start.integers[3..5].to_vec(),
                bytes: start.bytes[16..].to_vec(),
            });
            if let Some(key) = &after {
                super::find::validate_key(key)?;
            }
            let terms = (!query.regex && matches!(mode, SearchMode::Broad | SearchMode::Related))
                .then(|| {
                    crate::text::lexical::Terms::new(
                        &super::modes::words(query.query.as_str()),
                        query.query.as_str().chars().any(char::is_uppercase),
                    )
                });
            let mut ranked =
                RankedWindow::new(terms.is_some(), query.budget.max_results, after.clone());
            let mut matching = 0;
            let mut more_window = false;
            let mut range_incomplete = false;
            let mut staging_limited = false;
            let mut stats = TextSearchStats::default();
            let mut matched_bytes = 0;
            let mut window_end = None;
            let (pattern, regex) =
                super::modes::text_pattern(query.query.as_str(), mode, query.regex);
            let metadata_pool = super::source_metadata::Pool::collect(
                &ranking, sql, &snapshot, query, mode, work_end,
            )?;
            range_incomplete |= metadata_pool.truncated;
            let matcher = crate::text::compile_pattern(&pattern, regex, !query.regex)?;
            let mut position = (
                start.integers[0] != 0,
                super::linked::from_time_key(start.integers[1]),
                start.bytes[..16].to_vec(),
            );
            // Regex is a live-source selector, not a literal/split metadata plan.
            if query.kind == SearchKind::All && !query.regex && start.integers[0] == 0 {
                let metadata =
                    super::text_metadata::collect(&ranking, sql, &snapshot, query, mode, work_end)?;
                range_incomplete |= metadata.truncated;
                for (value, key) in metadata.values {
                    if after
                        .as_ref()
                        .is_some_and(|p| super::find::compare(&key, p).is_le())
                    {
                        continue;
                    }
                    let bytes = size(&value)?;
                    if !ranked.push_file(vec![Hit { value, key, bytes }], None) {
                        range_incomplete = true;
                        break;
                    }
                }
            }
            if source.is_none() {
                range_incomplete = true;
                snapshot
                    .index
                    .coverage
                    .reasons
                    .push(CoverageReason::ReadFailure);
            }
            'scan: loop {
                if pinned
                    .as_ref()
                    .is_some_and(|p| at_window_end(position.0, position.1, &position.2, p))
                {
                    more_window = pinned.as_ref().is_some_and(|p| p.has_more);
                    break;
                }
                let Some(source) = source else {
                    break;
                };
                if Instant::now() >= work_end || matching == MAX_MATCHING_FILES {
                    more_window = true;
                    break;
                }
                let (ids, has_more) = file_window(sql, position.0, &position.2, &query.scope)?;
                if ids.is_empty() {
                    break;
                }
                let exhausted = !has_more;
                for FileCandidate { id, last, key } in ids {
                    if pinned
                        .as_ref()
                        .is_some_and(|p| at_window_end(position.0, position.1, &position.2, p))
                    {
                        more_window = pinned.as_ref().is_some_and(|p| p.has_more);
                        break 'scan;
                    }
                    if Instant::now() >= work_end || matching == MAX_MATCHING_FILES {
                        more_window = true;
                        break 'scan;
                    }
                    let file = file_by_id(sql, id)?;
                    let previous_end = window_end;
                    position = (true, last.unwrap_or(i64::MIN), key.to_vec());
                    window_end = Some((position.1, file.pointer.file));
                    if crate::policy::built_in_denied(&file.pointer.path) {
                        continue;
                    }
                    if !query.scope.includes_path(&file.pointer.path)
                        || !query.scope.languages.is_empty()
                            && !file
                                .language
                                .is_some_and(|l| query.scope.languages.contains(&l))
                    {
                        continue;
                    }
                    stats.scanned_files += 1;
                    let Some(stream) = source.open_stream(&file.pointer.path)? else {
                        range_incomplete = true;
                        stats.unavailable_files += 1;
                        if !snapshot
                            .index
                            .coverage
                            .reasons
                            .contains(&CoverageReason::ReadFailure)
                        {
                            snapshot
                                .index
                                .coverage
                                .reasons
                                .push(CoverageReason::ReadFailure);
                        }
                        continue;
                    };
                    let result = crate::text::search_with_terms(
                        stream,
                        crate::text::TextRequest {
                            pointer: &file.pointer,
                            query: &pattern,
                            regex,
                            deadline: work_end,
                            max_matches: if query.kind == SearchKind::Code { 1 } else { 3 },
                            full: query.full,
                        },
                        &matcher,
                        terms.as_ref(),
                    )?;
                    for (condition, reason) in [
                        (
                            result.binary || result.non_utf8,
                            CoverageReason::UnsupportedEncoding,
                        ),
                        (result.changed, CoverageReason::ChangedDuringRead),
                        (result.stale_index, CoverageReason::StaleSnapshot),
                        (result.oversized, CoverageReason::SourceBytesLimit),
                        (result.time_limited, CoverageReason::TimeLimit),
                        (result.line_limited, CoverageReason::ByteLimit),
                    ] {
                        if condition && !snapshot.index.coverage.reasons.contains(&reason) {
                            snapshot.index.coverage.reasons.push(reason);
                        }
                    }
                    stats.binary_files += u32::from(result.binary);
                    stats.non_utf8_files += u32::from(result.non_utf8);
                    stats.oversized_files += u32::from(result.oversized);
                    stats.changed_files += u32::from(result.changed);
                    stats.time_limited_files += u32::from(result.time_limited);
                    stats.line_limited_files += u32::from(result.line_limited);
                    let omitted = if query.kind == SearchKind::Code {
                        0
                    } else {
                        result.omitted_matches
                    };
                    stats.omitted_matches += omitted;
                    range_incomplete |= omitted > 0
                        || !result.complete
                        || result.binary
                        || result.non_utf8
                        || result.oversized
                        || result.changed
                        || result.stale_index;
                    // Native source IO can consume the scan allowance. Keep
                    // the whole unfinished file behind the continuation and
                    // leave the remaining snapshot time for rendering, rather
                    // than issuing metadata SQL after the source deadline.
                    if result.time_limited || Instant::now() >= work_end {
                        window_end = previous_end;
                        more_window = true;
                        range_incomplete = true;
                        break 'scan;
                    }
                    let metadata = metadata_pool.best(self, sql, &snapshot, &file, query, mode)?;
                    if Instant::now() >= work_end {
                        window_end = previous_end;
                        more_window = true;
                        range_incomplete = true;
                        break 'scan;
                    }
                    if result.hits.is_empty() && metadata.is_none() {
                        ranked.observe(result.lexical);
                        continue;
                    }
                    let tier = metadata.as_ref().map_or(5, |(_, tier, _, _)| *tier);
                    matching += 1;
                    stats.matching_files += 1;
                    matched_bytes += result
                        .hits
                        .iter()
                        .map(|(_, body)| body.text.len())
                        .sum::<usize>();
                    if matched_bytes > 2 * 1024 * 1024 {
                        window_end = previous_end;
                        more_window = true;
                        break 'scan;
                    }
                    let mut activity = crate::rank::activity(
                        sql,
                        "file",
                        &file.pointer.file.0,
                        crate::rank::ActivityQuery {
                            project: &snapshot.index.project,
                            viewer: &self.viewer,
                            records: self.records,
                            now: ranking.now_unix_ms,
                        },
                    )?;
                    if crate::rank::downweight(file.pointer.path.as_str(), query.kind) {
                        activity.score *= 0.5;
                    }
                    let candidate = Candidate {
                        kind: Kind::File,
                        rowid: file.rowid,
                        tier,
                        key: file.pointer.file.0.to_vec(),
                        tie: file.pointer.path.as_str().into(),
                        activity,
                        precomputed_last: last,
                        lexical: metadata.as_ref().map_or(0.0, |(_, _, lexical, _)| *lexical),
                        related: metadata.as_ref().is_some_and(|(_, _, _, related)| *related),
                    };
                    let base_key = super::find::key(&candidate, query.order);
                    let hits = if let Some((mut code, _, _, _)) = metadata {
                        if result.stale_index {
                            code.pointer.freshness = SnapshotFreshness::Stale;
                        }
                        let body = if query.full {
                            super::body::source(self, &mut code.pointer, work_end)?
                        } else {
                            None
                        };
                        vec![(code, body)]
                    } else {
                        result
                            .hits
                            .into_iter()
                            .map(|(code, body)| (code, query.full.then_some(body)))
                            .collect()
                    };
                    let mut pending = Vec::with_capacity(hits.len());
                    for (code, body) in hits {
                        let mut key = base_key.clone();
                        let stable = cursor::digest(&(file.pointer.file, code.pointer.span))?;
                        let end = key.bytes.len();
                        key.bytes[end - 32..].copy_from_slice(&stable);
                        let hit = SearchHit {
                            target: HitTarget::Code(code),
                            reason: HitReason {
                                mode,
                                match_tier: tier,
                                last_touch_unix_ms: candidate.activity.last,
                                edited_by: candidate.activity.edited_by.clone(),
                                cited_messages: candidate.activity.cited_messages,
                                text_only: !matches!(file.coverage, FileCoverage::Indexed),
                                related: candidate.related,
                            },
                            rank_version: crate::rank::VERSION,
                            body,
                        };
                        let bytes = size(&hit)?;
                        pending.push(Hit {
                            value: hit,
                            key,
                            bytes,
                        });
                    }
                    if !ranked.push_file(pending, result.lexical) {
                        window_end = previous_end;
                        more_window = true;
                        range_incomplete = true;
                        staging_limited = true;
                        break 'scan;
                    }
                }
                if exhausted {
                    break;
                }
            }
            if let Some(pinned) = &pinned
                && !at_window_end(position.0, position.1, &position.2, pinned)
            {
                return Err(cursor::invalid(
                    "text window could not be replayed within its bound; retry or restart",
                ));
            }
            let (best, mut more_hits) = ranked.finish(after.as_ref());
            let mut items = Vec::new();
            let mut bytes = 0;
            let mut keys = Vec::new();
            let mut bodies_omitted = 0;
            let mut files = Vec::<(FileId, u8)>::new();
            for mut hit in best {
                if let HitTarget::Code(code) = &hit.value.target {
                    if let Some((_, count)) = files
                        .iter_mut()
                        .find(|(file, _)| *file == code.pointer.file)
                    {
                        if *count == 3 {
                            continue;
                        }
                        *count += 1;
                    } else {
                        files.push((code.pointer.file, 1));
                    }
                }
                let max = if query.full {
                    query.budget.max_bytes.min(12 * 1024)
                } else {
                    query.budget.max_bytes
                } as usize;
                if bytes + hit.bytes + size(&snapshot.index)? + 1800 > max
                    && hit.value.body.is_some()
                {
                    hit.value.body = None;
                    bodies_omitted += 1;
                    hit.bytes = size(&hit.value)?;
                }
                if bytes + hit.bytes + size(&snapshot.index)? + 1800 > max {
                    more_hits = true;
                    break;
                }
                bytes += hit.bytes;
                keys.push(hit.key);
                items.push(hit.value);
            }
            // The window carries encoded continuations in multiple fields.
            // Fit the actual answer and move a whole hit back behind its cursor
            // rather than trusting a fixed envelope estimate.
            loop {
                let next = if more_hits {
                    let last = keys
                        .last()
                        .ok_or_else(|| capacity("Atlas text response bytes", 1, 0))?;
                    Some(
                        PositionCursor::new(
                            &snapshot.index,
                            "text",
                            digest,
                            Key {
                                integers: vec![
                                    start.integers[0],
                                    start.integers[1],
                                    1,
                                    last.integers[0],
                                    last.integers[1],
                                    super::modes::key(mode),
                                ],
                                bytes: [&start.bytes[..16], last.bytes.as_slice()].concat(),
                            },
                            None,
                        )?
                        .with_ranking_time(ranking.now_unix_ms)
                        .with_text_window(pinned.clone().or_else(|| {
                            window_end.map(|(last_touch_unix_ms, file)| TextWindow {
                                last_touch_unix_ms,
                                file: file.0,
                                has_more: more_window,
                            })
                        }))
                        .encode()?,
                    )
                } else if more_window {
                    let (time, file) =
                        window_end.ok_or_else(|| capacity("Atlas text scan deadline", 1, 0))?;
                    Some(
                        PositionCursor::new(
                            &snapshot.index,
                            "text",
                            digest,
                            Key {
                                integers: vec![
                                    1,
                                    super::linked::time_key(time),
                                    0,
                                    0,
                                    0,
                                    super::modes::key(mode),
                                ],
                                bytes: file.0.to_vec(),
                            },
                            None,
                        )?
                        .with_ranking_time(ranking.now_unix_ms)
                        .encode()?,
                    )
                } else {
                    None
                };
                if more_window {
                    let reason = if matching == MAX_MATCHING_FILES || pinned.is_some() {
                        CoverageReason::ResultLimit
                    } else if matched_bytes > 2 * 1024 * 1024 || staging_limited {
                        CoverageReason::ByteLimit
                    } else {
                        CoverageReason::TimeLimit
                    };
                    if !snapshot.index.coverage.reasons.contains(&reason) {
                        snapshot.index.coverage.reasons.push(reason);
                    }
                }
                let output = SearchResults {
                    mode,
                    fallback_from: (mode != initial).then_some(initial),
                    page: page(
                        &snapshot,
                        items,
                        query.budget,
                        next,
                        range_incomplete || advanced || !snapshot.negative_complete(),
                        bytes,
                        query.next.as_ref(),
                    )?,
                    truncated_candidates: if more_window || metadata_pool.truncated {
                        None
                    } else {
                        Some(0)
                    },
                    full: query.full,
                    text: Some(stats.clone()),
                    bodies_omitted,
                };
                let answer = snapshot.answer(Read::Present { value: output }, advanced);
                let maximum = if query.full {
                    query.budget.max_bytes.min(12 * 1024)
                } else {
                    query.budget.max_bytes
                };
                let compact_fits = self.compact.is_none_or(|(bytes, explain)| {
                    crate::render::search(&answer, bytes, explain).is_ok()
                });
                if size(&answer)? <= maximum as usize && compact_fits {
                    if let Read::Present { value } = &answer.data {
                        value.validate()?;
                    }
                    return check_output(
                        answer,
                        QueryBudget {
                            max_bytes: maximum,
                            ..query.budget
                        },
                    );
                }
                let Read::Present { value: output } = answer.data else {
                    unreachable!()
                };
                items = output.page.into_items();
                if let Some(hit) = items.iter_mut().rev().find(|hit| hit.body.is_some()) {
                    let before = size(hit)?;
                    hit.body = None;
                    bytes = bytes.saturating_sub(before - size(hit)?);
                    bodies_omitted += 1;
                    continue;
                }
                let removed = items
                    .pop()
                    .ok_or_else(|| capacity("Atlas text response bytes", 1, 0))?;
                keys.pop();
                bytes = bytes.saturating_sub(size(&removed)?);
                if removed.body.is_some() {
                    bodies_omitted += 1;
                }
                if items.is_empty() {
                    return Err(capacity("Atlas text response bytes", 1, 0));
                }
                more_hits = true;
            }
        })?;
        super::freshness::finish(self, answer, query.budget, end)
    }
}
fn at_window_end(started: bool, time: i64, file: &[u8], bound: &TextWindow) -> bool {
    started && time == bound.last_touch_unix_ms && file == bound.file
}
