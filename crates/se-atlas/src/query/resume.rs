//! File-grouped other-agent news; reading or constructing an offer never advances it.
use super::changes::{author, change_by_id, check_retention, range_cursor};
use super::*;
use rusqlite::params;
#[derive(Eq, PartialEq, Ord, PartialOrd)]
struct ChangePosition {
    newest: u64,
    generation: u64,
    ordinal: u32,
}
struct Group {
    file: FileId,
    item: ResumeChange,
    newest: u64,
    relevant: bool,
    mixed_authors: bool,
}
/// Attributed news before ordering and the five-item cut.
struct News {
    groups: Vec<Group>,
    bulk: Vec<ResumeChange>,
    unrepresented: u64,
}
impl QueryReader<'_, '_, '_> {
    pub fn resume_code(&mut self, request: &ResumeRequest) -> AtlasResult<ResumeCode> {
        if self.ctx.viewer != AtlasPrincipal::Agent(request.viewer.clone())
            || request.recently_edited_symbols.len() > 32
        {
            return Err(se_types::SeError::invalid(
                "Atlas resume viewer",
                "the verified agent and at most 32 recent symbols",
            ));
        }
        let identity = self.cache.identity().clone();
        let env = self.ctx.split();
        self.cache
            .read(crate::clock::now() + Duration::from_millis(5), |sql| {
                resume_page(&identity, &env, request, sql)
            })
    }
}
fn resume_page(
    identity: &CacheIdentity,
    env: &QueryEnv<'_>,
    request: &ResumeRequest,
    sql: &SqlView<'_>,
) -> AtlasResult<ResumeCode> {
    let snapshot = snapshot(identity, env, sql)?;
    let mut output = ResumeCode {
        index: snapshot.index.clone(),
        state: ResumeCodeState::Available,
        items: Vec::new(),
        omitted: Some(0),
        unattributed_omitted: Some(0),
        complete: snapshot.negative_complete(),
        omitted_since: None,
        advance: None,
        diagnostic: None,
    };
    if matches!(
        snapshot.index.state,
        IndexState::Disabled | IndexState::NotBuilt
    ) {
        output.state = ResumeCodeState::Disabled;
        output.complete = false;
        return Ok(output);
    }
    let lower = if let Some(value) = &request.saved_cursor {
        saved_fence(&snapshot, env.viewer, value)?
    } else {
        output.state = ResumeCodeState::BaselineGap;
        output.complete = false;
        snapshot.floor.0
    };
    let (ids, scan_limited) = candidate_ids(sql, snapshot.published.0, snapshot.floor.0, lower)?;
    if scan_limited {
        output.complete = false;
        output.omitted = None;
    }
    let News {
        mut groups,
        bulk,
        mut unrepresented,
    } = news(sql, request, lower, ids, &mut output)?;
    let mixed = groups.iter().filter(|g| g.mixed_authors).count();
    if mixed > 0 {
        output.complete = false;
        unrepresented += mixed as u64;
        groups.retain(|g| !g.mixed_authors);
    }
    groups.sort_by(|a, b| {
        b.relevant
            .cmp(&a.relevant)
            .then(b.newest.cmp(&a.newest))
            .then(a.file.0.cmp(&b.file.0))
    });
    let available = groups.len() + bulk.len();
    output.items = groups
        .into_iter()
        .map(|g| g.item)
        .chain(bulk)
        .take(5)
        .collect();
    output.omitted = output
        .omitted
        .map(|_| available.saturating_sub(output.items.len()) as u64 + unrepresented);
    output.complete &= output.omitted == Some(0);
    let retrieval =
        range_cursor(&snapshot, env.viewer, lower, Some(snapshot.published))?.encode()?;
    if !fit(&mut output, &retrieval) {
        return Ok(output);
    }
    if output.items.is_empty() && output.complete {
        output.state = ResumeCodeState::Zero;
    } else if !snapshot.negative_complete() && matches!(output.state, ResumeCodeState::Available) {
        output.state = ResumeCodeState::Updating;
    }
    let next = range_cursor(&snapshot, env.viewer, snapshot.published.0, None)?.encode()?;
    let offer = cursor::digest(&(
        env.viewer,
        &request.saved_cursor,
        request.cursor_revision,
        &next,
        &output.items,
    ))?;
    let mut id = [0; 16];
    id.copy_from_slice(&offer[..16]);
    output.advance = Some(ResumeAdvance {
        offer: ResumeOfferId(id),
        expected_cursor: request.saved_cursor.clone(),
        expected_revision: request.cursor_revision,
        next_cursor: next,
        fence: snapshot.published,
    });
    Ok(output)
}
/// The delivered fence a saved cursor carries; a paged changes range is refused.
fn saved_fence(
    snapshot: &Snapshot,
    viewer: &AtlasPrincipal,
    value: &AtlasCursor,
) -> AtlasResult<u64> {
    let cursor = PositionCursor::decode(value)?;
    cursor.validate(
        &snapshot.index,
        "changes-range",
        cursor::digest(&("changes-range", viewer))?,
    )?;
    if cursor.last_key.integers.len() != 2
        || !cursor.last_key.bytes.is_empty()
        || cursor.change_fence.is_some()
    {
        return Err(cursor::invalid(
            "resume needs its saved delivered fence, not a paged changes range",
        ));
    }
    check_retention(snapshot, cursor.last_key.integers[0], viewer)?;
    Ok(cursor.last_key.integers[0])
}
fn news(
    sql: &SqlView<'_>,
    request: &ResumeRequest,
    lower: u64,
    ids: Vec<ChangePosition>,
    output: &mut ResumeCode,
) -> AtlasResult<News> {
    let mut news = News {
        groups: Vec::with_capacity(32),
        bulk: Vec::new(),
        unrepresented: 0,
    };
    for ChangePosition {
        generation,
        ordinal,
        ..
    } in ids
    {
        let (_, resolved_at) = author(sql, generation, ordinal)?;
        let mut change = change_by_id(sql, generation, ordinal)?;
        if !super::changes::public_change(&mut change) {
            continue;
        }
        let edit = match change {
            CodeChange::Bulk(value) if news.bulk.len() < 5 => {
                news.bulk.push(ResumeChange::Bulk(value));
                continue;
            }
            CodeChange::Bulk(_) => {
                news.unrepresented += 1;
                continue;
            }
            CodeChange::Edit(edit) => edit,
        };
        match &edit.author {
            AuthorHint::Captured { agent, .. } if agent == &request.viewer => continue,
            AuthorHint::Captured { .. } => (),
            _ => {
                output.unattributed_omitted = output.unattributed_omitted.map(|n| n + 1);
                output.complete = false;
                continue;
            }
        }
        let relevant = edit
            .symbol
            .is_some_and(|s| request.recently_edited_symbols.contains(&s));
        let late = edit.id.generation.0 <= lower && resolved_at.is_some_and(|g| g > lower);
        if !news.group(edit, relevant, late) {
            news.unrepresented += 1;
            output.complete = false;
        }
    }
    Ok(news)
}
impl News {
    /// Folds an edit into its file's group; false when the 32-group cap leaves it out.
    fn group(&mut self, edit: Box<CodeEdit>, relevant: bool, late: bool) -> bool {
        if let Some(group) = self.groups.iter_mut().find(|g| g.file == edit.pointer.file) {
            group.relevant |= relevant;
            if let ResumeChange::File {
                kinds,
                changes,
                late_attribution,
                baseline_reset,
                author,
                ..
            } = &mut group.item
            {
                if let (
                    AuthorHint::Captured { agent: left, .. },
                    AuthorHint::Captured { agent: right, .. },
                ) = (&*author, &edit.author)
                {
                    group.mixed_authors |= left != right;
                }
                if !kinds.contains(&edit.kind) {
                    kinds.push(edit.kind);
                }
                *changes += 1;
                *late_attribution |= late;
                *baseline_reset |= edit.baseline_reset;
            }
        } else if self.groups.len() < 32 {
            self.groups.push(Group {
                file: edit.pointer.file,
                newest: edit.id.generation.0,
                relevant,
                mixed_authors: false,
                item: ResumeChange::File {
                    pointer: edit.pointer,
                    kinds: vec![edit.kind],
                    changes: 1,
                    author: edit.author,
                    dependents: edit.dependents,
                    late_attribution: late,
                    baseline_reset: edit.baseline_reset,
                },
            });
        } else {
            return false;
        }
        true
    }
}
/// Drops items until the rendered context fits; false when even no items do not.
fn fit(output: &mut ResumeCode, retrieval: &AtlasCursor) -> bool {
    loop {
        if !output.complete {
            output.omitted_since = Some(retrieval.clone());
        }
        if crate::render::resume(output).is_ok() {
            return true;
        }
        if output.items.pop().is_none() {
            output.state = ResumeCodeState::BudgetExceeded;
            output.omitted_since = None;
            output.advance = None;
            output.diagnostic = Some(
                capacity("Atlas resume context including retrieval", 601, 600)
                    .body
                    .clone(),
            );
            return false;
        }
        output.omitted = output.omitted.map(|n| n + 1);
        output.complete = false;
    }
}

/// Query each indexed generation range separately. Merge only bounded identities,
/// close both statements, then materialize rows through small point queries.
fn candidate_ids(
    sql: &SqlView<'_>,
    fence: u64,
    floor: u64,
    lower: u64,
) -> AtlasResult<(Vec<ChangePosition>, bool)> {
    let mut output = Vec::with_capacity(513);
    let mut limited = false;
    for statement in [
        "SELECT generation,ordinal,generation FROM changes WHERE generation>?1 AND generation<=?2 AND generation>?3 ORDER BY generation DESC,ordinal DESC LIMIT 513",
        "SELECT generation,ordinal,resolved_at_generation FROM authors WHERE resolved_at_generation>?1 AND resolved_at_generation<=?2 AND generation>?3 AND generation<=?2 ORDER BY resolved_at_generation DESC,generation DESC,ordinal DESC LIMIT 513",
    ] {
        let mut stmt = sql.prepare(statement)?;
        let mut rows = stmt
            .query(params![signed(lower)?, signed(fence)?, signed(floor)?])
            .map_err(cache_error)?;
        let mut scanned = 0;
        while let Some(row) = rows.next().map_err(cache_error)? {
            scanned += 1;
            let item = ChangePosition {
                newest: number(row, 2)?,
                generation: number(row, 0)?,
                ordinal: get(row, 1)?,
            };
            if let Some(old) = output.iter().position(|v: &ChangePosition| {
                v.generation == item.generation && v.ordinal == item.ordinal
            }) {
                if output[old].newest >= item.newest {
                    continue;
                }
                output.remove(old);
            }
            let at = output.partition_point(|v| v > &item);
            output.insert(at, item);
            if output.len() > 512 {
                output.pop();
                limited = true;
            }
        }
        limited |= scanned == 513;
    }
    Ok((output, limited))
}
