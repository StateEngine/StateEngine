//! Bounded reverse BFS is recomputed per page; no graph frontier enters a cursor.
use super::impact_files::FileGraph;
use super::target::*;
use super::*;
#[derive(Clone, Copy)]
struct Node {
    symbol: i64,
    parent: Option<usize>,
    via: Option<i64>,
    depth: u8,
}
impl Node {
    fn root(symbol: i64) -> Self {
        Self {
            symbol,
            parent: None,
            via: None,
            depth: 0,
        }
    }
}
#[derive(Clone)]
struct ResultRow {
    node: usize,
    file: [u8; 16],
    symbol: [u8; 32],
    site: u64,
}
/// One response page: entries strictly after the cursor key, within the query budget.
struct Page<'k> {
    output: Impact,
    after: Option<&'k Key>,
    last: Option<Key>,
    more: bool,
    budget: QueryBudget,
    index_bytes: usize,
}
impl QueryReader<'_, '_, '_> {
    pub fn impact(&mut self, query: &ImpactQuery) -> AtlasResult<Answer<Read<Impact>>> {
        let (end, hard) = deadline(query.budget)?;
        let started = end - query.budget.work;
        if !(1..=3).contains(&query.depth) {
            return Err(se_types::SeError::invalid("impact depth", "1..3"));
        }
        let digest = cursor::digest(&(
            "impact",
            &query.target,
            query.depth,
            query.include_name_only,
            &self.ctx.viewer,
        ))?;
        let identity = self.cache.identity().clone();
        let env = self.ctx.split();
        let result = self.cache.read(hard, |sql| {
            Self::impact_page(&identity, &env, query, end, digest, sql)
        });
        let answer = phase_timeout("impact query", started, hard, result)?;
        let answer = super::freshness::finish(self, answer, query.budget, (end, hard));
        phase_timeout("impact query", started, hard, answer)
    }

    fn impact_page(
        identity: &CacheIdentity,
        env: &QueryEnv<'_>,
        query: &ImpactQuery,
        end: Instant,
        digest: [u8; 32],
        sql: &SqlView<'_>,
    ) -> AtlasResult<Answer<Read<Impact>>> {
        let snapshot = snapshot(identity, env, sql)?;
        let previous = query
            .next
            .as_ref()
            .map(PositionCursor::decode)
            .transpose()?;
        let advanced = previous
            .as_ref()
            .map(|p| p.validate(&snapshot.index, "impact", digest))
            .transpose()?
            .unwrap_or(false);
        let after = previous.as_ref().map(|p| &p.last_key);
        if let Some(key) = after {
            validate_key(key)?;
        }
        let mut nodes = Vec::with_capacity(32);
        let mut root_files = Vec::new();
        let target = &concrete(sql, &query.target)?;
        let mut limited = seed(env, sql, &snapshot, target, &mut nodes, &mut root_files)?;
        if nodes.is_empty() && root_files.is_empty() {
            return Ok(snapshot.unknown(
                "no indexed impact target; inspect coverage and explicit file/record links",
            ));
        }
        if nodes.len() > 512 {
            nodes.truncate(512);
            limited = true;
        }
        let root_symbols = matches!(target, AtlasTarget::Symbol(_))
            .then(|| nodes.iter().map(|n| n.symbol).collect::<Vec<_>>());
        let (results, examined, at) = walk(sql, query, &mut nodes, &mut limited, end)?;
        let files = super::impact_files::collect(
            sql,
            root_files.clone(),
            query.depth,
            512usize.saturating_sub(nodes.len()),
            1024usize.saturating_sub(examined),
            end,
            root_symbols.as_deref(),
        )?;
        limited |= files.limited;
        limited |= merge_root_files(sql, &results, &files, &mut root_files, end)?;
        let mut page = Page {
            output: Impact {
                dependents: Vec::new(),
                tests: Vec::new(),
                records: Vec::new(),
                omitted_frontier: 0,
                frontier_count_complete: !limited,
                next: None,
                complete: !limited && snapshot.negative_complete() && !advanced,
            },
            after,
            last: None,
            more: false,
            budget: query.budget,
            index_bytes: size(&snapshot.index)?,
        };
        fill_dependents(sql, &nodes, &results, &files, &mut page)?;
        let frontier = nodes.len().saturating_sub(at) as u64;
        drop(nodes);
        drop(results);
        drop(files);
        if !page.more {
            let end = end - Duration::from_millis(2);
            limited |= fill_records(env, sql, &snapshot, &root_files, end, &mut page)?;
        }
        let mut output = page.output;
        output.frontier_count_complete = !limited;
        output.complete &= !limited;
        // An exhausted graph budget cannot offer a cursor claiming complete traversal.
        if limited {
            output.omitted_frontier = frontier;
            output.complete = false;
        } else if page.more {
            let key = page
                .last
                .ok_or_else(|| capacity("Atlas impact response bytes", 1, 0))?;
            output.next =
                Some(PositionCursor::new(&snapshot.index, "impact", digest, key, None)?.encode()?);
            output.complete = false;
        }

        check_output(
            snapshot.answer(Read::Present { value: output }, advanced),
            query.budget,
        )
    }
}
/// Reverse BFS: dependents found, edges examined, and the first node left unexpanded.
fn walk(
    sql: &SqlView<'_>,
    query: &ImpactQuery,
    nodes: &mut Vec<Node>,
    limited: &mut bool,
    end: Instant,
) -> AtlasResult<(Vec<ResultRow>, usize, usize)> {
    let mut results = Vec::with_capacity(32);
    let mut examined = 0;
    let mut exhausted = false;
    let mut at = 0;
    while at < nodes.len() {
        if crate::clock::now() >= end {
            exhausted = true;
            break;
        }
        let node = nodes[at];
        if node.depth >= query.depth {
            at += 1;
            continue;
        }
        let (edges, partial) = super::impact_edges::read(
            sql,
            node.symbol,
            query.include_name_only,
            1024usize.saturating_sub(examined),
            end,
        )?;
        exhausted |= partial;
        examined += edges.len();
        for edge in edges {
            if crate::clock::now() >= end {
                exhausted = true;
                break;
            }
            let Some(child) = edge.enclosing else {
                continue;
            };
            let (symbol, _) = symbol_by_id(sql, child)?;
            if symbol.value.kind == SymbolKind::Module && symbol.value.parent.is_none() {
                continue;
            }
            let file = file_by_id(sql, edge.file)?;
            if crate::policy::built_in_denied(&file.pointer.path)
                || !matches!(file.coverage, FileCoverage::Indexed)
            {
                *limited = true;
                continue;
            }
            if nodes.iter().any(|n| n.symbol == child) {
                continue;
            }
            if nodes.len() == 512 {
                exhausted = true;
                break;
            }
            results.push(ResultRow {
                node: nodes.len(),
                file: file.pointer.file.0,
                symbol: symbol.value.id.0,
                site: edge.start,
            });
            nodes.push(Node {
                symbol: child,
                parent: Some(at),
                via: Some(edge.id),
                depth: node.depth + 1,
            });
        }
        if exhausted {
            break;
        }
        at += 1;
    }
    *limited |= exhausted;
    Ok((results, examined, at))
}
/// Records are linked from the roots and from every file a dependent lives in.
fn merge_root_files(
    sql: &SqlView<'_>,
    results: &[ResultRow],
    files: &FileGraph,
    root_files: &mut Vec<i64>,
    end: Instant,
) -> AtlasResult<bool> {
    let mut limited = false;
    for result in results {
        if crate::clock::now() >= end {
            limited = true;
            break;
        }
        let id: i64 = scalar(
            sql,
            "SELECT id FROM files WHERE key=?1",
            [result.file.as_slice()],
        )?;
        if !root_files.contains(&id) {
            root_files.push(id);
        }
    }
    for id in files.file_rows() {
        if !root_files.contains(&id) {
            root_files.push(id);
        }
    }
    Ok(limited)
}
fn fill_dependents(
    sql: &SqlView<'_>,
    nodes: &[Node],
    results: &[ResultRow],
    files: &FileGraph,
    page: &mut Page<'_>,
) -> AtlasResult<()> {
    let mut positions = Vec::with_capacity(results.len() + files.results.len());
    positions.extend((0..results.len()).map(|at| (false, at)));
    positions.extend(files.results.iter().map(|&at| (true, at)));
    let order = |(file, at): (bool, usize)| {
        if file {
            files.order(at)
        } else {
            let result = &results[at];
            let mut bytes = [0; 48];
            bytes[..32].copy_from_slice(&result.symbol);
            bytes[32..].copy_from_slice(&result.file);
            (nodes[result.node].depth, bytes, result.site, 0)
        }
    };
    positions.sort_by_key(|at| order(*at));
    for (file, position) in positions {
        let (depth, bytes, site, kind) = order((file, position));
        let key = Key {
            integers: vec![u64::from(depth), u64::from(kind), site],
            bytes: bytes.to_vec(),
        };
        if page.after.is_some_and(|a| compare(&key, a).is_le()) {
            continue;
        }
        let output = &mut page.output;
        if output.dependents.len() + output.tests.len() == page.budget.max_results as usize {
            page.more = true;
            break;
        }
        let dependent = if file {
            files.dependent(sql, position)?
        } else {
            dependent(sql, nodes, results[position].node)?
        };
        let is_test = test_path(dependent.pointer.path.as_str());
        if size(output)? + size(&dependent)? + page.index_bytes + 1200
            > page.budget.max_bytes as usize
        {
            page.more = true;
            break;
        }
        if is_test {
            output.tests.push(dependent);
        } else {
            output.dependents.push(dependent);
        }
        page.last = Some(key);
    }
    Ok(())
}
fn fill_records(
    env: &QueryEnv<'_>,
    sql: &SqlView<'_>,
    snapshot: &Snapshot,
    root_files: &[i64],
    end: Instant,
    page: &mut Page<'_>,
) -> AtlasResult<bool> {
    let records = super::impact_records::collect(env, sql, snapshot, root_files, end)?;
    for record in records.rows {
        if page.after.is_some_and(|a| compare(&record.key, a).is_le()) {
            continue;
        }
        let output = &mut page.output;
        if output.dependents.len() + output.tests.len() + output.records.len()
            == page.budget.max_results as usize
            || size(output)? + size(&record.hit)? + page.index_bytes + 1200
                > page.budget.max_bytes as usize
        {
            page.more = true;
            break;
        }
        page.last = Some(record.key);
        output.records.push(record.hit);
    }
    Ok(records.limited)
}
fn validate_key(key: &Key) -> AtlasResult<()> {
    if key.integers.len() != 3 {
        return Err(cursor::invalid("invalid impact ordering key"));
    }
    match key.integers[1] {
        0 | 1 if (1..=3).contains(&key.integers[0]) && key.bytes.len() == 48 => Ok(()),
        2 if key.integers[0] == 4 => super::find::validate_key(&Key {
            integers: vec![4, key.integers[2]],
            bytes: key.bytes.clone(),
        }),
        _ => Err(cursor::invalid("invalid impact ordering key")),
    }
}
fn compare(a: &Key, b: &Key) -> std::cmp::Ordering {
    a.integers[0].cmp(&b.integers[0]).then_with(|| {
        if a.integers[0] == 4 {
            (a.integers[2], &a.bytes).cmp(&(b.integers[2], &b.bytes))
        } else {
            (&a.bytes, a.integers[2], a.integers[1]).cmp(&(&b.bytes, b.integers[2], b.integers[1]))
        }
    })
}

fn seed(
    env: &QueryEnv<'_>,
    sql: &SqlView<'_>,
    snapshot: &Snapshot,
    target: &AtlasTarget,
    nodes: &mut Vec<Node>,
    files: &mut Vec<i64>,
) -> AtlasResult<bool> {
    match target {
        AtlasTarget::Symbol(_) | AtlasTarget::File(_) | AtlasTarget::Auto(_) => {
            if let Some(target) = resolve(sql, target)? {
                files.push(target.file.rowid);
                if let Some(symbol) = target.symbol {
                    nodes.push(Node::root(symbol.rowid));
                    return Ok(false);
                }
                return file_symbols(sql, target.file.rowid, nodes);
            }
        }
        AtlasTarget::Commit(oid) => {
            let oid = match oid {
                GitObjectId::Sha1(v) => v.as_slice(),
                GitObjectId::Sha256(v) => v.as_slice(),
            };
            return seed_links(sql, "commit", oid, nodes, files);
        }
        AtlasTarget::Record(key) => {
            let pointer = {
                let mut stmt =
                    sql.prepare("SELECT kind,source_event FROM records WHERE record_id=?1")?;
                let mut rows = stmt.query([key.as_str()]).map_err(cache_error)?;
                let Some(row) = rows.next().map_err(cache_error)? else {
                    return Ok(false);
                };
                RecordPointer {
                    key: key.clone(),
                    kind: tag(get(row, 0)?)?,
                    source_event: get::<String>(row, 1)?.parse()?,
                }
            };
            match env
                .records
                .read(&snapshot.index.project, env.viewer, &pointer, None)?
            {
                Read::Present { value } if value.pointer == pointer => (),
                Read::Absent { .. } => return Ok(false),
                _ => return Err(cache_error("impact record authority unavailable")),
            }
            return seed_links(sql, "record", key.as_str().as_bytes(), nodes, files);
        }
    }
    Ok(nodes.len() > 512)
}
fn seed_links(
    sql: &SqlView<'_>,
    kind: &str,
    key: &[u8],
    nodes: &mut Vec<Node>,
    files: &mut Vec<i64>,
) -> AtlasResult<bool> {
    let (targets, mut limited) = super::impact_files::linked_files(sql, kind, key)?;
    for file in targets {
        if crate::policy::built_in_denied(&file_by_id(sql, file)?.pointer.path) {
            continue;
        }
        files.push(file);
    }
    for &file in files.iter() {
        limited |= file_symbols(sql, file, nodes)?;
    }
    Ok(limited)
}
/// Adds a file's symbols as roots; true when the 512-node cap cut them short.
fn file_symbols(sql: &SqlView<'_>, file: i64, nodes: &mut Vec<Node>) -> AtlasResult<bool> {
    let statement = "SELECT id FROM symbols WHERE file=?1 ORDER BY key LIMIT 513";
    for symbol in id_column(sql, statement, [file], 0)? {
        if nodes.len() == 512 {
            return Ok(true);
        }
        if !nodes.iter().any(|n| n.symbol == symbol) {
            nodes.push(Node::root(symbol));
        }
    }
    Ok(false)
}

fn dependent(sql: &SqlView<'_>, nodes: &[Node], position: usize) -> AtlasResult<Dependent> {
    let mut node = position;
    let mut hops = Vec::with_capacity(3);
    let mut pointer = None;
    let mut symbol = None;
    while let Some(parent) = nodes[node].parent {
        let id = nodes[node]
            .via
            .ok_or_else(|| cache_error("impact node lost its edge"))?;
        let reference = reference_by_id(sql, id)?;
        let to = reference
            .enclosing
            .ok_or_else(|| cache_error("impact edge lost enclosing symbol"))?;
        let from = symbol_key(sql, nodes[parent].symbol)?;
        if pointer.is_none() {
            pointer = Some(reference.site.clone());
            symbol = Some(to);
        }
        hops.push(ImpactHop {
            from,
            to,
            site: reference.site,
            accuracy: reference.accuracy,
        });
        node = parent;
    }
    hops.reverse();
    Ok(Dependent {
        pointer: pointer.ok_or_else(|| cache_error("impact root is not a dependent"))?,
        symbol,
        hops,
        file_hops: Vec::new(),
    })
}
fn test_path(path: &str) -> bool {
    path.split('/')
        .any(|p| matches!(p, "test" | "tests" | "__tests__"))
        || path
            .rsplit('/')
            .next()
            .is_some_and(|p| p.starts_with("test_") || p.contains(".test.") || p.contains(".spec."))
}
