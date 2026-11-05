//! Bounded reverse BFS is recomputed per page; no graph frontier enters a cursor.
use super::target::*;
use super::*;
#[derive(Clone, Copy)]
struct Node {
    symbol: i64,
    parent: Option<usize>,
    via: Option<i64>,
    depth: u8,
}
#[derive(Clone)]
struct ResultRow {
    node: usize,
    file: [u8; 16],
    symbol: [u8; 32],
    site: u64,
}
impl QueryReader<'_> {
    pub fn impact(&self, query: &ImpactQuery) -> AtlasResult<Answer<Read<Impact>>> {
        let end = deadline(query.budget)?;
        if !(1..=3).contains(&query.depth) {
            return Err(se_types::SeError::invalid("impact depth", "1..3"));
        }
        let digest = cursor::digest(&(
            "impact",
            &query.target,
            query.depth,
            query.include_name_only,
            &self.viewer,
        ))?;
        self.cache.read(end, |sql| {
            let snapshot = self.snapshot(sql)?;
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
            let mut limited = seed(
                self,
                sql,
                &snapshot,
                &query.target,
                &mut nodes,
                &mut root_files,
            )?;
            if nodes.is_empty() && root_files.is_empty() {
                return Ok(snapshot.unknown(
                    "no indexed impact target; inspect coverage and explicit file/record links",
                ));
            }
            if nodes.len() > 512 {
                nodes.truncate(512);
                limited = true;
            }
            let root_symbols = matches!(query.target, AtlasTarget::Symbol(_))
                .then(|| nodes.iter().map(|n| n.symbol).collect::<Vec<_>>());
            let mut results = Vec::with_capacity(32);
            let mut examined = 0;
            let mut exhausted = false;
            let mut at = 0;
            while at < nodes.len() {
                if Instant::now() >= end {
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
                    if Instant::now() >= end {
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
                        limited = true;
                        continue;
                    }
                    if nodes.iter().any(|n| n.symbol == child) {
                        continue;
                    }
                    if nodes.len() == 512 {
                        exhausted = true;
                        break;
                    }
                    let position = nodes.len();
                    nodes.push(Node {
                        symbol: child,
                        parent: Some(at),
                        via: Some(edge.id),
                        depth: node.depth + 1,
                    });
                    results.push(ResultRow {
                        node: position,
                        file: file.pointer.file.0,
                        symbol: symbol.value.id.0,
                        site: edge.start,
                    });
                }
                if exhausted {
                    break;
                }
                at += 1;
            }
            limited |= exhausted;
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
            for result in &results {
                if Instant::now() >= end {
                    limited = true;
                    break;
                }
                let mut statement = sql.prepare("SELECT id FROM files WHERE key=?1")?;
                let id: i64 = statement
                    .query_row([result.file.as_slice()], |r| r.get(0))
                    .map_err(cache_error)?;
                if !root_files.contains(&id) {
                    root_files.push(id);
                }
            }
            for id in files.file_rows() {
                if !root_files.contains(&id) {
                    root_files.push(id);
                }
            }
            let mut positions = Vec::with_capacity(results.len() + files.results.len());
            for at in 0..results.len() {
                positions.push((false, at));
            }
            for &at in &files.results {
                positions.push((true, at));
            }
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
            let mut output = Impact {
                dependents: Vec::new(),
                tests: Vec::new(),
                records: Vec::new(),
                omitted_frontier: 0,
                frontier_count_complete: !limited,
                next: None,
                complete: !limited && snapshot.negative_complete() && !advanced,
            };
            let mut last = None;
            let mut more = false;
            for (file, position) in positions {
                let (depth, bytes, site, kind) = order((file, position));
                let key = Key {
                    integers: vec![u64::from(depth), u64::from(kind), site],
                    bytes: bytes.to_vec(),
                };
                if after.is_some_and(|a| compare(&key, a).is_le()) {
                    continue;
                }
                if output.dependents.len() + output.tests.len() == query.budget.max_results as usize
                {
                    more = true;
                    break;
                }
                let dependent = if file {
                    files.dependent(sql, position)?
                } else {
                    dependent(sql, &nodes, results[position].node)?
                };
                let is_test = test_path(dependent.pointer.path.as_str());
                if size(&output)? + size(&dependent)? + size(&snapshot.index)? + 1200
                    > query.budget.max_bytes as usize
                {
                    more = true;
                    break;
                }
                if is_test {
                    output.tests.push(dependent);
                } else {
                    output.dependents.push(dependent);
                }
                last = Some(key);
            }
            let frontier = nodes.len().saturating_sub(at) as u64;
            drop(nodes);
            drop(results);
            drop(files);
            if !more {
                let records = super::impact_records::collect(
                    self,
                    sql,
                    &snapshot,
                    &root_files,
                    end - Duration::from_millis(2),
                )?;
                limited |= records.limited;
                for record in records.rows {
                    if after.is_some_and(|a| compare(&record.key, a).is_le()) {
                        continue;
                    }
                    if output.dependents.len() + output.tests.len() + output.records.len()
                        == query.budget.max_results as usize
                        || size(&output)? + size(&record.hit)? + size(&snapshot.index)? + 1200
                            > query.budget.max_bytes as usize
                    {
                        more = true;
                        break;
                    }
                    last = Some(record.key);
                    output.records.push(record.hit);
                }
            }
            output.frontier_count_complete = !limited;
            output.complete &= !limited;
            // An exhausted graph budget cannot offer a cursor claiming complete traversal.
            if limited {
                output.omitted_frontier = frontier;
                output.complete = false;
            } else if more {
                let key = last.ok_or_else(|| capacity("Atlas impact response bytes", 1, 0))?;
                output.next = Some(
                    PositionCursor::new(&snapshot.index, "impact", digest, key, None)?.encode()?,
                );
                output.complete = false;
            }

            check_output(
                snapshot.answer(Read::Present { value: output }, advanced),
                query.budget,
            )
        })
    }
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
    reader: &QueryReader<'_>,
    sql: &SqlView<'_>,
    snapshot: &Snapshot,
    target: &AtlasTarget,
    nodes: &mut Vec<Node>,
    files: &mut Vec<i64>,
) -> AtlasResult<bool> {
    match target {
        AtlasTarget::Symbol(_) | AtlasTarget::File(_) => {
            if let Some(target) = resolve(sql, target)? {
                files.push(target.file.rowid);
                if let Some(symbol) = target.symbol {
                    nodes.push(Node {
                        symbol: symbol.rowid,
                        parent: None,
                        via: None,
                        depth: 0,
                    });
                    return Ok(false);
                }
                let mut stmt =
                    sql.prepare("SELECT id FROM symbols WHERE file=?1 ORDER BY key LIMIT 513")?;
                let mut rows = stmt.query([target.file.rowid]).map_err(cache_error)?;
                while let Some(row) = rows.next().map_err(cache_error)? {
                    if nodes.len() == 512 {
                        return Ok(true);
                    }
                    nodes.push(Node {
                        symbol: get(row, 0)?,
                        parent: None,
                        via: None,
                        depth: 0,
                    });
                }
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
            match reader
                .records
                .read(&snapshot.index.project, &reader.viewer, &pointer, None)?
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
        let mut stmt =
            sql.prepare("SELECT id FROM symbols WHERE file=?1 ORDER BY key LIMIT 513")?;
        let mut rows = stmt.query([file]).map_err(cache_error)?;
        while let Some(row) = rows.next().map_err(cache_error)? {
            if nodes.len() == 512 {
                limited = true;
                break;
            }
            let symbol = get(row, 0)?;
            if nodes.iter().any(|n| n.symbol == symbol) {
                continue;
            }
            nodes.push(Node {
                symbol,
                parent: None,
                via: None,
                depth: 0,
            });
        }
    }
    Ok(limited)
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
        let mut target = sql.prepare("SELECT key FROM symbols WHERE id=?1")?;
        let from = SymbolId(
            target
                .query_row([nodes[parent].symbol], |r| r.get::<_, Vec<u8>>(0))
                .map_err(cache_error)?
                .try_into()
                .map_err(|_| cache_error("invalid symbol key"))?,
        );
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
