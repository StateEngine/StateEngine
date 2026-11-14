//! File import edges do not require a fabricated enclosing or target symbol.
use super::target::reference_by_id;
use super::*;
use rusqlite::params;
#[derive(Clone, Copy)]
enum Site {
    Import(i64),
    Reference(i64),
}
#[derive(Clone, Copy)]
struct Node {
    row: i64,
    key: FileId,
    parent: Option<usize>,
    via: Option<Site>,
    start: u64,
    depth: u8,
}
struct Edges {
    sites: Vec<(Site, i64, u64)>,
    examined: usize,
    limited: bool,
}
pub(super) struct FileGraph {
    nodes: Vec<Node>,
    pub results: Vec<usize>,
    pub limited: bool,
    pub examined: usize,
}
impl FileGraph {
    pub fn file_rows(&self) -> impl Iterator<Item = i64> + '_ {
        self.nodes.iter().map(|n| n.row)
    }
    pub fn order(&self, at: usize) -> (u8, [u8; 48], u64, u8) {
        let node = self.nodes[at];
        let mut bytes = [0; 48];
        bytes[..16].copy_from_slice(&node.key.0);
        (node.depth, bytes, node.start, 1)
    }
    pub fn dependent(&self, sql: &SqlView<'_>, at: usize) -> AtlasResult<Dependent> {
        let mut node = at;
        let mut hops = Vec::with_capacity(3);
        while let Some(parent) = self.nodes[node].parent {
            let via = self.nodes[node]
                .via
                .ok_or_else(|| cache_error("file impact edge lost site"))?;
            let (site, start, end, accuracy) = match via {
                Site::Import(id) => {
                    let (start, end) = {
                        let mut statement =
                            sql.prepare("SELECT start_byte,end_byte FROM imports WHERE id=?1")?;
                        let mut rows = statement.query([id]).map_err(cache_error)?;
                        let row = rows
                            .next()
                            .map_err(cache_error)?
                            .ok_or_else(|| cache_error("impact import disappeared"))?;
                        (number(row, 0)?, number(row, 1)?)
                    };
                    (
                        file_by_id(sql, self.nodes[node].row)?.pointer,
                        start,
                        end,
                        Accuracy::ExplicitImport,
                    )
                }
                Site::Reference(id) => {
                    let reference = reference_by_id(sql, id)?;
                    let span = reference
                        .site
                        .span
                        .ok_or_else(|| cache_error("anonymous reference lost its span"))?;
                    (
                        reference.site,
                        span.start_byte,
                        span.end_byte,
                        reference.accuracy,
                    )
                }
            };
            hops.push(FileImpactHop {
                from: self.nodes[parent].key,
                to: self.nodes[node].key,
                site,
                start_byte: start,
                end_byte: end,
                accuracy,
            });
            node = parent;
        }
        hops.reverse();
        Ok(Dependent {
            pointer: file_by_id(sql, self.nodes[at].row)?.pointer,
            symbol: None,
            hops: Vec::new(),
            file_hops: hops,
        })
    }
}
pub(super) fn collect(
    sql: &SqlView<'_>,
    roots: Vec<i64>,
    depth: u8,
    node_limit: usize,
    edge_limit: usize,
    end: Instant,
    root_symbols: Option<&[i64]>,
) -> AtlasResult<FileGraph> {
    let mut graph = FileGraph {
        nodes: Vec::new(),
        results: Vec::new(),
        limited: false,
        examined: 0,
    };
    for row in roots {
        if graph.nodes.iter().any(|n| n.row == row) {
            continue;
        }
        if graph.nodes.len() == node_limit {
            graph.limited = true;
            break;
        }
        let file = file_by_id(sql, row)?;
        if crate::policy::built_in_denied(&file.pointer.path)
            || !matches!(file.coverage, FileCoverage::Indexed)
        {
            graph.limited = true;
            continue;
        }
        graph.nodes.push(Node {
            row,
            key: file.pointer.file,
            parent: None,
            via: None,
            start: 0,
            depth: 0,
        });
    }
    let mut at = 0;
    let mut exhausted = false;
    while at < graph.nodes.len() {
        let node = graph.nodes[at];
        if node.depth >= depth {
            at += 1;
            continue;
        }
        if crate::clock::now() >= end {
            exhausted = true;
            break;
        }
        let edges = edges(
            sql,
            node.row,
            if node.depth == 0 { root_symbols } else { None },
            edge_limit.saturating_sub(graph.examined),
            end,
        )?;
        exhausted |= edges.limited;
        graph.examined += edges.examined;
        for (site, file, start) in edges.sites {
            let seen = graph.nodes.iter().any(|n| n.row == file);
            let self_site = matches!(site, Site::Reference(_))
                && file == node.row
                && node.depth == 0
                && !graph
                    .nodes
                    .iter()
                    .any(|n| n.row == file && n.parent.is_some());
            if seen && !self_site {
                continue;
            }
            if graph.nodes.len() == node_limit {
                exhausted = true;
                break;
            }
            let file_row = file_by_id(sql, file)?;
            if crate::policy::built_in_denied(&file_row.pointer.path)
                || !matches!(file_row.coverage, FileCoverage::Indexed)
            {
                graph.limited = true;
                continue;
            }
            let position = graph.nodes.len();
            graph.nodes.push(Node {
                row: file,
                key: file_row.pointer.file,
                parent: Some(at),
                via: Some(site),
                start,
                depth: node.depth + 1,
            });
            graph.results.push(position);
        }
        if exhausted {
            break;
        }
        at += 1;
    }
    graph.limited |= exhausted;
    Ok(graph)
}
/// Every range closes before file metadata or a hop is materialized. Resolved
/// top-level references keep a real file/span rather than a fabricated symbol.
fn edges(
    sql: &SqlView<'_>,
    file: i64,
    targets: Option<&[i64]>,
    limit: usize,
    end: Instant,
) -> AtlasResult<Edges> {
    let mut output = Vec::new();
    let mut examined = 0;
    let mut limited = false;
    {
        let mut statement=sql.prepare("SELECT id,file,start_byte FROM imports WHERE target_file=?1 AND resolution='ExplicitImport' ORDER BY file,start_byte,id LIMIT 1025")?;
        let mut rows = statement.query([file]).map_err(cache_error)?;
        while let Some(row) = rows.next().map_err(cache_error)? {
            if examined == limit || crate::clock::now() >= end {
                limited = true;
                break;
            }
            examined += 1;
            output.push((Site::Import(get(row, 0)?), get(row, 1)?, number(row, 2)?));
        }
    }
    let symbols = if let Some(targets) = targets {
        targets.to_vec()
    } else {
        let mut statement =
            sql.prepare("SELECT id FROM symbols WHERE file=?1 ORDER BY key LIMIT 513")?;
        let mut rows = statement.query([file]).map_err(cache_error)?;
        let mut ids = Vec::new();
        while let Some(row) = rows.next().map_err(cache_error)? {
            if ids.len() == 512 {
                limited = true;
                break;
            }
            ids.push(get::<i64>(row, 0)?);
        }
        ids
    };
    for symbol in symbols {
        if crate::clock::now() >= end {
            limited = true;
            break;
        }
        let (references, partial) =
            super::impact_edges::read(sql, symbol, false, limit.saturating_sub(examined), end)?;
        limited |= partial;
        examined += references.len();
        for reference in references {
            if let Some(enclosing) = reference.enclosing {
                let (symbol, _) = symbol_by_id(sql, enclosing)?;
                if symbol.value.kind != SymbolKind::Module || symbol.value.parent.is_some() {
                    continue;
                }
            }
            output.push((
                Site::Reference(reference.id),
                reference.file,
                reference.start,
            ));
        }
        if examined == limit {
            limited = true;
            break;
        }
    }
    Ok(Edges {
        sites: output,
        examined,
        limited,
    })
}
/// Bounded source links are resolved through small point statements, never a
/// large UNION that shares its statement reservation with metadata loads.
pub(super) fn linked_files(
    sql: &SqlView<'_>,
    kind: &str,
    key: &[u8],
) -> AtlasResult<(Vec<i64>, bool)> {
    let source = {
        let statement = if kind == "record" {
            "SELECT id FROM records WHERE record_id=CAST(?1 AS TEXT)"
        } else {
            "SELECT id FROM commits WHERE oid=?1"
        };
        let mut stmt = sql.prepare(statement)?;
        let mut rows = stmt.query([key]).map_err(cache_error)?;
        rows.next()
            .map_err(cache_error)?
            .map(|r| get::<i64>(r, 0))
            .transpose()?
    };
    let Some(source) = source else {
        return Ok((Vec::new(), false));
    };
    let targets = {
        let mut stmt=sql.prepare("SELECT target_kind,target_key FROM mentions WHERE source_kind=?1 AND source_id=?2 AND target_kind IN ('file','symbol') ORDER BY target_kind,target_key LIMIT 257")?;
        let mut rows = stmt.query(params![kind, source]).map_err(cache_error)?;
        let mut output = Vec::new();
        while let Some(row) = rows.next().map_err(cache_error)? {
            output.push((get::<String>(row, 0)?, get::<Vec<u8>>(row, 1)?));
        }
        output
    };
    let mut files = Vec::new();
    let mut limited = targets.len() == 257;
    for (kind, key) in targets.into_iter().take(256) {
        let statement = if kind == "file" {
            "SELECT id FROM files WHERE key=?1"
        } else {
            "SELECT file FROM symbols WHERE key=?1"
        };
        let file = {
            let mut stmt = sql.prepare(statement)?;
            let mut rows = stmt.query([key]).map_err(cache_error)?;
            rows.next()
                .map_err(cache_error)?
                .map(|r| get::<i64>(r, 0))
                .transpose()?
        };
        if let Some(file) = file {
            if files.contains(&file) {
                continue;
            }
            if files.len() == 32 {
                limited = true;
                break;
            }
            files.push(file);
        }
    }
    files.sort();
    Ok((files, limited))
}
