use super::*;
use rusqlite::{params, types::Value};
pub(super) struct Target {
    pub file: FileRow,
    pub symbol: Option<SymbolRow>,
}
pub(super) fn resolve(sql: &SqlView<'_>, target: &AtlasTarget) -> AtlasResult<Option<Target>> {
    Ok(resolve_inner(sql, target)?
        .filter(|t| !crate::policy::built_in_denied(&t.file.pointer.path)))
}
/// The explicit target a positional one names, so callers see one shape.
pub(super) fn concrete(sql: &SqlView<'_>, target: &AtlasTarget) -> AtlasResult<AtlasTarget> {
    let AtlasTarget::Auto(text) = target else {
        return Ok(target.clone());
    };
    let found = auto(sql, text.as_str())?;
    Ok(match found.symbol {
        Some(symbol) => AtlasTarget::Symbol(SymbolSelector::Id(symbol.value.id)),
        None => AtlasTarget::File(found.file.pointer.path),
    })
}
/// An indexed path, then `path:line` for the symbol spanning that line (or the
/// file), then one exact symbol name; anything else is a usage error.
fn auto(sql: &SqlView<'_>, text: &str) -> AtlasResult<Target> {
    let mut found = match RelativePath::new(text) {
        Ok(path) => resolve_inner(sql, &AtlasTarget::File(path))?,
        Err(_) => None,
    };
    if found.is_none()
        && let Some((path, line)) = text.rsplit_once(':')
        && let (Ok(path), Ok(line @ 1..)) = (RelativePath::new(path), line.parse::<u32>())
    {
        // The widest column picks the smallest symbol open across the whole line.
        let position = Position {
            line,
            byte_column: u32::MAX,
        };
        let at = AtlasTarget::Symbol(SymbolSelector::At {
            path: path.clone(),
            position,
        });
        found = resolve_inner(sql, &at)?.or(resolve_inner(sql, &AtlasTarget::File(path))?);
    }
    if found.is_none() {
        found = resolve_name(sql, &QueryText::new(text)?, None, None, None, None)?;
    }
    found.ok_or_else(|| {
        se_types::SeError::invalid(
            "Atlas target",
            "an indexed path, path:line or exact symbol name; search with atlas find first",
        )
    })
}
fn resolve_inner(sql: &SqlView<'_>, target: &AtlasTarget) -> AtlasResult<Option<Target>> {
    if let AtlasTarget::File(path) = target {
        return Ok(file_by_path(sql, path)?.map(|file| Target { file, symbol: None }));
    }
    if let AtlasTarget::Auto(text) = target {
        return auto(sql, text.as_str()).map(Some);
    }
    let AtlasTarget::Symbol(selector) = target else {
        return Err(se_types::SeError::invalid(
            "Atlas reference target",
            "a symbol, path, or path and position",
        ));
    };
    let (name, path, container, kind, line) = match selector {
        SymbolSelector::Id(id) => {
            let found = id_column(
                sql,
                "SELECT id FROM symbols WHERE key=?1",
                [id.0.as_slice()],
                1,
            )?;
            return found.first().map(|&id| load(sql, id)).transpose();
        }
        SymbolSelector::At { path, position } => {
            if position.line == 0 {
                return Err(se_types::SeError::invalid(
                    "Atlas position",
                    "a 1-based line",
                ));
            }
            let Some(file) = file_by_path(sql, path)? else {
                return Ok(None);
            };
            let found = id_column(
                sql,
                "SELECT id FROM symbols WHERE file=?1 AND (start_line<?2 OR (start_line=?2 AND start_column<=?3)) AND (end_line>?2 OR (end_line=?2 AND end_column>?3)) ORDER BY (end_byte-start_byte),key LIMIT 1",
                params![file.rowid, position.line, position.byte_column],
                1,
            )?;
            return found
                .first()
                .map(|&id| {
                    symbol_by_id(sql, id).map(|(symbol, _)| Target {
                        file,
                        symbol: Some(symbol),
                    })
                })
                .transpose();
        }
        SymbolSelector::Name {
            name,
            path,
            container,
            kind,
            line,
        } => (name, path, container, kind, line),
    };
    resolve_name(sql, name, path.as_ref(), container.as_ref(), *kind, *line)
}
fn resolve_name(
    sql: &SqlView<'_>,
    name: &QueryText,
    path: Option<&RelativePath>,
    container: Option<&QueryText>,
    kind: Option<SymbolKind>,
    line: Option<u32>,
) -> AtlasResult<Option<Target>> {
    let file = path.map(|p| file_by_path(sql, p)).transpose()?;
    if file.as_ref().is_some_and(Option::is_none) {
        return Ok(None);
    }
    let mut statement =
        "SELECT s.id FROM symbols s JOIN names n ON n.id=s.name WHERE n.text=?1".to_owned();
    let mut values = vec![Value::Text(name.as_str().into())];
    if let Some(Some(file)) = &file {
        values.push(file.rowid.into());
        statement.push_str(" AND s.file=?2");
    }
    statement.push_str(" ORDER BY s.key LIMIT 513");
    let ids = id_column(sql, &statement, rusqlite::params_from_iter(values), 513)?;
    let limited = ids.len() > 512;
    let (candidates, displays) = filter(sql, ids, container, kind, line)?;
    if limited {
        return Err(capacity(
            "Atlas selector candidates; narrow path or container",
            513,
            512,
        ));
    }
    if candidates.is_empty() {
        return Ok(None);
    }
    if candidates.len() == 1 {
        return Ok(Some(load(sql, candidates[0].0)?));
    }
    // Without an explicit kind or line filter, a lone type declaration wins
    // over same-named non-declaration symbols, such as a Rust impl block
    // named after its type; anything else stays ambiguous.
    if kind.is_none() && line.is_none() {
        let declarations = candidates.iter().filter(|(_, declaration)| *declaration);
        if declarations.count() == 1 {
            let (id, _) = candidates
                .iter()
                .find(|(_, declaration)| *declaration)
                .ok_or_else(|| cache_error("missing declaration candidate"))?;
            return Ok(Some(load(sql, *id)?));
        }
    }
    Err(se_types::SeError::new(
        se_types::Detail::AtlasSymbolAmbiguous(se_types::details::AtlasSymbolAmbiguous {
            symbol: format!(
                "{} ({} candidates; {} omitted)",
                name.as_str(),
                candidates.len(),
                candidates.len().saturating_sub(20)
            ),
            candidates: displays,
        }),
    ))
}
type Selected = (Vec<(i64, bool)>, Vec<String>);
/// Selected candidates are kept as ids and declaration flags; display strings are
/// bounded to the first twenty, so the resolver never holds the rows it filters.
fn filter(
    sql: &SqlView<'_>,
    ids: Vec<i64>,
    container: Option<&QueryText>,
    kind: Option<SymbolKind>,
    line: Option<u32>,
) -> AtlasResult<Selected> {
    const TYPE_DECLARATION: &[SymbolKind] = &[
        SymbolKind::Struct,
        SymbolKind::Class,
        SymbolKind::Enum,
        SymbolKind::Interface,
        SymbolKind::Trait,
        SymbolKind::TypeAlias,
    ];
    let mut candidates = Vec::new();
    let mut displays = Vec::new();
    for id in ids.into_iter().take(512) {
        let target = load(sql, id)?;
        if crate::policy::built_in_denied(&target.file.pointer.path) {
            continue;
        }
        let symbol = &target
            .symbol
            .as_ref()
            .ok_or_else(|| cache_error("missing resolved symbol"))?
            .value;
        if let Some(kind) = kind
            && symbol.kind != kind
        {
            continue;
        }
        if let Some(line) = line
            && symbol.span.start.line != line
        {
            continue;
        }
        if let Some(container) = container
            && !container_matches(sql, id, container.as_str())?
        {
            continue;
        }
        candidates.push((id, TYPE_DECLARATION.contains(&symbol.kind)));
        if displays.len() < 20 {
            displays.push(format!(
                "{:?} {}:{} {}",
                symbol.kind,
                target.file.pointer.path.as_str(),
                symbol.span.start.line,
                symbol.name
            ));
        }
    }
    Ok((candidates, displays))
}
fn load(sql: &SqlView<'_>, id: i64) -> AtlasResult<Target> {
    let (symbol, file) = symbol_by_id(sql, id)?;
    Ok(Target {
        file: file_by_id(sql, file)?,
        symbol: Some(symbol),
    })
}
fn container_matches(sql: &SqlView<'_>, id: i64, expected: &str) -> AtlasResult<bool> {
    let mut names = Vec::new();
    let mut current = id;
    let mut visited = Vec::with_capacity(32);
    loop {
        if visited.len() == 32 || visited.contains(&current) {
            return Err(cache_error("container ancestry exceeds 32 or cycles"));
        }
        visited.push(current);
        let parent = scalar(sql, "SELECT parent FROM symbols WHERE id=?1", [current])?;
        let Some(parent) = parent else {
            break;
        };
        let name = "SELECT n.text FROM symbols s JOIN names n ON n.id=s.name WHERE s.id=?1";
        names.push(scalar::<String>(sql, name, [parent])?);
        current = parent;
    }
    names.reverse();
    Ok(names.join("::") == expected || names.join(".") == expected)
}
pub(super) fn reference_by_id(sql: &SqlView<'_>, id: i64) -> AtlasResult<Reference> {
    let (file, enclosing, target, name, kind, span, accuracy) = {
        let mut stmt=sql.prepare("SELECT file,enclosing,target,spelling,kind,start_byte,end_byte,start_line,start_column,end_line,end_column,accuracy FROM refs WHERE id=?1")?;
        let mut rows = stmt.query([id]).map_err(cache_error)?;
        let row = rows
            .next()
            .map_err(cache_error)?
            .ok_or_else(|| cache_error("reference disappeared in snapshot"))?;
        (
            get::<i64>(row, 0)?,
            get::<Option<i64>>(row, 1)?,
            get::<Option<i64>>(row, 2)?,
            get::<i64>(row, 3)?,
            tag(get(row, 4)?)?,
            span(row, 5)?,
            tag(get(row, 11)?)?,
        )
    };
    let mut site = file_by_id(sql, file)?.pointer;
    site.span = Some(span);
    let spelling = scalar(sql, "SELECT text FROM names WHERE id=?1", [name])?;
    Ok(Reference {
        site,
        kind,
        spelling,
        enclosing: enclosing.map(|id| symbol_key(sql, id)).transpose()?,
        resolved_target: target.map(|id| symbol_key(sql, id)).transpose()?,
        accuracy,
    })
}
pub(super) fn symbol_key(sql: &SqlView<'_>, id: i64) -> AtlasResult<SymbolId> {
    let key: Vec<u8> = scalar(sql, "SELECT key FROM symbols WHERE id=?1", [id])?;
    Ok(SymbolId(
        key.try_into()
            .map_err(|_| cache_error("invalid symbol key"))?,
    ))
}
pub(super) fn reference_key(reference: &Reference, id: i64) -> AtlasResult<Key> {
    let span = reference
        .site
        .span
        .ok_or_else(|| cache_error("reference has no span"))?;
    Ok(Key {
        integers: vec![
            u64::from(reference.accuracy == Accuracy::NameOnly),
            span.start_byte,
            span.end_byte,
            u64::try_from(id).map_err(cache_error)?,
        ],
        bytes: [
            reference.site.file.0.as_slice(),
            kind_name(reference.kind).as_bytes(),
        ]
        .concat(),
    })
}
pub(super) fn kind_name(kind: ReferenceKind) -> &'static str {
    match kind {
        ReferenceKind::Call => "Call",
        ReferenceKind::Import => "Import",
        ReferenceKind::Export => "Export",
        ReferenceKind::TypeUse => "TypeUse",
        ReferenceKind::ValueUse => "ValueUse",
    }
}
