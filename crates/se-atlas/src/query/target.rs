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
fn resolve_inner(sql: &SqlView<'_>, target: &AtlasTarget) -> AtlasResult<Option<Target>> {
    if let AtlasTarget::File(path) = target {
        return Ok(file_by_path(sql, path)?.map(|file| Target { file, symbol: None }));
    }
    let AtlasTarget::Symbol(selector) = target else {
        return Err(se_types::SeError::invalid(
            "Atlas reference target",
            "a symbol, path, or path and position",
        ));
    };
    let (name, path, container, kind, line) = match selector {
        SymbolSelector::Id(id) => return resolve_by_id(sql, id),
        SymbolSelector::At { path, position } => {
            return resolve_at_position(sql, path, position);
        }
        SymbolSelector::Name {
            name,
            path,
            container,
            kind,
            line,
        } => (name, path, container, kind, line),
    };
    let file = path.as_ref().map(|p| file_by_path(sql, p)).transpose()?;
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
    let ids = {
        let mut stmt = sql.prepare(&statement)?;
        let mut rows = stmt
            .query(rusqlite::params_from_iter(values))
            .map_err(cache_error)?;
        let mut ids = Vec::with_capacity(513);
        while let Some(row) = rows.next().map_err(cache_error)? {
            ids.push(get::<i64>(row, 0)?);
        }
        ids
    };
    const TYPE_DECLARATION: &[SymbolKind] = &[
        SymbolKind::Struct,
        SymbolKind::Class,
        SymbolKind::Enum,
        SymbolKind::Interface,
        SymbolKind::Trait,
        SymbolKind::TypeAlias,
    ];
    let limited = ids.len() > 512;
    let mut candidates: Vec<(i64, bool)> = Vec::new();
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
            && symbol.kind != *kind
        {
            continue;
        }
        if let Some(line) = line
            && symbol.span.start.line != *line
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
    choose_named_target(sql, name, kind, line, limited, candidates, displays)
}
fn resolve_by_id(sql: &SqlView<'_>, id: &SymbolId) -> AtlasResult<Option<Target>> {
    let found = {
        let mut stmt = sql.prepare("SELECT id FROM symbols WHERE key=?1")?;
        let mut rows = stmt.query([id.0.as_slice()]).map_err(cache_error)?;
        rows.next()
            .map_err(cache_error)?
            .map(|r| get::<i64>(r, 0))
            .transpose()?
    };
    found.map(|id| load(sql, id)).transpose()
}
fn resolve_at_position(
    sql: &SqlView<'_>,
    path: &RelativePath,
    position: &Position,
) -> AtlasResult<Option<Target>> {
    if position.line == 0 {
        return Err(se_types::SeError::invalid(
            "Atlas position",
            "a 1-based line",
        ));
    }
    let Some(file) = file_by_path(sql, path)? else {
        return Ok(None);
    };
    let found = {
        let mut stmt=sql.prepare("SELECT id FROM symbols WHERE file=?1 AND (start_line<?2 OR (start_line=?2 AND start_column<=?3)) AND (end_line>?2 OR (end_line=?2 AND end_column>?3)) ORDER BY (end_byte-start_byte),key LIMIT 1")?;
        let mut rows = stmt
            .query(params![file.rowid, position.line, position.byte_column])
            .map_err(cache_error)?;
        rows.next()
            .map_err(cache_error)?
            .map(|r| get::<i64>(r, 0))
            .transpose()?
    };
    found
        .map(|id| {
            symbol_by_id(sql, id).map(|(symbol, _)| Target {
                file,
                symbol: Some(symbol),
            })
        })
        .transpose()
}
fn choose_named_target(
    sql: &SqlView<'_>,
    name: &QueryText,
    kind: &Option<SymbolKind>,
    line: &Option<u32>,
    limited: bool,
    candidates: Vec<(i64, bool)>,
    displays: Vec<String>,
) -> AtlasResult<Option<Target>> {
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
        let parent = {
            let mut stmt = sql.prepare("SELECT parent FROM symbols WHERE id=?1")?;
            stmt.query_row([current], |r| r.get::<_, Option<i64>>(0))
                .map_err(cache_error)?
        };
        let Some(parent) = parent else {
            break;
        };
        let name = {
            let mut stmt = sql.prepare(
                "SELECT n.text FROM symbols s JOIN names n ON n.id=s.name WHERE s.id=?1",
            )?;
            stmt.query_row([parent], |r| r.get::<_, String>(0))
                .map_err(cache_error)?
        };
        names.push(name);
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
    let spelling = {
        let mut stmt = sql.prepare("SELECT text FROM names WHERE id=?1")?;
        stmt.query_row([name], |r| r.get(0)).map_err(cache_error)?
    };
    Ok(Reference {
        site,
        kind,
        spelling,
        enclosing: enclosing.map(|id| symbol_key(sql, id)).transpose()?,
        resolved_target: target.map(|id| symbol_key(sql, id)).transpose()?,
        accuracy,
    })
}
fn symbol_key(sql: &SqlView<'_>, id: i64) -> AtlasResult<SymbolId> {
    let mut stmt = sql.prepare("SELECT key FROM symbols WHERE id=?1")?;
    let key: Vec<u8> = stmt.query_row([id], |r| r.get(0)).map_err(cache_error)?;
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
