//! Conservative lexical and literal-module resolution. No project code runs.
pub mod catalog;
pub mod imports;
pub mod lexical;
use crate::{errors::AtlasResult, lifecycle::*, model::*};
use std::time::Instant;

#[derive(Clone, Copy, Debug)]
pub enum Export {
    Symbol(SymbolId),
    Missing,
    Ambiguous,
    /// The catalog reached a cycle, hop, row or work bound.
    Incomplete,
}
/// The implementation uses the same bounded SQL reader/writer as ingestion.
/// It must exclude stale semantic sets. Export traversal is limited to eight
/// reexports and rejects cycles; ambiguity never chooses an arbitrary row.
pub trait Catalog {
    fn file(&mut self, path: &RelativePath) -> AtlasResult<Option<FileId>>;
    fn export(&mut self, file: FileId, name: &str, max_hops: u8) -> AtlasResult<Export>;
}
#[derive(Debug, Default)]
pub struct ResolutionReport {
    pub resolved: u32,
    pub name_only: u32,
    pub incomplete: bool,
}
pub fn resolve(
    parsed: &mut ParsedFile,
    path: &RelativePath,
    catalog: &mut impl Catalog,
    deadline: Instant,
) -> AtlasResult<ResolutionReport> {
    let mut report = ResolutionReport::default();
    for index in 0..parsed.imports.len() {
        if crate::clock::now() >= deadline {
            report.incomplete = true;
            break;
        }
        resolve_import(parsed, index, path, catalog, deadline, &mut report)?;
    }
    for index in 0..parsed.references.len() {
        if crate::clock::now() >= deadline {
            report.incomplete = true;
            break;
        }
        let site = &parsed.references[index];
        let target = reference_target(parsed, site, path, catalog, &mut report)?;
        let site = &mut parsed.references[index].site;
        site.resolved_target = target.map(|v| v.0);
        site.accuracy = target.map_or(Accuracy::NameOnly, |v| v.1);
        if target.is_some() {
            report.resolved += 1
        } else {
            report.name_only += 1
        }
    }
    // Unprocessed sites are still labelled NameOnly, never promoted by budget.
    report.name_only = parsed.references.len() as u32 - report.resolved;
    Ok(report)
}
/// Binds one import to a single file and export; ambiguity leaves it unbound.
fn resolve_import(
    parsed: &mut ParsedFile,
    index: usize,
    path: &RelativePath,
    catalog: &mut impl Catalog,
    deadline: Instant,
    report: &mut ResolutionReport,
) -> AtlasResult<()> {
    let shadowed_require = parsed.imports[index].kind == ImportKind::CommonJs
        && !matches!(
            lexical::lookup(
                parsed,
                parsed.imports[index].lexical_scope,
                "require",
                parsed.imports[index].span.start_byte
            ),
            lexical::Binding::Missing
        );
    let import = &mut parsed.imports[index];
    import.target_file = None;
    import.target_symbol = None;
    import.target_namespace = false;
    if import.wildcard || shadowed_require {
        return Ok(());
    }
    let mut found = None;
    let mut context = None;
    let mut ambiguous = false;
    for candidate in imports::binding_candidates(path, import)? {
        if crate::clock::now() >= deadline {
            report.incomplete = true;
            break;
        }
        if let Some(file) = catalog.file(&candidate)? {
            context = match context {
                None => Some(file),
                Some(old) if old == file => context,
                _ => {
                    ambiguous = true;
                    None
                }
            };
            let target = if let Some(name) = import.imported_name.as_deref() {
                exported(catalog, file, name, report)?.map(|symbol| (file, Some(symbol), false))
            } else {
                Some((file, None, true))
            };
            if let Some(target) = target {
                ambiguous |= found.is_some_and(|old| old != target);
                found = Some(target);
            }
        }
    }
    for candidate in imports::namespace_candidates(path, import)? {
        if crate::clock::now() >= deadline {
            report.incomplete = true;
            break;
        }
        if let Some(file) = catalog.file(&candidate)? {
            let target = (file, None, true);
            ambiguous |= found.is_some_and(|old| old != target);
            found = Some(target);
        }
    }
    if ambiguous {
        return Ok(());
    }
    if let Some((file, symbol, namespace)) = found {
        import.target_file = Some(file);
        import.target_symbol = symbol;
        import.target_namespace = namespace;
    } else {
        import.target_file = context;
    }
    Ok(())
}
fn reference_target(
    parsed: &ParsedFile,
    site: &ParsedReference,
    path: &RelativePath,
    catalog: &mut impl Catalog,
    report: &mut ResolutionReport,
) -> AtlasResult<Option<(SymbolId, Accuracy)>> {
    let at = site.site.site.span.map_or(0, |s| s.start_byte);
    let binding = lexical::lookup(parsed, site.lexical_scope, &site.site.spelling, at);
    Ok(match (&site.qualifier, binding) {
        (ReferenceQualifier::Unqualified, lexical::Binding::Symbol(symbol)) => {
            Some((symbol, Accuracy::LexicalBinding))
        }
        (ReferenceQualifier::Unqualified, lexical::Binding::Import(index)) => parsed.imports[index]
            .target_symbol
            .map(|s| (s, Accuracy::ExplicitImport)),
        (ReferenceQualifier::Namespace(parts), _)
            if parsed.language == Language::Rust
                && parts
                    .first()
                    .is_some_and(|p| matches!(p.as_str(), "crate" | "self" | "super")) =>
        {
            let spelling = format!("{}::{}", parts.join("::"), site.site.spelling);
            rust_target(parsed, site, path, &spelling, catalog, report)?
        }
        (ReferenceQualifier::Namespace(parts), _) if parts.len() == 1 => {
            match lexical::lookup(parsed, site.lexical_scope, &parts[0], at) {
                lexical::Binding::Import(i)
                    if parsed.imports[i].target_namespace && !parsed.imports[i].wildcard =>
                {
                    match parsed.imports[i].target_file {
                        Some(file) => exported(catalog, file, &site.site.spelling, report)?
                            .map(|s| (s, Accuracy::ExplicitImport)),
                        None => None,
                    }
                }
                lexical::Binding::Symbol(id) if parsed.language == Language::Rust => {
                    let module = (id, parts[0].as_str());
                    module_member(parsed, site, module, path, catalog, report)?
                }
                _ => None,
            }
        }
        _ => None,
    })
}
/// `module::name` in Rust: an inline module answers from its own exported
/// children; a file module resolves through the module path like `self::`.
fn module_member(
    parsed: &ParsedFile,
    site: &ParsedReference,
    (id, module_name): (SymbolId, &str),
    path: &RelativePath,
    catalog: &mut impl Catalog,
    report: &mut ResolutionReport,
) -> AtlasResult<Option<(SymbolId, Accuracy)>> {
    let Some(module) = parsed
        .symbols
        .iter()
        .find(|s| s.id == id && s.kind == SymbolKind::Module)
    else {
        return Ok(None);
    };
    if module.body_hash.is_none() {
        let spelling = format!("self::{module_name}::{}", site.site.spelling);
        return rust_target(parsed, site, path, &spelling, catalog, report);
    }
    let mut children = parsed
        .symbols
        .iter()
        .filter(|s| s.parent == Some(id) && s.exported && s.name == site.site.spelling);
    let child = children.next();
    Ok(child
        .filter(|_| children.next().is_none())
        .map(|s| (s.id, Accuracy::LexicalBinding)))
}
/// One export lookup; reaching a catalog bound marks the report incomplete.
fn exported(
    catalog: &mut impl Catalog,
    file: FileId,
    name: &str,
    report: &mut ResolutionReport,
) -> AtlasResult<Option<SymbolId>> {
    Ok(match catalog.export(file, name, 8)? {
        Export::Symbol(symbol) => Some(symbol),
        Export::Incomplete => {
            report.incomplete = true;
            None
        }
        _ => None,
    })
}
fn rust_target(
    parsed: &ParsedFile,
    site: &ParsedReference,
    path: &RelativePath,
    spelling: &str,
    catalog: &mut impl Catalog,
    report: &mut ResolutionReport,
) -> AtlasResult<Option<(SymbolId, Accuracy)>> {
    let at = site.site.site.span.map_or(0, |s| s.start_byte);
    let inline_module = parsed.symbols.iter().any(|s| {
        s.kind == SymbolKind::Module
            && s.parent.is_some()
            && s.span.start_byte <= at
            && at < s.span.end_byte
    });
    let mut found = None;
    for path in imports::rust_paths(path, spelling, true, u32::from(inline_module))? {
        if let Some(file) = catalog.file(&path)?
            && let Some(symbol) = exported(catalog, file, &site.site.spelling, report)?
        {
            if found.is_some_and(|old| old != symbol) {
                return Ok(None);
            }
            found = Some(symbol);
        }
    }
    Ok(found.map(|s| (s, Accuracy::ExplicitImport)))
}
