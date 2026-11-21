use super::{budget::Arena, imports, syntax::*};
use crate::{errors::AtlasResult, lifecycle::*, model::*, scope::Scope};
use se_types::code::AtlasText;
use tree_sitter::{Node, Tree};

struct Frame {
    node: usize,
    symbol: usize,
}
struct ScopeFrame {
    node: usize,
    scope: u32,
}
struct Ctx<'a> {
    scope: &'a Scope,
    snapshot: &'a SourceSnapshot,
    file: FileId,
    language: Language,
    root: Node<'a>,
}
/// Mutable extraction rows, kept apart from the ancestry so a declared
/// symbol can borrow the ancestry while the rows are being filled.
struct State {
    parsed: ParsedFile,
    symbols: Vec<Frame>,
    scopes: Vec<ScopeFrame>,
    reasons: Vec<CoverageReason>,
}
fn module_header(ctx: &Ctx, arena: &mut Arena) -> AtlasResult<State> {
    let path = ctx.snapshot.path.as_str();
    let mut parsed = ParsedFile {
        file: ctx.file,
        language: ctx.language,
        content_hash: ctx.snapshot.content_hash,
        coverage: FileCoverage::Indexed,
        symbols: Vec::new(),
        imports: Vec::new(),
        references: Vec::new(),
        scopes: Vec::new(),
    };
    arena.row(
        &mut parsed.scopes,
        LexicalScope {
            parent: None,
            span: span(ctx.root),
        },
    )?;
    let module = ctx.scope.symbol_id(ctx.file, "Module", &[], path, 0);
    let module_name = path.rsplit('/').next().unwrap_or(path);
    let name = arena.text(if module_name.len() <= 1024 {
        module_name
    } else {
        "(file)"
    })?;
    arena.row(
        &mut parsed.symbols,
        SymbolRecord {
            id: module,
            parent: None,
            name,
            kind: SymbolKind::Module,
            span: span(ctx.root),
            exported: false,
            export_alias: None,
            signature_hash: None,
            body_hash: None,
            doc_line: String::new(),
            lexical_scope: 0,
        },
    )?;
    let mut symbols = Vec::new();
    let mut scopes = Vec::new();
    arena.push(
        &mut symbols,
        Frame {
            node: ctx.root.id(),
            symbol: 0,
        },
    )?;
    arena.push(
        &mut scopes,
        ScopeFrame {
            node: ctx.root.id(),
            scope: 0,
        },
    )?;
    let mut reasons = Vec::new();
    if ctx.root.has_error() {
        reasons.push(CoverageReason::ParseErrors)
    }
    Ok(State {
        parsed,
        symbols,
        scopes,
        reasons,
    })
}
pub(super) fn extract(
    scope: &Scope,
    snapshot: &SourceSnapshot,
    language: Language,
    tree: &Tree,
    mut arena: Arena,
) -> AtlasResult<ParsedFile> {
    let ctx = Ctx {
        scope,
        snapshot,
        file: scope.file_id(&snapshot.path),
        language,
        root: tree.root_node(),
    };
    let mut state = module_header(&ctx, &mut arena)?;
    let mut cursor = ctx.root.walk();
    // Node::parent searches from the root; reuse the cursor's ancestry instead.
    // The extraction arena and existing depth bound cover these retained nodes.
    let mut ancestors = Vec::new();
    loop {
        let node = cursor.node();
        if ancestors.len() >= 128 {
            state.reasons.push(CoverageReason::ResultLimit);
            break;
        }
        let current_scope = state.scopes.last().map_or(0, |f| f.scope);
        let declaration = match language {
            Language::Rust => super::rust::declaration(node, &ancestors, &snapshot.bytes),
            Language::Python => super::python::declaration(node, &ancestors, &snapshot.bytes),
            _ => super::javascript::declaration(node, &ancestors, &snapshot.bytes),
        }
        .or_else(|| pattern_binding(node, &ancestors, language, &snapshot.bytes));
        let declaration_name = declaration.as_ref().map(|d| d.name.id());
        if let Some(declaration) = declaration {
            record_declaration(&ctx, &ancestors, &mut state, node, declaration, &mut arena)?;
        }
        enter_scope(&ctx, &mut state, node, current_scope, &mut arena)?;
        let current_scope = state.scopes.last().map_or(0, |f| f.scope);
        imports::extract(
            node,
            &ancestors,
            &snapshot.bytes,
            language,
            current_scope,
            &mut arena,
            &mut state.parsed.imports,
        )?;
        record_reference(
            &ctx,
            &ancestors,
            &mut state,
            node,
            declaration_name,
            &mut arena,
        )?;
        if cursor.goto_first_child() {
            arena.push(&mut ancestors, node)?;
            continue;
        }
        loop {
            leave(cursor.node(), &mut state.symbols, &mut state.scopes);
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                if !state.reasons.is_empty() {
                    state.parsed.coverage = FileCoverage::Partial {
                        reasons: state.reasons,
                    }
                }
                return Ok(state.parsed);
            }
            ancestors.pop();
        }
    }
    state.parsed.coverage = FileCoverage::Partial {
        reasons: state.reasons,
    };
    Ok(state.parsed)
}
fn record_declaration(
    ctx: &Ctx,
    ancestors: &[Node],
    state: &mut State,
    node: Node,
    declaration: Declaration,
    arena: &mut Arena,
) -> AtlasResult<()> {
    let current_scope = state.scopes.last().map_or(0, |f| f.scope);
    let name = declaration
        .name_override
        .unwrap_or_else(|| text(declaration.name, &ctx.snapshot.bytes));
    if name.is_empty() || name.len() > 1024 {
        if !state.reasons.contains(&CoverageReason::ByteLimit) {
            state.reasons.push(CoverageReason::ByteLimit)
        }
        return Ok(());
    }
    let parent = state
        .symbols
        .last()
        .map(|f| state.parsed.symbols[f.symbol].id);
    let kind = format!("{:?}", declaration.kind);
    let ordinal = state
        .parsed
        .symbols
        .iter()
        .filter(|s| s.parent == parent && s.name == name && s.kind == declaration.kind)
        .count() as u32;
    let id = ctx
        .scope
        .child_symbol_id(ctx.file, parent, &kind, name, ordinal);
    let name = arena.text(name)?;
    let doc_line = arena.text(doc_line(node, &ctx.snapshot.bytes))?;
    let signature_hash = signature(node, declaration.body, &ctx.snapshot.bytes);
    let export_alias = if default_export(ancestors, &ctx.snapshot.bytes) && name != "default" {
        Some(arena.text("default")?)
    } else {
        None
    };
    let record = SymbolRecord {
        id,
        parent,
        name,
        kind: declaration.kind,
        span: span(node),
        exported: declaration.exported,
        export_alias,
        signature_hash: Some(signature_hash),
        body_hash: declaration.body.map(|b| body_hash(b, &ctx.snapshot.bytes)),
        doc_line,
        lexical_scope: current_scope,
    };
    let index = state.parsed.symbols.len();
    arena.row(&mut state.parsed.symbols, record)?;
    arena.push(
        &mut state.symbols,
        Frame {
            node: node.id(),
            symbol: index,
        },
    )
}
fn enter_scope(
    ctx: &Ctx,
    state: &mut State,
    node: Node,
    current_scope: u32,
    arena: &mut Arena,
) -> AtlasResult<()> {
    if node != ctx.root && scope_boundary(node, ctx.language) {
        let next = state.parsed.scopes.len() as u32;
        arena.row(
            &mut state.parsed.scopes,
            LexicalScope {
                parent: Some(current_scope),
                span: span(node),
            },
        )?;
        arena.push(
            &mut state.scopes,
            ScopeFrame {
                node: node.id(),
                scope: next,
            },
        )
    } else {
        Ok(())
    }
}
fn record_reference(
    ctx: &Ctx,
    ancestors: &[Node],
    state: &mut State,
    node: Node,
    declaration_name: Option<usize>,
    arena: &mut Arena,
) -> AtlasResult<()> {
    let current_scope = state.scopes.last().map_or(0, |f| f.scope);
    let Some((name, kind, qualifier)) = reference(node, ancestors, &ctx.snapshot.bytes) else {
        return Ok(());
    };
    if declaration_name == Some(name.id()) {
        return Ok(());
    }
    let spelling = text(name, &ctx.snapshot.bytes);
    if spelling.is_empty() || spelling.len() > 1024 {
        if !state.reasons.contains(&CoverageReason::ByteLimit) {
            state.reasons.push(CoverageReason::ByteLimit)
        }
        return Ok(());
    }
    let spelling = arena.text(spelling)?;
    let qualifier = match qualifier {
        SyntaxQualifier::Unqualified => ReferenceQualifier::Unqualified,
        SyntaxQualifier::Dynamic => ReferenceQualifier::Dynamic,
        SyntaxQualifier::Namespace(text) if text.len() <= 4096 && text.split("::").count() <= 8 => {
            let count = text.split("::").count();
            arena.charge(count * std::mem::size_of::<String>())?;
            let mut parts = Vec::with_capacity(count);
            for part in text.split("::") {
                parts.push(arena.text(part)?);
            }
            ReferenceQualifier::Namespace(parts)
        }
        _ => ReferenceQualifier::Dynamic,
    };
    arena.charge(ctx.snapshot.path.as_str().len())?;
    let enclosing = state
        .symbols
        .last()
        .map(|f| state.parsed.symbols[f.symbol].id);
    arena.row(
        &mut state.parsed.references,
        ParsedReference {
            site: Reference {
                site: CodePointer {
                    file: ctx.file,
                    path: ctx.snapshot.path.clone(),
                    span: Some(span(name)),
                    content_hash: Some(ctx.snapshot.content_hash),
                    freshness: SnapshotFreshness::Current,
                },
                kind,
                spelling,
                enclosing,
                resolved_target: None,
                accuracy: Accuracy::NameOnly,
            },
            lexical_scope: current_scope,
            qualifier,
        },
    )
}
fn leave(node: Node<'_>, symbols: &mut Vec<Frame>, scopes: &mut Vec<ScopeFrame>) {
    if symbols.last().is_some_and(|f| f.node == node.id()) {
        symbols.pop();
    }
    if scopes.last().is_some_and(|f| f.node == node.id()) {
        scopes.pop();
    }
}
