use super::{budget::Arena, imports, syntax::*};
use crate::{errors::AtlasResult, lifecycle::*, model::*, scope::Scope};
use se_types::code::AtlasText;
use std::time::Instant;
use tree_sitter::{Node, Tree};

struct Frame {
    node: usize,
    symbol: usize,
}
struct ScopeFrame {
    node: usize,
    scope: u32,
}
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(super) fn extract(
    scope: &Scope,
    snapshot: &SourceSnapshot,
    language: Language,
    tree: &Tree,
    deadline: Instant,
    mut arena: Arena,
) -> AtlasResult<ParsedFile> {
    let file = scope.file_id(&snapshot.path);
    let root = tree.root_node();
    let mut parsed = ParsedFile {
        file,
        language,
        content_hash: snapshot.content_hash,
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
            span: span(root),
        },
    )?;
    let module = scope.symbol_id(file, "Module", &[], snapshot.path.as_str(), 0);
    let module_name = snapshot
        .path
        .as_str()
        .rsplit('/')
        .next()
        .unwrap_or(snapshot.path.as_str());
    let module_name = if module_name.len() <= 1024 {
        module_name
    } else {
        "(file)"
    };
    let name = arena.text(module_name)?;
    arena.row(
        &mut parsed.symbols,
        SymbolRecord {
            id: module,
            parent: None,
            name,
            kind: SymbolKind::Module,
            span: span(root),
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
            node: root.id(),
            symbol: 0,
        },
    )?;
    arena.push(
        &mut scopes,
        ScopeFrame {
            node: root.id(),
            scope: 0,
        },
    )?;
    let mut reasons = Vec::new();
    if root.has_error() {
        reasons.push(CoverageReason::ParseErrors)
    }
    let mut cursor = root.walk();
    let mut depth = 0usize;
    loop {
        let node = cursor.node();
        if crate::clock::now() >= deadline {
            reasons.push(CoverageReason::ParseWorkLimit);
            break;
        }
        if depth >= 128 {
            reasons.push(CoverageReason::ResultLimit);
            break;
        }
        let current_scope = scopes.last().map_or(0, |f| f.scope);
        let declaration = match language {
            Language::Rust => super::rust::declaration(node, &snapshot.bytes),
            Language::Python => super::python::declaration(node, &snapshot.bytes),
            _ => super::javascript::declaration(node, &snapshot.bytes),
        }
        .or_else(|| pattern_binding(node, language, &snapshot.bytes));
        let declaration_name = declaration.as_ref().map(|d| d.name.id());
        if let Some(declaration) = declaration {
            let name = declaration
                .name_override
                .unwrap_or_else(|| text(declaration.name, &snapshot.bytes));
            if name.is_empty() || name.len() > 1024 {
                if !reasons.contains(&CoverageReason::ByteLimit) {
                    reasons.push(CoverageReason::ByteLimit)
                }
            } else {
                let parent = symbols.last().map(|f| parsed.symbols[f.symbol].id);
                let kind = format!("{:?}", declaration.kind);
                let ordinal = parsed
                    .symbols
                    .iter()
                    .filter(|s| s.parent == parent && s.name == name && s.kind == declaration.kind)
                    .count() as u32;
                let id = scope.child_symbol_id(file, parent, &kind, name, ordinal);
                let name = arena.text(name)?;
                let doc_line = arena.text(doc_line(node, &snapshot.bytes))?;
                let Some(signature_hash) =
                    signature(node, declaration.body, &snapshot.bytes, deadline)
                else {
                    reasons.push(CoverageReason::ParseWorkLimit);
                    break;
                };
                let export_alias = if default_export(node, &snapshot.bytes) && name != "default" {
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
                    body_hash: declaration.body.map(|b| body_hash(b, &snapshot.bytes)),
                    doc_line,
                    lexical_scope: current_scope,
                };
                let index = parsed.symbols.len();
                arena.row(&mut parsed.symbols, record)?;
                arena.push(
                    &mut symbols,
                    Frame {
                        node: node.id(),
                        symbol: index,
                    },
                )?;
            }
        }
        if node != root && scope_boundary(node, language) {
            let next = parsed.scopes.len() as u32;
            arena.row(
                &mut parsed.scopes,
                LexicalScope {
                    parent: Some(current_scope),
                    span: span(node),
                },
            )?;
            arena.push(
                &mut scopes,
                ScopeFrame {
                    node: node.id(),
                    scope: next,
                },
            )?;
        }
        let current_scope = scopes.last().map_or(0, |f| f.scope);
        imports::extract(
            node,
            &snapshot.bytes,
            language,
            current_scope,
            &mut arena,
            &mut parsed.imports,
        )?;
        if let Some((name, kind, qualifier)) = reference(node, &snapshot.bytes)
            && declaration_name != Some(name.id())
        {
            let spelling = text(name, &snapshot.bytes);
            if !spelling.is_empty() && spelling.len() <= 1024 {
                let spelling = arena.text(spelling)?;
                let qualifier = match qualifier {
                    SyntaxQualifier::Unqualified => ReferenceQualifier::Unqualified,
                    SyntaxQualifier::Dynamic => ReferenceQualifier::Dynamic,
                    SyntaxQualifier::Namespace(text)
                        if text.len() <= 4096 && text.split("::").count() <= 8 =>
                    {
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
                arena.charge(snapshot.path.as_str().len())?;
                arena.row(
                    &mut parsed.references,
                    ParsedReference {
                        site: Reference {
                            site: CodePointer {
                                file,
                                path: snapshot.path.clone(),
                                span: Some(span(name)),
                                content_hash: Some(snapshot.content_hash),
                                freshness: SnapshotFreshness::Current,
                            },
                            kind,
                            spelling,
                            enclosing: symbols.last().map(|f| parsed.symbols[f.symbol].id),
                            resolved_target: None,
                            accuracy: Accuracy::NameOnly,
                        },
                        lexical_scope: current_scope,
                        qualifier,
                    },
                )?;
            } else if !reasons.contains(&CoverageReason::ByteLimit) {
                reasons.push(CoverageReason::ByteLimit)
            }
        }
        if cursor.goto_first_child() {
            depth += 1;
            continue;
        }
        loop {
            leave(cursor.node(), &mut symbols, &mut scopes);
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                if crate::clock::now() >= deadline
                    && !reasons.contains(&CoverageReason::ParseWorkLimit)
                {
                    reasons.push(CoverageReason::ParseWorkLimit)
                }
                if !reasons.is_empty() {
                    parsed.coverage = FileCoverage::Partial { reasons }
                }
                return Ok(parsed);
            }
            depth -= 1;
        }
    }
    parsed.coverage = FileCoverage::Partial { reasons };
    Ok(parsed)
}
fn leave(node: Node<'_>, symbols: &mut Vec<Frame>, scopes: &mut Vec<ScopeFrame>) {
    if symbols.last().is_some_and(|f| f.node == node.id()) {
        symbols.pop();
    }
    if scopes.last().is_some_and(|f| f.node == node.id()) {
        scopes.pop();
    }
}
