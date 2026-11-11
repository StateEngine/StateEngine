//! Syntactic bindings only. Path candidates and cross-file claims live in resolve.
use super::{
    budget::Arena,
    syntax::{literal, span, text},
};
use crate::{errors::AtlasResult, lifecycle::*, model::*};
use tree_sitter::Node;

pub(super) fn extract(
    node: Node<'_>,
    bytes: &[u8],
    language: Language,
    scope: u32,
    arena: &mut Arena,
    into: &mut Vec<ImportRecord>,
) -> AtlasResult<()> {
    match language {
        Language::JavaScript | Language::Jsx | Language::TypeScript | Language::Tsx => {
            javascript(node, bytes, scope, arena, into)
        }
        Language::Python => python(node, bytes, scope, arena, into),
        Language::Rust => rust(node, bytes, scope, arena, into),
    }
}
struct Binding<'a> {
    spelling: &'a str,
    local: Option<&'a str>,
    imported: Option<&'a str>,
    kind: ImportKind,
    reexport: bool,
    wildcard: bool,
}
fn emit(
    node: Node<'_>,
    binding: Binding<'_>,
    scope: u32,
    arena: &mut Arena,
    into: &mut Vec<ImportRecord>,
) -> AtlasResult<()> {
    if binding.spelling.is_empty()
        || binding.spelling.len() > 4096
        || binding.local.is_some_and(|v| v.len() > 1024)
        || binding.imported.is_some_and(|v| v.len() > 1024)
    {
        return Err(se_types::SeError::invalid(
            "Atlas import",
            "bounded nonempty module path and <=1024-byte bindings",
        ));
    }
    let record = ImportRecord {
        spelling: arena.text(binding.spelling)?,
        local_name: binding.local.map(|s| arena.text(s)).transpose()?,
        imported_name: binding.imported.map(|s| arena.text(s)).transpose()?,
        target_file: None,
        target_symbol: None,
        target_namespace: false,
        span: span(node),
        kind: binding.kind,
        lexical_scope: scope,
        reexport: binding.reexport,
        wildcard: binding.wildcard,
    };
    arena.row(into, record)
}
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn javascript(
    node: Node<'_>,
    bytes: &[u8],
    scope: u32,
    arena: &mut Arena,
    into: &mut Vec<ImportRecord>,
) -> AtlasResult<()> {
    let mut ancestor = Some(node);
    let mut statement = None;
    for _ in 0..6 {
        let Some(n) = ancestor else { break };
        if matches!(n.kind(), "import_statement" | "export_statement") {
            statement = Some(n);
            break;
        }
        ancestor = n.parent();
    }
    if let Some(statement) = statement {
        let Some(source) = statement
            .child_by_field_name("source")
            .and_then(|s| literal(s, bytes))
        else {
            return Ok(());
        };
        let reexport = statement.kind() == "export_statement";
        let (local, imported, wildcard) = match node.kind() {
            "import_specifier" | "export_specifier" => {
                let Some(name) = node.child_by_field_name("name") else {
                    return Ok(());
                };
                let name = literal(name, bytes).unwrap_or_else(|| text(name, bytes));
                (
                    Some(
                        node.child_by_field_name("alias")
                            .map(|n| text(n, bytes))
                            .unwrap_or(name),
                    ),
                    Some(name),
                    false,
                )
            }
            "namespace_import" => (node.named_child(0).map(|n| text(n, bytes)), None, false),
            "identifier" if node.parent().is_some_and(|p| p.kind() == "import_clause") => {
                (Some(text(node, bytes)), Some("default"), false)
            }
            "import_statement"
                if !(0..node.named_child_count())
                    .filter_map(|i| node.named_child(i as u32))
                    .any(|n| n.kind() == "import_clause") =>
            {
                (None, None, false)
            }
            "export_statement"
                if !(0..node.named_child_count())
                    .filter_map(|i| node.named_child(i as u32))
                    .any(|n| n.kind() == "export_clause") =>
            {
                (None, None, true)
            }
            _ => return Ok(()),
        };
        return emit(
            node,
            Binding {
                spelling: source,
                local,
                imported,
                kind: ImportKind::Esm,
                reexport,
                wildcard,
            },
            scope,
            arena,
            into,
        );
    }
    if node.kind() == "variable_declarator" {
        let Some(value) = node
            .child_by_field_name("value")
            .filter(|n| n.kind() == "call_expression")
        else {
            return Ok(());
        };
        if value
            .child_by_field_name("function")
            .map(|n| text(n, bytes))
            != Some("require")
        {
            return Ok(());
        }
        let Some(source) = value
            .child_by_field_name("arguments")
            .filter(|n| n.named_child_count() == 1)
            .and_then(|n| n.named_child(0))
            .and_then(|n| literal(n, bytes))
        else {
            return Ok(());
        };
        let local = node
            .child_by_field_name("name")
            .filter(|n| n.kind() == "identifier")
            .map(|n| text(n, bytes));
        return emit(
            node,
            Binding {
                spelling: source,
                local,
                imported: None,
                kind: ImportKind::CommonJs,
                reexport: false,
                wildcard: local.is_none(),
            },
            scope,
            arena,
            into,
        );
    }
    Ok(())
}
fn python(
    node: Node<'_>,
    bytes: &[u8],
    scope: u32,
    arena: &mut Arena,
    into: &mut Vec<ImportRecord>,
) -> AtlasResult<()> {
    let Some(parent) = node.parent() else {
        return Ok(());
    };
    if !matches!(parent.kind(), "import_statement" | "import_from_statement") {
        return Ok(());
    }
    if !matches!(
        node.kind(),
        "dotted_name" | "aliased_import" | "wildcard_import"
    ) {
        return Ok(());
    }
    if parent.child_by_field_name("module_name") == Some(node) {
        return Ok(());
    }
    let name = node
        .child_by_field_name("name")
        .map(|n| text(n, bytes))
        .unwrap_or_else(|| text(node, bytes));
    let alias = node.child_by_field_name("alias").map(|n| text(n, bytes));
    let (source, imported, local) = if parent.kind() == "import_from_statement" {
        let Some(source) = parent.child_by_field_name("module_name") else {
            return Ok(());
        };
        (text(source, bytes), Some(name), alias.or(Some(name)))
    } else {
        // Without an alias, `import pkg.child` binds pkg, not pkg.child. Do
        // not attribute pkg.member to an unrelated export of the child module.
        (
            if alias.is_some() {
                name
            } else {
                name.split('.').next().unwrap_or(name)
            },
            None,
            alias.or_else(|| name.split('.').next()),
        )
    };
    let wildcard = node.kind() == "wildcard_import";
    emit(
        node,
        Binding {
            spelling: source,
            local: if wildcard { None } else { local },
            imported: if wildcard { None } else { imported },
            kind: ImportKind::Python,
            reexport: false,
            wildcard,
        },
        scope,
        arena,
        into,
    )
}
fn rust(
    node: Node<'_>,
    bytes: &[u8],
    scope: u32,
    arena: &mut Arena,
    into: &mut Vec<ImportRecord>,
) -> AtlasResult<()> {
    let Some(parent) = node.parent() else {
        return Ok(());
    };
    let name = match node.kind() {
        "use_as_clause" => node.child_by_field_name("path"),
        "identifier" | "scoped_identifier" | "self" | "crate" | "super"
            if matches!(parent.kind(), "use_declaration" | "use_list") =>
        {
            Some(node)
        }
        "use_wildcard" => Some(node),
        _ => None,
    };
    let Some(name) = name else { return Ok(()) };
    let mut prefixes = Vec::new();
    let mut ancestor = node.parent();
    let mut declaration = None;
    for _ in 0..32 {
        let Some(n) = ancestor else { break };
        if n.kind() == "use_declaration" {
            declaration = Some(n);
            break;
        }
        if n.kind() == "scoped_use_list"
            && let Some(path) = n.child_by_field_name("path")
        {
            arena.push(&mut prefixes, text(path, bytes))?;
        }
        ancestor = n.parent();
    }
    let Some(declaration) = declaration else {
        return Ok(());
    };
    let suffix = text(name, bytes);
    let length = prefixes.iter().map(|p| p.len() + 2).sum::<usize>() + suffix.len();
    if length > 4096 {
        return Err(se_types::SeError::invalid(
            "Rust import path",
            "at most 4096 bytes",
        ));
    }
    arena.charge(length)?;
    let mut path = String::with_capacity(length);
    for prefix in prefixes.iter().rev() {
        path.push_str(prefix);
        path.push_str("::")
    }
    path.push_str(suffix);
    let wildcard = node.kind() == "use_wildcard";
    let imported = suffix
        .rsplit("::")
        .next()
        .filter(|s| *s != "self" && *s != "*");
    let local = node
        .child_by_field_name("alias")
        .map(|n| text(n, bytes))
        .or(imported);
    emit(
        node,
        Binding {
            spelling: &path,
            local: if wildcard { None } else { local },
            imported,
            kind: ImportKind::Rust,
            reexport: super::syntax::exported(declaration, bytes),
            wildcard,
        },
        scope,
        arena,
        into,
    )
}
