use crate::model::*;
use std::time::Instant;
use tree_sitter::Node;

pub(super) struct Declaration<'a> {
    pub name: Node<'a>,
    pub name_override: Option<&'static str>,
    pub kind: SymbolKind,
    pub body: Option<Node<'a>>,
    pub exported: bool,
}
pub(super) fn span(node: Node<'_>) -> Span {
    let a = node.start_position();
    let b = node.end_position();
    Span {
        start: Position {
            line: a.row as u32 + 1,
            byte_column: a.column as u32,
        },
        end: Position {
            line: b.row as u32 + 1,
            byte_column: b.column as u32,
        },
        start_byte: node.start_byte() as u64,
        end_byte: node.end_byte() as u64,
    }
}
pub(super) fn text<'a>(node: Node<'_>, bytes: &'a [u8]) -> &'a str {
    // The caller admits UTF-8 before creating the tree. An erroneous grammar
    // span is not an exact name; extraction marks it partial rather than lossy.
    node.utf8_text(bytes).unwrap_or("")
}
pub(super) fn literal<'a>(node: Node<'_>, bytes: &'a [u8]) -> Option<&'a str> {
    let value = text(node, bytes);
    let first = value.as_bytes().first()?;
    if !matches!(first, b'\'' | b'"') || value.as_bytes().last() != Some(first) || value.len() < 2 {
        return None;
    }
    let value = &value[1..value.len() - 1];
    (!value.contains(['\\', '\0', '\n', '\r'])).then_some(value)
}
pub(super) fn exported(node: Node<'_>, bytes: &[u8]) -> bool {
    node.parent().is_some_and(|n| {
        matches!(n.kind(), "export_statement" | "ambient_declaration")
            || matches!(n.kind(), "lexical_declaration" | "variable_declaration")
                && n.parent().is_some_and(|p| p.kind() == "export_statement")
    }) || node
        .child_by_field_name("name")
        .is_some_and(|n| !text(n, bytes).starts_with('_'))
        && matches!(node.kind(), "function_definition" | "class_definition")
        || (0..node.named_child_count())
            .filter_map(|i| node.named_child(i as u32))
            .any(|n| n.kind() == "visibility_modifier")
}
pub(super) fn body_hash(node: Node<'_>, bytes: &[u8]) -> ContentHash {
    let mut range = node.byte_range();
    if bytes.get(range.start) == Some(&b'{')
        && range.end > range.start
        && bytes.get(range.end - 1) == Some(&b'}')
    {
        range.start += 1;
        range.end -= 1;
    }
    ContentHash(*blake3::hash(&bytes[range]).as_bytes())
}
pub(super) fn signature(
    node: Node<'_>,
    body: Option<Node<'_>>,
    bytes: &[u8],
    deadline: Instant,
) -> Option<ContentHash> {
    let end = body.map_or(node.end_byte(), |b| b.start_byte());
    let mut hash = blake3::Hasher::new();
    let mut cursor = node.walk();
    loop {
        if crate::clock::now() >= deadline {
            return None;
        }
        let n = cursor.node();
        let skip = n.start_byte() >= end || n.kind().contains("comment");
        if !skip && n.child_count() == 0 {
            let value = &bytes[n.byte_range()];
            hash.update(&(value.len() as u64).to_be_bytes());
            hash.update(value);
        }
        if !skip && cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return Some(ContentHash(*hash.finalize().as_bytes()));
            }
        }
    }
}
pub(super) fn doc_line<'a>(node: Node<'_>, bytes: &'a [u8]) -> &'a str {
    let line = if let Some(previous) = node
        .prev_named_sibling()
        .filter(|n| n.kind().contains("comment"))
    {
        let comment = text(previous, bytes).trim();
        if comment.starts_with("///") || comment.starts_with("/**") || comment.starts_with("//!") {
            comment
                .trim_start_matches('/')
                .trim_start_matches('*')
                .trim()
        } else {
            ""
        }
    } else if node.kind() == "function_definition" || node.kind() == "class_definition" {
        node.child_by_field_name("body")
            .and_then(|b| b.named_child(0))
            .filter(|n| n.kind() == "expression_statement")
            .and_then(|n| n.named_child(0))
            .filter(|n| n.kind() == "string")
            .map(|n| text(n, bytes).trim_matches(['\'', '"']))
            .unwrap_or("")
    } else {
        ""
    };
    let line = line.lines().next().unwrap_or("");
    let mut end = line.len().min(160);
    while !line.is_char_boundary(end) {
        end -= 1
    }
    &line[..end]
}
pub(super) fn scope_boundary(node: Node<'_>, language: Language) -> bool {
    let kind = node.kind();
    if language == Language::Python {
        return matches!(
            kind,
            "function_definition"
                | "class_definition"
                | "lambda"
                | "list_comprehension"
                | "dictionary_comprehension"
                | "set_comprehension"
                | "generator_expression"
        );
    }
    matches!(
        kind,
        "block"
            | "statement_block"
            | "function_declaration"
            | "function_item"
            | "function_signature_item"
            | "arrow_function"
            | "function_expression"
            | "generator_function"
            | "method_definition"
            | "method_signature"
            | "class_declaration"
            | "class"
            | "interface_declaration"
            | "trait_item"
            | "impl_item"
            | "mod_item"
            | "internal_module"
            | "closure_expression"
    )
}
/// Returns a syntactic use, not every identifier token. Member calls remain
/// qualified candidates; lexical/import resolution decides their accuracy later.
pub(super) enum SyntaxQualifier<'a> {
    Unqualified,
    Namespace(&'a str),
    Dynamic,
}
pub(super) fn reference<'a, 'b>(
    node: Node<'a>,
    bytes: &'b [u8],
) -> Option<(Node<'a>, ReferenceKind, SyntaxQualifier<'b>)> {
    let kind = match node.kind() {
        "jsx_opening_element" | "jsx_self_closing_element" => {
            let name = node.child_by_field_name("name")?;
            if name.kind() != "identifier"
                || !text(name, bytes)
                    .chars()
                    .next()
                    .is_some_and(char::is_uppercase)
            {
                return None;
            }
            return Some((name, ReferenceKind::ValueUse, SyntaxQualifier::Unqualified));
        }
        "call_expression" | "call" => ReferenceKind::Call,
        "new_expression" => ReferenceKind::Call,
        "type_identifier" => {
            let parent = node.parent()?;
            if parent.child_by_field_name("name") == Some(node) {
                return None;
            }
            return Some((node, ReferenceKind::TypeUse, SyntaxQualifier::Unqualified));
        }
        "identifier" | "shorthand_property_identifier" => {
            let parent = node.parent()?;
            if parent.kind() == "type" {
                return Some((node, ReferenceKind::TypeUse, SyntaxQualifier::Unqualified));
            }
            let rhs = ["value", "right", "condition", "object"]
                .into_iter()
                .any(|field| parent.child_by_field_name(field) == Some(node));
            if !rhs
                && !matches!(
                    parent.kind(),
                    "arguments"
                        | "argument_list"
                        | "return_statement"
                        | "return_expression"
                        | "binary_expression"
                        | "binary_operator"
                        | "unary_expression"
                        | "unary_operator"
                        | "expression_statement"
                        | "if_expression"
                        | "if_statement"
                        | "await_expression"
                        | "yield"
                        | "array"
                        | "array_expression"
                        | "tuple_expression"
                        | "block"
                        | "object"
                )
            {
                return None;
            }
            return Some((node, ReferenceKind::ValueUse, SyntaxQualifier::Unqualified));
        }
        _ => return None,
    };
    let function = node
        .child_by_field_name("function")
        .or_else(|| node.child_by_field_name("constructor"))?;
    if matches!(function.kind(), "identifier" | "type_identifier") {
        return Some((function, kind, SyntaxQualifier::Unqualified));
    }
    let name = function
        .child_by_field_name("property")
        .or_else(|| function.child_by_field_name("field"))
        .or_else(|| function.child_by_field_name("attribute"))
        .or_else(|| function.child_by_field_name("name"))?;
    let prefix = function
        .child_by_field_name("object")
        .or_else(|| function.child_by_field_name("value"))
        .or_else(|| function.child_by_field_name("path"));
    let qualifier = prefix
        .filter(|p| {
            matches!(
                p.kind(),
                "identifier" | "scoped_identifier" | "crate" | "self" | "super"
            )
        })
        .map(|p| SyntaxQualifier::Namespace(text(p, bytes)))
        .unwrap_or(SyntaxQualifier::Dynamic);
    Some((name, kind, qualifier))
}

/// Individual leaves of supported destructuring patterns are bindings too.
/// Keys, type syntax and default-value expressions are not declaration names.
pub(super) fn pattern_binding<'a>(
    node: Node<'a>,
    language: Language,
    bytes: &[u8],
) -> Option<Declaration<'a>> {
    if !matches!(
        node.kind(),
        "identifier" | "shorthand_property_identifier_pattern"
    ) {
        return None;
    }
    let mut child = node;
    for _ in 0..32 {
        let parent = child.parent()?;
        let (field, kind) = match parent.kind() {
            "variable_declarator" => ("name", SymbolKind::Variable),
            "let_declaration" => ("pattern", SymbolKind::Variable),
            "assignment" if language == Language::Python => ("left", SymbolKind::Variable),
            "required_parameter" | "optional_parameter" | "parameter" => {
                ("pattern", SymbolKind::Parameter)
            }
            "formal_parameters" | "parameters" => {
                if child == node {
                    return None;
                }
                return Some(Declaration {
                    name: node,
                    name_override: None,
                    kind: SymbolKind::Parameter,
                    body: None,
                    exported: false,
                });
            }
            "pair_pattern" => {
                if parent.child_by_field_name("value") != Some(child) {
                    return None;
                }
                child = parent;
                continue;
            }
            "assignment_pattern" => {
                if parent.child_by_field_name("left") != Some(child) {
                    return None;
                }
                child = parent;
                continue;
            }
            "tuple_pattern"
            | "slice_pattern"
            | "tuple_struct_pattern"
            | "struct_pattern"
            | "field_pattern"
            | "ref_pattern"
            | "mut_pattern"
            | "reference_pattern"
            | "array_pattern"
            | "object_pattern"
            | "rest_pattern"
            | "list_pattern"
            | "pattern_list" => {
                child = parent;
                continue;
            }
            _ => return None,
        };
        if child == node || parent.child_by_field_name(field) != Some(child) {
            return None;
        }
        return Some(Declaration {
            name: node,
            name_override: None,
            kind,
            body: None,
            exported: exported(parent, bytes),
        });
    }
    None
}

pub(super) fn default_export(node: Node<'_>, bytes: &[u8]) -> bool {
    node.parent()
        .filter(|p| p.kind() == "export_statement")
        .is_some_and(|p| {
            let mut cursor = p.walk();
            p.children(&mut cursor)
                .any(|n| !n.is_named() && text(n, bytes) == "default")
        })
}
