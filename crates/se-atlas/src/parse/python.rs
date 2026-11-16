use super::syntax::{Declaration, exported};
use crate::model::SymbolKind;
use tree_sitter::Node;
pub(super) fn declaration<'a>(
    node: Node<'a>,
    ancestors: &[Node<'a>],
    bytes: &[u8],
) -> Option<Declaration<'a>> {
    use SymbolKind::*;
    let kind = match node.kind() {
        "function_definition" => match ancestors.iter().rev().nth(1).map(Node::kind) {
            Some("class_definition") => Method,
            _ => Function,
        },
        "class_definition" => Class,
        "assignment" => match ancestors.iter().rev().nth(2).map(Node::kind) {
            Some("class_definition") => Field,
            _ => Variable,
        },
        "default_parameter" | "typed_parameter" | "typed_default_parameter" => Parameter,
        "identifier" if ancestors.last().is_some_and(|n| n.kind() == "parameters") => Parameter,
        _ => return None,
    };
    let name = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("left"))
        .or_else(|| (node.kind() == "identifier").then_some(node))
        .or_else(|| node.named_child(0))?;
    if name.kind() != "identifier" {
        return None;
    }
    Some(Declaration {
        name,
        name_override: None,
        kind,
        body: node
            .child_by_field_name("body")
            .or_else(|| node.child_by_field_name("right")),
        exported: exported(node, ancestors, bytes),
    })
}
