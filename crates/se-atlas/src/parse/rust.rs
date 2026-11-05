use super::syntax::{Declaration, exported};
use crate::model::SymbolKind;
use tree_sitter::Node;
pub(super) fn declaration<'a>(node: Node<'a>, bytes: &[u8]) -> Option<Declaration<'a>> {
    use SymbolKind::*;
    let kind = match node.kind() {
        "function_item" | "function_signature_item" => {
            if node
                .parent()
                .and_then(|n| n.parent())
                .is_some_and(|n| matches!(n.kind(), "impl_item" | "trait_item"))
            {
                Method
            } else {
                Function
            }
        }
        "struct_item" => Struct,
        "enum_item" => Enum,
        "trait_item" => Trait,
        "type_item" => TypeAlias,
        "const_item" => Constant,
        "static_item" => Static,
        "mod_item" => Module,
        "macro_definition" => Macro,
        "field_declaration" => Field,
        "enum_variant" => EnumVariant,
        "let_declaration" => Variable,
        "parameter" => Parameter,
        "impl_item" => Namespace,
        _ => return None,
    };
    let mut name = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("pattern"))
        .or_else(|| {
            (node.kind() == "impl_item")
                .then(|| node.child_by_field_name("type"))
                .flatten()
        })?;
    // Generic argument spelling and whitespace do not identify the impl owner.
    if node.kind() == "impl_item" {
        while name.kind() == "generic_type" {
            name = name.child_by_field_name("type")?;
        }
    }
    if !matches!(
        name.kind(),
        "identifier"
            | "type_identifier"
            | "field_identifier"
            | "scoped_type_identifier"
            | "generic_type"
    ) {
        return None;
    }
    Some(Declaration {
        name,
        name_override: None,
        kind,
        body: node
            .child_by_field_name("body")
            .or_else(|| node.child_by_field_name("value")),
        exported: exported(node, bytes),
    })
}
