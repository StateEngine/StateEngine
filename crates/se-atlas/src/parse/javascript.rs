//! Shared JS/JSX and TS/TSX syntax, with grammar selection in the parser owner.
use super::syntax::{Declaration, exported};
use crate::model::SymbolKind;
use tree_sitter::Node;
pub(super) fn declaration<'a>(node: Node<'a>, bytes: &[u8]) -> Option<Declaration<'a>> {
    use SymbolKind::*;
    let kind = match node.kind() {
        "function_declaration" | "generator_function_declaration" => Function,
        "function_expression" | "arrow_function" if super::syntax::default_export(node, bytes) => {
            Function
        }
        "method_definition" | "method_signature" | "abstract_method_signature" => Method,
        "class_declaration" | "class" => Class,
        "interface_declaration" => Interface,
        "type_alias_declaration" => TypeAlias,
        "enum_declaration" => Enum,
        "internal_module" => Namespace,
        "enum_assignment" => EnumVariant,
        "variable_declarator" => {
            if node.child_by_field_name("value").is_some_and(|n| {
                matches!(
                    n.kind(),
                    "arrow_function" | "function_expression" | "generator_function"
                )
            }) {
                Function
            } else {
                Variable
            }
        }
        "public_field_definition" | "property_signature" | "field_definition" => Field,
        "required_parameter" | "optional_parameter" => Parameter,
        "identifier"
            if node
                .parent()
                .is_some_and(|n| n.kind() == "formal_parameters") =>
        {
            Parameter
        }
        _ => return None,
    };
    let candidate = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("pattern"))
        .or_else(|| (node.kind() == "identifier").then_some(node));
    let anonymous = candidate.is_none() && super::syntax::default_export(node, bytes);
    let name = if anonymous { node } else { candidate? };
    if !anonymous
        && !matches!(
            name.kind(),
            "identifier"
                | "property_identifier"
                | "private_property_identifier"
                | "type_identifier"
        )
    {
        return None;
    }
    let body = node.child_by_field_name("body").or_else(|| {
        node.child_by_field_name("value")
            .map(|v| v.child_by_field_name("body").unwrap_or(v))
    });
    Some(Declaration {
        name,
        name_override: anonymous.then_some("default"),
        kind,
        body,
        exported: exported(node, bytes),
    })
}
