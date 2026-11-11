//! Compact discovery is an argument-shape guide, not the input validator.
//! Only annotations and string grammars are omitted: definitions, references,
//! unions and structural constraints retain their generated layout and meaning.
//! Complete CLI schemas and decoding still use the original DTOs.
use schemars::{Schema, transform::transform_subschemas};
use serde_json::Value;

pub(super) fn compact(value: Value) -> se_types::Result<Value> {
    let mut schema = Schema::try_from(value)
        .map_err(|_| se_types::SeError::invalid("MCP schema", "a generated schema object"))?;
    trim(&mut schema);
    Ok(schema.to_value())
}

fn trim(schema: &mut Schema) {
    if let Some(object) = schema.as_object_mut() {
        for key in ["$schema", "title", "description", "format"] {
            object.remove(key);
        }
        if object.get("default") == Some(&Value::Null) {
            object.remove("default");
        }
        // Models should copy IDs rather than manufacture them. Removing these
        // repeated grammars does not change serde parsers or full CLI schemas.
        if object.get("type").and_then(Value::as_str) == Some("string") {
            for key in ["pattern", "minLength", "maxLength"] {
                object.remove(key);
            }
            if object
                .get("anyOf")
                .and_then(Value::as_array)
                .is_some_and(|variants| {
                    !variants.is_empty()
                        && variants.iter().all(|v| {
                            v.as_object()
                                .is_some_and(|v| v.len() == 1 && v.contains_key("pattern"))
                        })
                })
            {
                object.remove("anyOf");
            }
        }
    }
    // Traverse schema positions, never arbitrary objects: an input property
    // named `format`, `title` or `description` must remain an advertised field.
    transform_subschemas(&mut trim, schema);
}
