//! Compact discovery is an argument-shape guide, not the input validator.
//! Titles, formats and string grammars are omitted and each description keeps
//! its first line, so a model learns what a field means without the full prose.
//! Definitions, references, unions and structural constraints keep their
//! generated layout. Complete CLI schemas and decoding use the original DTOs.
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
        for key in ["$schema", "title", "format"] {
            object.remove(key);
        }
        if let Some(Value::String(description)) = object.get_mut("description")
            && let Some((first, _)) = description.split_once('\n')
        {
            *description = first.trim_end().to_owned();
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
