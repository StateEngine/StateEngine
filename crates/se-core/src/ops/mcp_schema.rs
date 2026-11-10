//! Compact discovery is an argument-shape guide, not the input validator.
//! Full descriptions and opaque string grammars remain in `se schema`; decoding
//! still uses the original DTOs and validation on every transport.
use schemars::{
    Schema,
    transform::{Transform, transform_subschemas},
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub(super) fn compact(value: Value) -> se_types::Result<Value> {
    let mut schema = Schema::try_from(value)
        .map_err(|_| se_types::SeError::invalid("MCP schema", "a generated schema object"))?;
    trim(&mut schema);
    inline_small_definitions(&mut schema);
    nullable(&mut schema);
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
        // Canonical/legacy ID regexes are expensive, repeated implementation
        // detail. Models should copy IDs, not manufacture them. This projection
        // does not change their serde parsers or the complete CLI schemas.
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
    transform_subschemas(&mut trim, schema);
}

fn reference_counts(schema: &mut Schema, counts: &mut BTreeMap<String, usize>) {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        *counts.entry(reference.into()).or_default() += 1;
    }
    transform_subschemas(
        &mut |child: &mut Schema| reference_counts(child, counts),
        schema,
    );
}

struct Inline<'a> {
    reference: &'a str,
    definition: &'a Map<String, Value>,
}
impl Transform for Inline<'_> {
    fn transform(&mut self, schema: &mut Schema) {
        if schema.get("$ref").and_then(Value::as_str) == Some(self.reference)
            && let Some(object) = schema.as_object_mut()
        {
            object.remove("$ref");
            // A sibling such as a property's default/description takes priority.
            for (key, value) in self.definition {
                object.entry(key.clone()).or_insert_with(|| value.clone());
            }
        }
        transform_subschemas(self, schema);
    }
}

fn inline_small_definitions(schema: &mut Schema) {
    loop {
        let mut counts = BTreeMap::new();
        reference_counts(schema, &mut counts);
        let selected = schema
            .get("$defs")
            .and_then(Value::as_object)
            .and_then(|defs| {
                defs.iter().find_map(|(name, definition)| {
                    let reference = format!("#/$defs/{name}");
                    let object = definition.as_object()?;
                    // Single-use leaves save their wrapper; tiny strings also save
                    // space when repeated. Keep recursive/shared structured types.
                    let count = counts.get(&reference).copied().unwrap_or(0);
                    let mut leaf = true;
                    let mut definition_schema = Schema::from(object.clone());
                    schemars::transform::RecursiveTransform(|s: &mut Schema| {
                        leaf &= s.get("$ref").is_none();
                    })
                    .transform(&mut definition_schema);
                    let tiny = object.len() == 1
                        && object.get("type").and_then(Value::as_str) == Some("string");
                    (leaf && (count <= 1 || tiny))
                        .then(|| (name.clone(), reference, object.clone()))
                })
            });
        let Some((name, reference, definition)) = selected else {
            break;
        };
        if let Some(defs) = schema
            .as_object_mut()
            .and_then(|s| s.get_mut("$defs"))
            .and_then(Value::as_object_mut)
        {
            defs.remove(&name);
        }
        Inline {
            reference: &reference,
            definition: &definition,
        }
        .transform(schema);
    }
    if schema
        .get("$defs")
        .and_then(Value::as_object)
        .is_some_and(Map::is_empty)
    {
        schema.remove("$defs");
    }
}

fn nullable(schema: &mut Schema) {
    transform_subschemas(&mut nullable, schema);
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    let Some(variants) = object.get("anyOf").and_then(Value::as_array) else {
        return;
    };
    if variants.len() != 2 {
        return;
    }
    let null = serde_json::json!({"type":"null"});
    if !variants.contains(&null) {
        return;
    }
    let Some(other) = variants
        .iter()
        .find(|v| **v != null)
        .and_then(Value::as_object)
    else {
        return;
    };
    let Some(kind) = other.get("type").and_then(Value::as_str) else {
        return;
    };
    // Enums and constraints outside `type` would also constrain the null arm.
    // Only a plain type can safely replace this union with a type array.
    if other.len() != 1 || object.contains_key("type") {
        return;
    }
    let kinds = serde_json::json!([kind, "null"]);
    object.remove("anyOf");
    object.insert("type".into(), kinds);
}
