//! Compact discovery preserves argument shapes; full schemas and decoding stay authoritative.
use se_core::ops::{decode_tool, mcp_tools, schema_catalogue};
use se_types::{AgentId, MessageId};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;

// Compare the public surfaces independently of definition layout. Visit schema
// positions, never arbitrary JSON objects: a property named format/title/description
// is an argument, not schema metadata. Keep defaults, enums and all non-string bounds.
fn shape(root: &Value, schema: &Value, active: &mut BTreeSet<String>) -> Check<Value> {
    let Some(object) = schema.as_object() else {
        return Ok(schema.clone());
    };
    let mut result = Map::new();
    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        let pointer = reference
            .strip_prefix('#')
            .ok_or("non-local schema reference")?;
        let target = root.pointer(pointer).ok_or("dangling schema reference")?;
        if active.insert(reference.into()) {
            let expanded = shape(root, target, active)?;
            result = expanded.as_object().ok_or("non-object definition")?.clone();
            active.remove(reference);
        } else {
            // Preserve a recursive edge rather than recursively expanding forever.
            result.insert("$ref".into(), json!(reference));
        }
    }
    for (key, value) in object {
        if matches!(
            key.as_str(),
            "$ref" | "$defs" | "$schema" | "title" | "description" | "format"
        ) || (key == "default" && value.is_null())
        {
            continue;
        }
        if object.get("type") == Some(&json!("string"))
            && matches!(key.as_str(), "pattern" | "minLength" | "maxLength")
        {
            continue;
        }
        // Legacy/canonical ID alternatives are intentionally omitted in discovery.
        if key == "anyOf"
            && object.get("type") == Some(&json!("string"))
            && value.as_array().is_some_and(|variants| {
                !variants.is_empty()
                    && variants.iter().all(|v| {
                        v.as_object()
                            .is_some_and(|v| v.len() == 1 && v.contains_key("pattern"))
                    })
            })
        {
            continue;
        }
        let normalized = match key.as_str() {
            "properties" | "patternProperties" => {
                let mut properties = Map::new();
                for (name, child) in value.as_object().ok_or("schema property map absent")? {
                    properties.insert(name.clone(), shape(root, child, active)?);
                }
                Value::Object(properties)
            }
            "anyOf" | "oneOf" | "allOf" | "prefixItems" => Value::Array(
                value
                    .as_array()
                    .ok_or("schema alternatives absent")?
                    .iter()
                    .map(|child| shape(root, child, active))
                    .collect::<Check<Vec<_>>>()?,
            ),
            "items"
            | "additionalProperties"
            | "propertyNames"
            | "contains"
            | "not"
            | "if"
            | "then"
            | "else" => shape(root, value, active)?,
            _ => value.clone(),
        };
        if let Some(inherited) = result.get(key) {
            // $ref constraints are conjunctive, not an override mechanism.
            if key != "default" {
                assert_eq!(inherited, &normalized, "conflicting $ref sibling {key}");
            }
        }
        result.insert(key.clone(), normalized);
    }
    // A union of plain types has the same meaning as a type array. Constrained
    // arms (especially enums) must stay in their union so null remains admissible.
    if let Some(variants) = result.get("anyOf").and_then(Value::as_array) {
        let kinds: Option<Vec<_>> = variants
            .iter()
            .map(|variant| {
                let object = variant.as_object()?;
                (object.len() == 1).then_some(())?;
                object.get("type")?.as_str().map(str::to_owned)
            })
            .collect();
        if let Some(kinds) = kinds.filter(|kinds| !kinds.is_empty()) {
            assert!(
                !result.contains_key("type"),
                "unexpected conjunctive type union"
            );
            result.remove("anyOf");
            result.insert("type".into(), json!(kinds));
        }
    }
    Ok(Value::Object(result))
}

#[test]
fn every_exposed_argument_shape_survives_compaction() -> Check {
    let full = schema_catalogue(None)?;
    let tools = mcp_tools()?;
    let exposed = full
        .ops
        .iter()
        .filter(|op| op.metadata["mcp"]["kind"] == "tool")
        .count();
    assert_eq!(tools.len(), exposed);
    for tool in tools {
        let op = full
            .ops
            .iter()
            .find(|op| op.metadata["mcp"]["name"] == tool.name)
            .ok_or("tool lacks full schema")?;
        let mut compact = tool.input_schema.clone();
        let properties = compact["properties"]
            .as_object_mut()
            .ok_or("tool properties absent")?;
        for caller in ["agent_id", "project_id"] {
            assert_eq!(properties[caller]["type"], "string");
            assert!(!compact_required(&tool.input_schema, caller));
            properties.remove(caller);
        }
        // Empty DTOs do not necessarily emit a properties map.
        if properties.is_empty() && op.input.get("properties").is_none() {
            compact
                .as_object_mut()
                .ok_or("tool root absent")?
                .remove("properties");
        }
        assert_eq!(
            shape(&op.input, &op.input, &mut BTreeSet::new())?,
            shape(&compact, &compact, &mut BTreeSet::new())?,
            "{}",
            tool.name
        );
    }
    Ok(())
}

fn compact_required(schema: &Value, field: &str) -> bool {
    schema["required"]
        .as_array()
        .is_some_and(|fields| fields.contains(&json!(field)))
}

#[test]
fn discovery_trims_repeated_detail_without_mutating_full_cli_schemas() -> Check {
    let before = schema_catalogue(Some("atlas.find"))?.ops.remove(0);
    let tools = mcp_tools()?;
    let find = tools
        .iter()
        .find(|tool| tool.name == "stateengine_atlas_find")
        .ok_or("find absent")?;
    assert!(before.input.get("$schema").is_some());
    assert!(before.input.get("title").is_some());
    assert!(
        before.input["properties"]["regex"]
            .get("description")
            .is_some()
    );
    assert!(find.input_schema.get("$schema").is_none());
    assert!(find.input_schema.get("title").is_none());
    assert!(
        find.input_schema["properties"]["regex"]
            .get("description")
            .is_none()
    );
    assert_eq!(
        find.input_schema["properties"]["query"],
        json!({"type":"string"})
    );
    // "format" is a real argument and must not be mistaken for an annotation.
    assert_eq!(
        find.input_schema["properties"]["format"]["enum"],
        json!(["compact", "json"])
    );
    assert_eq!(
        find.input_schema["properties"]["format"]["default"],
        "compact"
    );
    let after = schema_catalogue(Some("atlas.find"))?.ops.remove(0);
    assert_eq!(before.input, after.input);
    assert_eq!(before.output, after.output);
    let decoded = decode_tool(find.name, json!({"query":"example"}))?;
    assert_eq!(decoded.input_schema(), before.input);
    Ok(())
}

#[test]
fn nullable_enums_keep_null_outside_the_enum_constraint() -> Check {
    let tools = mcp_tools()?;
    for (tool_name, field, expected) in [
        (
            "stateengine_atlas_find",
            "mode",
            json!(["exact", "literal", "phrase", "broad", "related"]),
        ),
        (
            "stateengine_agent_create",
            "provider",
            json!(["claude", "codex", "secode", "acp"]),
        ),
    ] {
        let tool = tools
            .iter()
            .find(|tool| tool.name == tool_name)
            .ok_or("tool absent")?;
        let schema = shape(
            &tool.input_schema,
            &tool.input_schema["properties"][field],
            &mut BTreeSet::new(),
        )?;
        let variants = schema["anyOf"]
            .as_array()
            .ok_or("nullable enum union absent")?;
        assert!(variants.contains(&json!({"type":"null"})));
        assert!(variants.iter().any(|variant| variant["enum"] == expected));
        assert!(
            schema.get("enum").is_none(),
            "enum must not reject the null arm"
        );
    }
    for arguments in [
        json!({"query":"example"}),
        json!({"query":"example","mode":null}),
        json!({"query":"example","mode":"exact"}),
    ] {
        decode_tool("stateengine_atlas_find", arguments)?;
    }
    for provider in [Value::Null, json!("claude"), json!("codex")] {
        decode_tool(
            "stateengine_agent_create",
            json!({"name":"example-agent",
            "provider":provider,"idempotency_key":"catalogue-example-create"}),
        )?;
    }
    assert!(
        decode_tool(
            "stateengine_atlas_find",
            json!({"query":"example","mode":"invalid"})
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn tagged_targets_and_mutation_payloads_keep_their_actual_json_shapes() -> Check {
    for target in [
        json!({"Symbol":{"Name":{"name":"example"}}}),
        json!({"File":"src/example.rs"}),
    ] {
        for tool in ["stateengine_atlas_refs", "stateengine_atlas_impact"] {
            let decoded = decode_tool(tool, json!({"target":target,"format":"json"}))?;
            assert_eq!(serde_json::to_value(decoded)?["input"]["format"], "json");
        }
    }
    let agent = AgentId::from_parts(1, [3; 10])?;
    let message = MessageId::from_parts(1, [4; 10])?;
    for work in [Value::Null, json!({"action":"assign","addressees":[agent]})] {
        let to = if work.is_null() {
            "example-agent"
        } else {
            "floor"
        };
        let arguments = json!({"to":to,"body":"Synthetic example message","quiet":true,
            "kind":"task","reply_to":message,"work":work,
            "idempotency_key":"catalogue-example-send"});
        let decoded =
            serde_json::to_value(decode_tool("stateengine_msg_send", arguments.clone())?)?;
        for field in [
            "to",
            "body",
            "quiet",
            "kind",
            "reply_to",
            "work",
            "idempotency_key",
        ] {
            assert_eq!(decoded["input"][field], arguments[field]);
        }
    }
    for expect in [json!("absent"), json!(1)] {
        decode_tool(
            "stateengine_working_state_set",
            json!({"text":"Synthetic note",
            "expect":expect,"idempotency_key":"catalogue-example-note"}),
        )?;
    }
    Ok(())
}

#[test]
fn compact_discovery_does_not_relax_runtime_validation() -> Check {
    let message = MessageId::from_parts(1, [4; 10])?;
    for (tool, arguments) in [
        (
            "stateengine_atlas_find",
            json!({"query":"example","limit":0}),
        ),
        (
            "stateengine_atlas_find",
            json!({"query":"example","byte_budget":1}),
        ),
        (
            "stateengine_atlas_find",
            json!({"query":"example","format":"invalid"}),
        ),
        (
            "stateengine_atlas_find",
            json!({"query":"example","unknown":true}),
        ),
        ("stateengine_atlas_refs", json!({"target":"src/example.rs"})),
        (
            "stateengine_msg_read",
            json!({"message_id":"not-a-message-id"}),
        ),
        (
            "stateengine_msg_read",
            json!({"message_id":message,"msg_id":message}),
        ),
        (
            "stateengine_msg_send",
            json!({"to":"floor","body":"Synthetic message",
            "idempotency_key":"catalogue-example-send"}),
        ),
        (
            "stateengine_msg_send",
            json!({"to":"example-agent","body":"",
            "idempotency_key":"catalogue-example-send"}),
        ),
        (
            "stateengine_working_state_set",
            json!({"text":"note","expect":0,
            "idempotency_key":"catalogue-example-note"}),
        ),
    ] {
        assert!(
            decode_tool(tool, arguments.clone()).is_err(),
            "{tool} accepted {arguments}"
        );
    }
    for spelling in ["message_id", "msg_id"] {
        decode_tool("stateengine_msg_read", json!({spelling:message}))?;
    }
    Ok(())
}
