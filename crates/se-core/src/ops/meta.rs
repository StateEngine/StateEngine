//! Store-free metadata: its only inputs are the registered source types and build constants.
use super::*;
use se_types::{Detail, Result, SeError, details};
use std::collections::BTreeSet;
fn build() -> Build {
    let commit = option_env!("STATEENGINE_BUILD_COMMIT")
        .filter(|value| value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_owned);
    Build {
        provenance: if commit.is_some() {
            Provenance::Observed
        } else {
            Provenance::Unknown
        },
        commit,
    }
}
pub fn metadata_output(op: &AnyOp) -> Result<Option<AnyOutput>> {
    match op {
        AnyOp::MetaVersion(value) => {
            value.validate()?;
            Ok(Some(
                VersionOutput {
                    version: env!("CARGO_PKG_VERSION").into(),
                    build: build(),
                }
                .into(),
            ))
        }
        AnyOp::MetaHelp(value) => {
            value.validate()?;
            let mut command = cli_command();
            for part in &value.path {
                command = command.find_subcommand(part).cloned().ok_or_else(|| {
                    SeError::new(Detail::UsageUnknownCommand(details::UsageUnknownCommand {
                        got: value.path.join(" "),
                        suggestion: None,
                    }))
                })?;
            }
            if value.all {
                fn reveal(command: clap::Command) -> clap::Command {
                    command.hide(false).mut_subcommands(reveal)
                }
                command = reveal(command);
            }
            Ok(Some(
                HelpOutput {
                    path: value.path.clone(),
                    usage: command.render_long_help().to_string(),
                }
                .into(),
            ))
        }
        AnyOp::MetaSchema(value) => {
            value.validate()?;
            Ok(Some(schema_catalogue(value.op.as_deref())?.into()))
        }
        _ => Ok(None),
    }
}
fn internal(location: &str) -> SeError {
    SeError::new(Detail::Internal(details::Internal {
        report_id: "metadata-schema".into(),
        location: location.into(),
    }))
}
pub fn schema_catalogue(selected: Option<&str>) -> Result<SchemaCatalogue> {
    let mut ops = Vec::new();
    let mut families = BTreeSet::new();
    for meta in CATALOGUE {
        if selected.is_some_and(|name| name != meta.name) {
            continue;
        }
        let (input, output) = schemas(meta.name).ok_or_else(|| internal(meta.name))?;
        families.insert(meta.family.schema());
        ops.push(OpSchema {
            name: meta.name.into(),
            metadata: serde_json::to_value(meta).map_err(|e| internal(&e.to_string()))?,
            input,
            output,
        });
    }
    if ops.is_empty() {
        return Err(SeError::invalid(
            "operation",
            "an exact registered operation name",
        ));
    }
    let errors = error_schemas()?;
    Ok(SchemaCatalogue {
        api: format!(
            "{}.{}",
            se_types::API_VERSION.major,
            se_types::API_VERSION.minor
        ),
        build: build(),
        ops,
        families: families.into_iter().collect(),
        errors,
    })
}
fn error_schemas() -> Result<Vec<serde_json::Value>> {
    let codes = schemars::schema_for!(se_types::Code).to_value();
    let details = schemars::schema_for!(se_types::Detail).to_value();
    let values = codes
        .get("enum")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| internal("error code schema"))?;
    let variants = details
        .get("oneOf")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| internal("error detail schema"))?;
    let mut result = Vec::new();
    for value in values {
        let code: se_types::Code =
            serde_json::from_value(value.clone()).map_err(|e| internal(&e.to_string()))?;
        let variant = variants
            .iter()
            .find(|variant| variant.pointer("/properties/code/const") == Some(value))
            .ok_or_else(|| internal(code.as_str()))?;
        let schema = variant
            .pointer("/properties/detail")
            .ok_or_else(|| internal(code.as_str()))?;
        let mut schema =
            if let Some(reference) = schema.get("$ref").and_then(serde_json::Value::as_str) {
                let pointer = reference
                    .strip_prefix('#')
                    .ok_or_else(|| internal(reference))?;
                details
                    .pointer(pointer)
                    .cloned()
                    .ok_or_else(|| internal(reference))?
            } else {
                schema.clone()
            };
        let mut definitions = serde_json::Map::new();
        collect_definitions(&schema, &details, &mut definitions)?;
        if !definitions.is_empty() {
            schema
                .as_object_mut()
                .ok_or_else(|| internal(code.as_str()))?
                .insert("$defs".into(), serde_json::Value::Object(definitions));
        }
        result.push(serde_json::json!({"code":code,"class":code.class(),"exit":code.class().exit_code(),"detail":schema}));
    }
    Ok(result)
}
/// Detail schemas must retain their reachable definitions when lifted out of Detail.
fn collect_definitions(
    value: &serde_json::Value,
    source: &serde_json::Value,
    found: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(serde_json::Value::as_str) {
                let name = reference
                    .strip_prefix("#/$defs/")
                    .ok_or_else(|| internal(reference))?;
                if !found.contains_key(name) {
                    let definition = source
                        .pointer(&reference[1..])
                        .ok_or_else(|| internal(reference))?;
                    found.insert(name.to_owned(), definition.clone());
                    collect_definitions(definition, source, found)?;
                }
            }
            for child in object.values() {
                collect_definitions(child, source, found)?;
            }
        }
        serde_json::Value::Array(array) => {
            for child in array {
                collect_definitions(child, source, found)?;
            }
        }
        _ => (),
    }
    Ok(())
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpTool {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub input_schema: serde_json::Value,
}
/// The registered admitted rows are the only source of the model-facing tool list.
pub fn mcp_tools() -> Result<Vec<McpTool>> {
    let mut tools = Vec::new();
    for meta in CATALOGUE {
        if let McpExposure::Tool {
            name,
            title,
            description,
        } = meta.mcp
        {
            let input_schema = input_schema(meta.name).ok_or_else(|| internal(meta.name))?;
            tools.push(McpTool {
                name,
                title,
                description,
                input_schema,
            });
        }
    }
    Ok(tools)
}
pub fn decode_tool(name: &str, arguments: serde_json::Value) -> Result<AnyOp> {
    // Removal is deliberately absent from tools/list. A caller attempting the
    // ordinary operation/CLI spelling still gets its legal owner route, never
    // an executable model tool or an invitation to supply OwnerProof over MCP.
    if matches!(name, "stateengine_project_remove" | "stateengine_remove") {
        return Err(SeError::new(Detail::HumanTerminalRequired(
            details::HumanTerminalRequired {
                op: ProjectRemove::META.name.into(),
                reason: "MCP cannot supply human owner presence. Run `se remove --project PROJECT` or `se remove --all` from your own terminal outside an agent tree; repository files and retained history are preserved.".into(),
            },
        )));
    }
    let meta = CATALOGUE
        .iter()
        .find(|meta| matches!(meta.mcp,McpExposure::Tool {name:registered,..} if registered==name))
        .ok_or_else(|| SeError::invalid("tool", "an exposed registered StateEngine tool name"))?;
    decode_registered(meta, arguments)
}
/// IPC/linked ingress preserves the original key in both its transport identity
/// and closed DTO. Neither a transport field nor a read can manufacture a write.
pub fn decode_operation(
    name: &str,
    arguments: serde_json::Value,
    key: Option<&se_types::IdempotencyKey>,
) -> Result<AnyOp> {
    let meta = CATALOGUE
        .iter()
        .find(|meta| meta.name == name)
        .ok_or_else(|| SeError::invalid("operation", "an exact registered operation name"))?;
    let op = decode_registered(meta, arguments)?;
    if op.idempotency_key() != key {
        return Err(SeError::invalid(
            "request identity",
            "the same original idempotency_key in the transport and mutation DTO; reads carry none",
        ));
    }
    Ok(op)
}
fn decode_registered(
    meta: &crate::registry::OpMeta,
    arguments: serde_json::Value,
) -> Result<AnyOp> {
    let input_schema = input_schema(meta.name).ok_or_else(|| internal(meta.name))?;
    let properties = input_schema
        .get("properties")
        .and_then(serde_json::Value::as_object);
    if let Some(arguments) = arguments.as_object() {
        for field in arguments.keys() {
            if !properties.is_some_and(|properties| properties.contains_key(field)) {
                return Err(SeError::new(Detail::InputUnknownField(details::InputUnknownField {op:meta.name.into(),field:field.clone(),next_step:"Use the generated tool arguments; actor, project and private owner selectors are supplied by the authenticated route.".into()})));
            }
        }
    }
    let op:AnyOp=serde_json::from_value(serde_json::json!({"op":meta.name,"input":arguments})).map_err(|error|SeError::new(Detail::UsageInvalidValue(details::UsageInvalidValue {argument:format!("{} arguments",meta.name),got:error.to_string(),expected:"the closed generated input schema; actor and project come from the authenticated session".into()})))?;
    op.validate()?;
    Ok(op)
}
