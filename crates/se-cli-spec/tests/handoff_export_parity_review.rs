//! Reviewer checks: `se handoff export` and `stateengine_handoff_export` decode
//! to the same request, share defaults and budget bounds, and refuse the same
//! malformed cursor.
use se_core::ops::{self, AnyOp};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOOL: &str = "stateengine_handoff_export";

fn cli(args: &[&str]) -> se_types::Result<AnyOp> {
    let mut argv = vec!["se", "handoff", "export"];
    argv.extend_from_slice(args);
    let matches = se_cli_spec::cli_command()
        .try_get_matches_from(argv)
        .map_err(|error| se_types::SeError::invalid("argv", &error.to_string()))?;
    se_cli_spec::from_matches(&matches)
}

fn mcp(arguments: Value) -> se_types::Result<AnyOp> {
    ops::decode_tool(TOOL, arguments)
}

fn input(op: &AnyOp) -> Result<Value, Box<dyn std::error::Error>> {
    let AnyOp::HandoffExport(input) = op else {
        return Err(format!("decoded {} instead of handoff.export", op.meta().name).into());
    };
    Ok(serde_json::to_value(input)?)
}

fn refused(decoded: se_types::Result<AnyOp>) -> bool {
    decoded.and_then(|op| op.validate()).is_err()
}

#[test]
fn cli_and_mcp_decode_the_same_request() -> TestResult {
    let from_cli = cli(&["--from", "worker", "--budget", "4096"])?;
    let from_mcp = mcp(json!({"from": "worker", "budget": 4096}))?;
    assert_eq!(from_cli.meta().name, "handoff.export");
    assert_eq!(input(&from_cli)?, input(&from_mcp)?);
    assert_eq!(input(&from_cli)?["budget"], 4096);
    assert_eq!(input(&from_cli)?["from"], "worker");
    Ok(())
}

#[test]
fn both_doors_default_to_self_and_8192_bytes() -> TestResult {
    let from_cli = cli(&[])?;
    let from_mcp = mcp(json!({}))?;
    assert_eq!(input(&from_cli)?, input(&from_mcp)?);
    let value = input(&from_cli)?;
    assert_eq!(value["budget"], 8192);
    assert!(
        value.get("from").is_none(),
        "an omitted agent became {value}"
    );
    assert!(
        value.get("since").is_none(),
        "an omitted cursor became {value}"
    );
    from_cli.validate()?;
    Ok(())
}

#[test]
fn both_doors_share_the_budget_bounds() -> TestResult {
    for budget in [0u32, 255, 16385, 1_000_000] {
        assert!(
            refused(cli(&["--budget", &budget.to_string()])),
            "CLI admitted budget {budget}"
        );
        assert!(
            refused(mcp(json!({ "budget": budget }))),
            "MCP admitted budget {budget}"
        );
    }
    for budget in [256u32, 8192, 16384] {
        cli(&["--budget", &budget.to_string()])?.validate()?;
        mcp(json!({ "budget": budget }))?.validate()?;
    }
    Ok(())
}

/// Cursor text is opaque; the doors refuse malformed spelling, and the store
/// refuses a well-formed cursor that is not its own.
#[test]
fn both_doors_refuse_a_malformed_cursor() {
    assert!(
        refused(cli(&["--since", "not a cursor"])),
        "CLI admitted a malformed cursor"
    );
    assert!(
        refused(mcp(json!({"since": "not a cursor"}))),
        "MCP admitted a malformed cursor"
    );
}

#[test]
fn the_tool_schema_names_every_cli_input() -> TestResult {
    let tools = ops::mcp_tools()?;
    let tool = tools
        .iter()
        .find(|tool| tool.name == TOOL)
        .ok_or("handoff export is missing from the MCP catalogue")?;
    let properties = tool.input_schema["properties"]
        .as_object()
        .ok_or("handoff export schema has no properties")?;
    for name in ["from", "budget", "since"] {
        assert!(properties.contains_key(name), "MCP schema lacks {name}");
    }
    let required = tool.input_schema["required"]
        .as_array()
        .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    for name in ["from", "budget", "since"] {
        assert!(
            !required.contains(&name),
            "MCP schema requires optional {name}"
        );
    }
    Ok(())
}
