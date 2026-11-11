//! Independent checks of the public command, request and receipt boundaries.
use se_core::ops::{self, AnyOp, AnyOutput};
use serde_json::json;

const IMPORT: &str = "store.import_node";
const KEY: &str = "00000000-0000-4000-8000-000000000001";
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn command_selection_requires_the_explicit_feature() -> TestResult {
    let matches = ops::cli_command().try_get_matches_from([
        "se",
        "--key",
        KEY,
        "import",
        "--from-node",
        "retained-history",
    ]);
    if cfg!(feature = "import") {
        let operation = ops::from_matches(&matches?)?;
        assert_eq!(operation.meta().name, IMPORT);
        operation.validate()?;
        assert!(operation.idempotency_key().is_some());
    } else {
        assert!(matches.is_err(), "default command parser admitted import");
    }
    Ok(())
}

#[test]
fn raw_host_request_cannot_bypass_the_command_feature() -> TestResult {
    let operation = serde_json::from_value::<AnyOp>(json!({
        "op": IMPORT,
        "input": {"from_node": "retained-history", "idempotency_key": KEY}
    }));
    if cfg!(feature = "import") {
        let operation = operation?;
        operation.validate()?;
        assert_eq!(operation.meta().name, IMPORT);
    } else {
        assert!(
            operation.is_err(),
            "raw owner request admitted default import"
        );
    }
    Ok(())
}

#[test]
fn catalogue_schema_and_generated_help_agree_on_import_availability() -> TestResult {
    let enabled = cfg!(feature = "import");
    assert_eq!(ops::CATALOGUE.iter().any(|row| row.name == IMPORT), enabled);
    assert_eq!(ops::schemas(IMPORT).is_some(), enabled);
    assert_eq!(ops::schema_catalogue(Some(IMPORT)).is_ok(), enabled);
    let catalogue = ops::schema_catalogue(None)?;
    assert_eq!(catalogue.ops.iter().any(|row| row.name == IMPORT), enabled);
    let mut command = ops::cli_command();
    command.build();
    assert_eq!(command.find_subcommand("import").is_some(), enabled);
    // Import remains an owner-only command rather than a model-facing tool.
    if let Some(row) = ops::CATALOGUE.iter().find(|row| row.name == IMPORT) {
        assert!(matches!(
            row.mcp,
            se_core::registry::McpExposure::None { .. }
        ));
        assert_eq!(row.auth, se_core::registry::Auth::Owner);
    }
    Ok(())
}

#[test]
fn import_receipts_follow_the_same_wire_feature_boundary() -> TestResult {
    let output = serde_json::from_value::<AnyOutput>(json!({
        "schema":"se.import/v1", "maintenance_pending":false,
        "import_id":"synthetic-import", "source":"retained-history", "complete":false,
        "originals_retained":true, "families":[], "resume":[]
    }));
    if cfg!(feature = "import") {
        let output = output?;
        assert_eq!(output.family().schema(), "se.import/v1");
        assert_eq!(
            output.exit_code(),
            2,
            "incomplete import lost its failure status"
        );
    } else {
        assert!(
            output.is_err(),
            "default receipt decoder accepted import output"
        );
    }
    Ok(())
}

#[test]
fn ordinary_commands_and_schemas_remain_available() -> TestResult {
    let matches = ops::cli_command().try_get_matches_from(["se", "status"])?;
    assert_eq!(ops::from_matches(&matches)?.meta().name, "project.status");
    assert!(ops::schemas("project.status").is_some());
    assert!(ops::schema_catalogue(Some("project.status")).is_ok());
    Ok(())
}
