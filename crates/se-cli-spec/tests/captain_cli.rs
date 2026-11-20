use se_core::ops::{self, AnyOp};

#[test]
fn captain_commands_decode_and_advertise_the_same_operations()
-> Result<(), Box<dyn std::error::Error>> {
    let set = se_cli_spec::cli_command().try_get_matches_from([
        "se",
        "--key",
        "synthetic-set",
        "captain",
        "set",
        "worker",
    ])?;
    assert!(
        matches!(se_cli_spec::from_matches(&set)?, AnyOp::CaptainSet(value) if value.captain == "worker")
    );
    let clear = se_cli_spec::cli_command().try_get_matches_from([
        "se",
        "--key",
        "synthetic-clear",
        "captain",
        "clear",
    ])?;
    assert!(matches!(
        se_cli_spec::from_matches(&clear)?,
        AnyOp::CaptainClear(_)
    ));
    let show = se_cli_spec::cli_command().try_get_matches_from(["se", "captain", "show"])?;
    assert!(matches!(
        se_cli_spec::from_matches(&show)?,
        AnyOp::CaptainShow(_)
    ));
    for operation in ["captain.set", "captain.clear", "captain.show"] {
        assert!(ops::schemas(operation).is_some());
    }
    Ok(())
}

#[test]
fn captain_history_kind_is_available() -> Result<(), Box<dyn std::error::Error>> {
    let matches = se_cli_spec::cli_command().try_get_matches_from([
        "se",
        "history",
        "--kind",
        "project.captain_changed",
    ])?;
    let operation = se_cli_spec::from_matches(&matches)?;
    operation.validate()?;
    Ok(())
}

#[test]
fn owner_changes_are_not_mcp_tools() {
    use se_core::registry::McpExposure;
    assert!(matches!(
        ops::CaptainSet::META.mcp,
        McpExposure::None { .. }
    ));
    assert!(matches!(
        ops::CaptainClear::META.mcp,
        McpExposure::None { .. }
    ));
    assert!(matches!(
        ops::CaptainShow::META.mcp,
        McpExposure::Tool {
            name: "stateengine_captain_show",
            ..
        }
    ));
}
