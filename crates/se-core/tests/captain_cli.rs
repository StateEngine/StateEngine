use se_core::ops::{self, AnyOp};

#[test]
fn captain_commands_decode_and_advertise_the_same_operations()
-> Result<(), Box<dyn std::error::Error>> {
    let set = ops::cli_command().try_get_matches_from([
        "se",
        "--key",
        "synthetic-set",
        "captain",
        "set",
        "worker",
    ])?;
    assert!(
        matches!(ops::from_matches(&set)?, AnyOp::CaptainSet(value) if value.captain == "worker")
    );
    let clear = ops::cli_command().try_get_matches_from([
        "se",
        "--key",
        "synthetic-clear",
        "captain",
        "clear",
    ])?;
    assert!(matches!(ops::from_matches(&clear)?, AnyOp::CaptainClear(_)));
    let show = ops::cli_command().try_get_matches_from(["se", "captain", "show"])?;
    assert!(matches!(ops::from_matches(&show)?, AnyOp::CaptainShow(_)));
    for operation in ["captain.set", "captain.clear", "captain.show"] {
        assert!(ops::schemas(operation).is_some());
    }
    Ok(())
}

#[test]
fn captain_history_kind_is_available() -> Result<(), Box<dyn std::error::Error>> {
    let matches = ops::cli_command().try_get_matches_from([
        "se",
        "history",
        "--kind",
        "project.captain_changed",
    ])?;
    let operation = ops::from_matches(&matches)?;
    operation.validate()?;
    Ok(())
}
