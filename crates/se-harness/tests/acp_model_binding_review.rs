//! Launch validation for saved ACP models. Configuration only; no native process.
#![cfg(feature = "listener")]
use se_config::config_policy::ConfigFile;
use se_harness::harness::acp::AcpHarness;

type Check = Result<(), Box<dyn std::error::Error>>;

fn configuration(arguments: &[&str]) -> ConfigFile {
    let mut configuration = ConfigFile::default();
    configuration.acp.arguments = arguments.iter().map(|v| (*v).to_owned()).collect();
    configuration
}

/// Protects: a saved model no longer needs a `{model}` argv slot, because the
/// launch can select it over the protocol after the conversation opens.
#[test]
fn saved_model_without_argv_slot_is_accepted_for_protocol_selection() -> Check {
    let configuration = configuration(&["synthetic-agent", "--acp"]);
    let profile =
        AcpHarness::validate_launch(&configuration, "default", Some("synthetic-model"), None)?;
    assert_eq!(profile.name, "default");
    AcpHarness::validate_launch(&configuration, "default", None, None)?;
    Ok(())
}

/// Protects: an argv `{model}` slot still refuses a launch with no saved model,
/// and names the step that resolves it.
#[test]
fn argv_model_slot_still_requires_a_saved_model() -> Check {
    let configuration = configuration(&["synthetic-agent", "--model", "{model}"]);
    let refused = AcpHarness::validate_launch(&configuration, "default", None, None)
        .err()
        .ok_or("an argv {model} slot without a saved model was accepted")?;
    let message = refused.body.message();
    assert!(
        message.contains("requires a saved model") && message.contains("Select a model"),
        "refusal does not name its reason and repair: {message}"
    );
    AcpHarness::validate_launch(&configuration, "default", Some("synthetic-model"), None)?;
    Ok(())
}
