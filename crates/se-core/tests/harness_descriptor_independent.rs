//! Independent descriptor policy controls; native launch qualification is separate.
use se_core::config_policy::{
    ConfigFile, Provider,
    harness::{Driver, HarnessDescriptor, PermissionChoice},
};
use std::collections::BTreeMap;
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn configuration() -> ConfigFile {
    let mut config = ConfigFile::default();
    config.acp.harness = Some("second".into());
    config.acp.arguments = vec!["legacy".into(), "{model}".into()];
    config.acp.mode = "legacy-mode".into();
    for name in ["first", "second"] {
        config.harnesses.insert(
            name.into(),
            HarnessDescriptor {
                driver: Driver::AcpStdio,
                command: format!("{name}-native"),
                arguments: vec![name.into()],
                environment: vec!["FIXTURE_ACCOUNT".into()],
                model_environment: Some("FIXTURE_MODEL".into()),
                permissions: BTreeMap::from([(
                    "default".into(),
                    PermissionChoice {
                        arguments: vec![format!("{name}-level")],
                        environment: BTreeMap::from([("FIXTURE_MODE".into(), name.into())]),
                        mode: format!("{name}-mode"),
                    },
                )]),
            },
        );
    }
    config
}
#[test]
fn saved_descriptor_keeps_native_choice_when_creation_default_changes() -> Check {
    let config = configuration();
    config.validate()?;
    assert_eq!(
        config.selected_harness(Provider::Acp, None)?,
        Some("second".into())
    );
    let saved = config.acp_settings(Some("first"), "default")?;
    assert_eq!(saved.arguments, ["first", "first-level"]);
    assert_eq!(saved.environment, ["FIXTURE_ACCOUNT"]);
    assert_eq!(
        saved.values.get("FIXTURE_MODE").map(String::as_str),
        Some("first")
    );
    assert_eq!(saved.model_environment.as_deref(), Some("FIXTURE_MODEL"));
    assert_eq!(saved.mode, "first-mode");
    Ok(())
}
#[test]
fn legacy_saved_choice_ignores_new_descriptor_default() -> Check {
    let config = configuration();
    config.validate()?;
    let legacy = config.acp_settings(None, "default")?;
    assert_eq!(legacy.arguments, ["legacy", "{model}"]);
    assert_eq!(legacy.mode, "legacy-mode");
    assert!(legacy.values.is_empty());
    assert!(legacy.model_environment.is_none());
    Ok(())
}
#[test]
fn missing_saved_descriptor_or_permission_has_no_fallback() -> Check {
    let mut config = configuration();
    config.harnesses.remove("first");
    config.validate()?;
    assert!(config.acp_settings(Some("first"), "default").is_err());
    assert!(config.acp_settings(Some("second"), "unmapped").is_err());
    assert!(
        config
            .selected_harness(Provider::Codex, Some("second"))
            .is_err()
    );
    Ok(())
}
#[test]
fn model_binding_cannot_replace_native_permission_or_runtime_authority() -> Check {
    let mut config = configuration();
    config
        .harnesses
        .get_mut("first")
        .ok_or("missing fixture descriptor")?
        .model_environment = Some("fixture_mode".into());
    assert!(config.validate().is_err());
    config
        .harnesses
        .get_mut("first")
        .ok_or("missing fixture descriptor")?
        .model_environment = Some("STATEENGINE_SYNTHETIC".into());
    assert!(config.validate().is_err());
    Ok(())
}
#[test]
fn permission_mappings_cannot_replace_runtime_session_authority() -> Check {
    let mut config = configuration();
    config
        .harnesses
        .get_mut("first")
        .ok_or("missing fixture descriptor")?
        .permissions
        .get_mut("default")
        .ok_or("missing fixture permission")?
        .environment
        .insert("se_session".into(), "synthetic-not-a-capability".into());
    assert!(config.validate().is_err());
    Ok(())
}
