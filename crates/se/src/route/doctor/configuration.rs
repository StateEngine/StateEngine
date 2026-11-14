//! Diagnose the same file and policy as runtime startup, after protected
//! admission. Invalid configuration must not prevent doctor from diagnosing it.
use super::{Bootstrap, CheckFix, CheckState, DiagnosisCheck};
use crate::{bootstrap, config};
use se_config::config_policy::ConfigFile;
use se_types::{RenderCx, Result};

pub(super) fn check(cx: &Bootstrap, at: &str) -> Result<DiagnosisCheck> {
    let mut value = super::check(
        "configuration.file",
        "Runtime configuration",
        CheckState::Ok,
        String::new(),
        at,
    );
    value.expected = Some("Readable, valid version 1 user configuration, or an absent default file using built-in defaults".into());
    let selected = bootstrap::configuration_path(&cx.home);
    let subject = match &selected {
        Ok((path, _)) => path.display().to_string(),
        Err(_) => "SE_CONFIG".into(),
    };
    let loaded = selected.and_then(|(path, explicit)| {
        let loaded = config::load::<ConfigFile>(&path, explicit)?;
        loaded.value.validate()?;
        Ok(loaded)
    });
    match loaded {
        Ok(config::Loaded { origin, .. }) => {
            value.observed = Some(match origin {
                config::Origin::BuiltIn => {
                    format!("{subject}: absent default file; built-in defaults are valid")
                }
                config::Origin::File(path) => format!(
                    "{}: readable; TOML and configuration policy are valid",
                    path.display()
                ),
            });
        }
        Err(error) => {
            value.state = CheckState::Failed;
            value.observed = Some(subject);
            // The public error body omits the parser's source snippet and
            // values; never render the underlying cause into a diagnosis.
            value.reason = Some(error.body.message());
            value.code = Some(error.code().as_str().into());
            value.fix = Some(CheckFix {
                text: error.body.remedy(&RenderCx::default())?.text,
                command: None,
                argv: None,
            });
        }
    }
    Ok(value)
}
