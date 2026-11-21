//! Store-free metadata presentation for help and guide, delegating version/schema to `se-core`.
use crate::{cli_command, diagnostic_word, guide};
use se_core::{
    ops::{AnyOp, AnyOutput, CATALOGUE, HelpOutput, Validate},
    registry::{CliExposure, Scope},
};
use se_types::{Detail, Result, SeError, details};

pub fn metadata_output(op: &AnyOp) -> Result<Option<AnyOutput>> {
    match op {
        AnyOp::MetaHelp(value) => {
            value.validate()?;
            let mut command = cli_command();
            command.build();
            for part in &value.path {
                command = command.find_subcommand(part).cloned().ok_or_else(|| {
                    SeError::new(Detail::UsageUnknownCommand(details::UsageUnknownCommand {
                        got: value
                            .path
                            .iter()
                            .map(|part| diagnostic_word(part))
                            .collect::<Vec<_>>()
                            .join(" "),
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
            // A global --project is refused by every operation without a
            // project scope, so such help must not advertise it.
            let accepts_project = CATALOGUE.iter().copied().any(|meta| {
                matches!(
                    &meta.cli,
                    CliExposure::Leaf { path, .. }
                        if path
                            .iter()
                            .copied()
                            .zip(value.path.iter().map(String::as_str))
                            .all(|(registered, shown)| registered == shown)
                            && matches!(
                                meta.scope,
                                Scope::Project | Scope::ProjectOrAll | Scope::Session
                            )
                )
            });
            if !accepts_project {
                command = command.mut_args(|arg| {
                    if arg.get_id() == "project" {
                        arg.hide(true)
                    } else {
                        arg
                    }
                });
            }
            Ok(Some(
                HelpOutput {
                    path: value.path.clone(),
                    usage: command.render_long_help().to_string(),
                }
                .into(),
            ))
        }
        AnyOp::MetaGuide(value) => Ok(Some(guide::read(value)?.into())),
        other => se_core::ops::metadata_output(other),
    }
}
