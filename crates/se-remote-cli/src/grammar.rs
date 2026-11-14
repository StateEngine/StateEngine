use super::*;
use clap::{Arg, Command};
pub(super) const CONTROLS: &[&str] = &[
    "add",
    "permissions",
    "disconnect",
    "forget",
    "disable",
    "grants",
    "revoke",
    "__accept",
    "__authorize",
];
fn value(name: &'static str) -> Arg {
    Arg::new(name).long(name).num_args(1)
}
fn leaf(name: &'static str, about: &'static str) -> Command {
    Command::new(name)
        .about(about)
        .disable_help_flag(true)
        .disable_version_flag(true)
        .disable_help_subcommand(true)
}
pub(super) fn command() -> Command {
    se_core::ops::cli_command().mut_subcommand("remote", |command| {
        command
            .subcommand(
                leaf(
                    "disconnect",
                    "Close this saved connection without stopping the remote host or agents",
                )
                .arg(value("name").required(true)),
            )
            .subcommand(
                leaf(
                    "forget",
                    "Forget this saved connection without stopping the remote host or agents",
                )
                .arg(value("name").required(true)),
            )
            .subcommand(
                leaf("add", "Connect to a machine using your SSH configuration")
                    .arg(Arg::new("destination").index(1).required(true))
                    .arg(value("name").required(true)),
            )
            .subcommand(leaf("permissions", "Review source access or launch consent as the native Owner")
                .arg(value("name"))
                .arg(Arg::new("local").long("local").action(clap::ArgAction::SetTrue).conflicts_with_all(["name", "launch"]))
                .arg(Arg::new("launch").long("launch").action(clap::ArgAction::SetTrue).help("Review which existing destination agents this paired machine may launch")))
            .subcommand(leaf(
                "disable",
                "Close this machine's remote listener (human only)",
            ))
            .subcommand(
                leaf(
                    "grants",
                    "List machine sessions and their authority revisions",
                )
                .arg(value("after"))
                .arg(value("limit").default_value("20")),
            )
            .subcommand(
                leaf(
                    "revoke",
                    "Revoke a machine session and close its connections",
                )
                .arg(value("grant").required(true))
                .arg(value("revision").required(true)),
            )
            .subcommand(
                leaf("__accept", "Protected SSH bootstrap")
                    .hide(true)
                    .arg(value("source-host").required(true)),
            )
            .subcommand(leaf("__authorize", "Protected SSH channel authorization").hide(true))
    })
}
pub(super) fn decode(name: &str, m: &ArgMatches) -> Result<Input> {
    let input = match name {
        "disconnect" | "forget" => OwnerInput::Disconnect {
            alias: required(m, "name")?,
            forget: name == "forget",
        },
        "add" => OwnerInput::Add {
            destination: required(m, "destination")?,
            alias: required(m, "name")?,
            distribution: se_types::NativePath::from_local(
                std::env::current_exe()
                    .map_err(|_| invalid("a readable native distribution path"))?,
            )?,
        },
        "disable" => OwnerInput::Disable,
        "__accept" => OwnerInput::Bootstrap {
            source_host: identifier(m, "source-host")?,
        },
        "__authorize" => OwnerInput::MachineIdentity,
        "grants" => OwnerInput::Grants {
            after: text(m, "after")
                .map(|_| identifier(m, "after"))
                .transpose()?,
            limit: required(m, "limit")?
                .parse()
                .map_err(|_| invalid("limit 1..100"))?,
        },
        "revoke" => OwnerInput::Revoke {
            grant: identifier(m, "grant")?,
            authority_revision: required(m, "revision")?
                .parse()
                .map_err(|_| invalid("nonzero authority revision"))?,
            key: IdempotencyKey::new(
                text(m, "key").unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            )?,
        },
        _ => return Err(invalid("known native machine control")),
    };
    if name != "revoke" && text(m, "key").is_some() {
        return Err(invalid("this machine control has no mutation-key argument"));
    }
    input.validate()?;
    Ok(Input::Ready(input))
}
fn identifier<T: serde::de::DeserializeOwned>(m: &ArgMatches, name: &str) -> Result<T> {
    serde_json::from_value(serde_json::Value::String(required(m, name)?)).map_err(|_| invalid(name))
}
