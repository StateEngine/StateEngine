//! Persisted rendezvous bytes are runtime state, never caller input.
use se_core::ops::AgentCommand;
use se_types::{Detail, Result, SeError, details};
use std::path::Path;
pub(super) fn repair(home: &Path) -> String {
    let argv = vec![
        "se".into(),
        "doctor".into(),
        "--fix".into(),
        "runtime.endpoint".into(),
        "--home".into(),
        home.display().to_string(),
    ];
    let command = AgentCommand::from_argv(argv.clone())
        .map_or_else(|| format!("literal argv {argv:?}"), |value| value.command);
    format!(
        "Stop the runtime using this home from its owning terminal or application. Then run {command} and se up for this same home. The repair requires the exclusive runtime lease; preserve the store, credentials and machine identity."
    )
}
pub(super) fn decode(home: &Path, bytes: &[u8]) -> Result<se_host::EndpointRecord> {
    let cause = if bytes.is_empty() {
        "endpoint file is empty (zero bytes)".to_owned()
    } else {
        match se_host::client::endpoint::decode_endpoint(bytes) {
            Ok(record) => return Ok(record),
            Err(error) => format!("endpoint file is unreadable: {error}"),
        }
    };
    Err(SeError::new(Detail::SourceUnreadable(
        details::SourceUnreadable {
            subject: home.join("endpoint.json").display().to_string(),
            reason: cause,
            next_step: repair(home),
        },
    )))
}
