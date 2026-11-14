//! Translate saved workspace authority to the provider's existing sandbox.
//! Policy inspection reports intent; it does not claim a native tool ran.
use super::{incompatible, probe};
use crate::client::lease::Deadline;
use se_types::Result;
use serde_json::Value;
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

const CAPABILITY: &str = "git_metadata_read_only/v1";

fn document(bytes: &[u8]) -> Result<Value> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| incompatible("workspace-write requires readable provider sandbox policy"))?;
    if value["schema"] != "secode.sandbox-policy.v1"
        || !value["capabilities"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(CAPABILITY)))
    {
        return Err(incompatible(
            "workspace-write with read-only Git metadata requires provider capability git_metadata_read_only/v1; install a compatible bundle or select a read-only profile",
        ));
    }
    Ok(value)
}

pub(crate) async fn require_capability(
    server: se_proc::NativeExecutableInvocation,
    deadline: &Deadline,
) -> Result<()> {
    let bytes = probe::command(server, &["sandbox-policy".into(), "--capabilities".into()], deadline)
        .await.map_err(|cause| incompatible(format!(
            "workspace-write requires provider capability {CAPABILITY}; sandbox inspection failed: {cause}")))?;
    document(&bytes)?;
    Ok(())
}

pub(crate) async fn inspect(
    server: se_proc::NativeExecutableInvocation,
    profile: &Path,
    directory: &Path,
    deadline: &Deadline,
) -> Result<Value> {
    let scratch = profile.with_extension("scratch");
    let mut environment = vec![(
        OsString::from("SECODE_CONFIG"),
        profile.join("host-policy.json").into_os_string(),
    )];
    for name in ["TMPDIR", "TMP", "TEMP"] {
        environment.push((name.into(), scratch.as_os_str().to_owned()));
    }
    let bytes = probe::command_with_environment(
        server,
        &[
            "sandbox-policy".into(),
            "--service".into(),
            profile.as_os_str().to_owned(),
            "--directory".into(),
            directory.as_os_str().to_owned(),
        ],
        &environment,
        deadline,
    )
    .await?;
    document(&bytes)
}

pub(crate) fn verify(value: &Value, roots: &[PathBuf], network: bool) -> Result<()> {
    if value["realization"] != "not_started"
        || value["policy"]["git_metadata_read_only"] != true
        || value["policy"]["network"] != network
    {
        return Err(incompatible(
            "provider sandbox policy did not preserve the saved Git-metadata or network policy; no task was offered",
        ));
    }
    let actual = value["policy"]["writable_roots"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .map(|item| item.as_str().map(PathBuf::from))
                .collect::<Option<Vec<_>>>()
        })
        .ok_or_else(|| incompatible("provider sandbox policy has no readable writable-root set"))?;
    let expected = roots.iter().collect::<std::collections::BTreeSet<_>>();
    let observed = actual.iter().collect::<std::collections::BTreeSet<_>>();
    if expected != observed || actual.len() != observed.len() {
        return Err(incompatible(
            "provider writable roots differ from the saved workspace and private temporary directory; no task was offered",
        ));
    }
    Ok(())
}
