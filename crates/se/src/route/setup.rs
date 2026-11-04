//! Read-only setup observation, before any identity is selected or state created.
use super::files::Files;
use se_core::{
    ops::{StatusOutput, status},
    store_error::store_error,
};
use se_store::{ReadPhase, SqliteFactory, SqliteReader, StoreFactory, StoreOptions};
use se_types::{Read, Result};
use std::{path::Path, time::Duration};

pub enum Setup<T = SqliteReader> {
    Absent(Box<StatusOutput>),
    Present(T),
}
pub fn inspect(home: &Path, generated_at: String) -> Result<Setup> {
    Ok(
        match inspect_with(home, generated_at, SqliteFactory::open_reader)? {
            Setup::Absent(output) => Setup::Absent(output),
            Setup::Present((_, reader)) => Setup::Present(reader),
        },
    )
}
pub fn inspect_phase(
    home: &Path,
    generated_at: String,
) -> Result<Setup<(Files, (SqliteReader, ReadPhase))>> {
    inspect_with(home, generated_at, SqliteFactory::open_reader_with_phase)
}
fn inspect_with<T>(
    home: &Path,
    generated_at: String,
    open: impl FnOnce(&StoreOptions) -> se_store::StoreResult<Read<T>>,
) -> Result<Setup<(Files, T)>> {
    match std::fs::symlink_metadata(home) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(missing(
                home,
                generated_at,
                format!("native directory absence at {}", home.display()),
            ));
        }
        Err(error) => return Err(se_core::scope::unreadable("state home", &error.to_string())),
        Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
            return Err(se_core::scope::unreadable(
                "state home",
                "not a native directory without links",
            ));
        }
        Ok(_) => (),
    }
    // Protection and directory identity are native facts, independent of DB bytes.
    // Only the store reader below establishes initialization. A runtime.lock
    // may already exist for an uninstall or an init still holding exclusion.
    let files = Files::open(home).map_err(|e| store_error(&e))?;
    match open(&StoreOptions {
        state_directory: home.to_owned(),
        busy_timeout: Duration::from_millis(250),
    })
    .map_err(|e| store_error(&e))?
    {
        Read::Absent { checked } => Ok(missing(home, generated_at, checked)),
        Read::Present { value } => Ok(Setup::Present((files, value))),
        Read::Unreadable { source, reason, .. } => {
            Err(se_core::scope::unreadable(&source, &reason))
        }
        Read::Unknown { what } => Err(se_core::scope::unreadable("state store", &what)),
    }
}
fn missing<T>(home: &Path, generated_at: String, checked: String) -> Setup<T> {
    Setup::Absent(Box::new(status::missing(
        home.to_string_lossy().into_owned(),
        generated_at,
        checked,
    )))
}

/// Resolved setup inputs produce both the readable hint and literal remedy argv.
pub struct InitRemedy<'a> {
    pub home: &'a Path,
    pub workspace: &'a Path,
}
impl se_types::OperationCommand for InitRemedy<'_> {
    fn cli_argv(&self) -> Vec<String> {
        vec![
            "se".into(),
            "--home".into(),
            self.home.display().to_string(),
            "init".into(),
            "--repo".into(),
            self.workspace.display().to_string(),
        ]
    }
}
impl se_types::RemedyCommands for InitRemedy<'_> {
    fn for_error(&self, error: &se_types::ErrorBody) -> Result<Option<se_types::Cmd>> {
        (error.code() == se_types::Code::SetupRequired)
            .then(|| se_types::Argv::from_op(self).map(|argv| se_types::Cmd::Se { argv }))
            .transpose()
    }
}
pub fn required(cx: &crate::bootstrap::Bootstrap) -> se_types::SeError {
    use se_types::{Detail, SeError, details};
    SeError::new(Detail::SetupRequired(details::SetupRequired {
        subject: "StateEngine store".into(),
        reason: "not initialized for the selected state home".into(),
        next_step: format!(
            "Run se --home {} init --repo {}",
            quote(&cx.home.display().to_string()),
            quote(&cx.cwd.display().to_string())
        ),
    }))
}
fn quote(value: &str) -> String {
    #[cfg(windows)]
    let escaped = value.replace('\'', "''");
    #[cfg(not(windows))]
    let escaped = value.replace('\'', "'\"'\"'");
    format!("'{escaped}'")
}
