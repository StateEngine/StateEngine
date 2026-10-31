//! Read-only setup observation, before any identity is selected or state created.
use super::files::Files;
use se_core::{
    ops::{StatusOutput, status},
    store_error::store_error,
};
use se_store::{SqliteFactory, SqliteReader, StoreFactory, StoreOptions};
use se_types::{Read, Result};
use std::{path::Path, time::Duration};

pub enum Setup {
    Absent(Box<StatusOutput>),
    Present(SqliteReader),
}
pub fn inspect(home: &Path, generated_at: String) -> Result<Setup> {
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
    let _files = Files::open(home).map_err(|e| store_error(&e))?;
    match SqliteFactory::open_reader(&StoreOptions {
        state_directory: home.to_owned(),
        busy_timeout: Duration::from_millis(250),
    })
    .map_err(|e| store_error(&e))?
    {
        Read::Absent { checked } => Ok(missing(home, generated_at, checked)),
        Read::Present { value } => Ok(Setup::Present(value)),
        Read::Unreadable { source, reason, .. } => {
            Err(se_core::scope::unreadable(&source, &reason))
        }
        Read::Unknown { what } => Err(se_core::scope::unreadable("state store", &what)),
    }
}
fn missing(home: &Path, generated_at: String, checked: String) -> Setup {
    Setup::Absent(Box::new(status::missing(
        home.to_string_lossy().into_owned(),
        generated_at,
        checked,
    )))
}
