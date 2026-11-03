//! Managed-process SE_SESSION resolves to one protected launch pin. The handle
//! is a canonical public session ID; it is never interpreted as bearer bytes.
use crate::state_files::{failure, io_error};
use crate::{NativeStateFiles, OwnedFile, StateFileError, StateFileErrorCode};
use se_types::{LaunchId, Secret, SessionId};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::PathBuf,
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, StateFileError>;
/// A launch and its newly prepared process-bound session share their UUID;
/// the kind prefix keeps the two public identities distinct. This gives the
/// protected pin an exact address without a scan or another secret index.
pub fn session_launch_id(session: &SessionId) -> Result<LaunchId> {
    let path = PathBuf::from("SE_SESSION");
    let canonical: SessionId = session.as_str().parse().map_err(|_| {
        failure(
            StateFileErrorCode::LocationUnsafe,
            "canonical managed session handle required",
            &path,
        )
    })?;
    format!(
        "{}{}",
        LaunchId::PREFIX,
        &canonical.as_str()[SessionId::PREFIX.len()..]
    )
    .parse()
    .map_err(|_| {
        failure(
            StateFileErrorCode::LocationUnsafe,
            "canonical launch identity required",
            &path,
        )
    })
}
fn pin_path(state: &NativeStateFiles, handle: &str) -> Result<(SessionId, PathBuf)> {
    let session: SessionId = handle.parse().map_err(|_| {
        failure(
            StateFileErrorCode::LocationUnsafe,
            "SE_SESSION must be a canonical ses_ UUID handle",
            state.root(),
        )
    })?;
    let launch = session_launch_id(&session)?;
    Ok((
        session,
        state
            .root()
            .join("launch")
            .join(launch.as_str())
            .join("pin"),
    ))
}
fn validate_token(bytes: &[u8], session: &SessionId, path: &std::path::Path) -> Result<()> {
    let prefix = format!("sec1.{}.", session.as_str());
    let suffix = bytes
        .strip_prefix(prefix.as_bytes())
        .filter(|suffix| suffix.len() == 43)
        .ok_or_else(|| {
            failure(
                StateFileErrorCode::SourceChanged,
                "session pin must contain the exact sec1 session token",
                path,
            )
        })?;
    if !suffix
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
    {
        return Err(failure(
            StateFileErrorCode::SourceChanged,
            "session pin token encoding is invalid",
            path,
        ));
    }
    Ok(())
}
/// No ambient environment or fallback authority. The caller selects its already
/// protected state home and passes the SE_SESSION handle, never secret material.
pub fn read_session_pin(state: &NativeStateFiles, handle: &str) -> Result<Secret> {
    let (session, path) = pin_path(state, handle)?;
    let file = state.readback(&path)?.ok_or_else(|| {
        io_error(
            "managed session pin is absent; no owner fallback",
            &path,
            std::io::Error::from(std::io::ErrorKind::NotFound),
        )
    })?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(257)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error("read managed session pin", &path, e))?;
    if bytes.len() > 256 {
        return Err(failure(
            StateFileErrorCode::SourceChanged,
            "managed session pin exceeds its bound",
            &path,
        ));
    }
    validate_token(&bytes, &session, &path)?;
    Secret::new(std::mem::take(&mut *bytes)).map_err(|_| {
        failure(
            StateFileErrorCode::SourceChanged,
            "managed session pin token is invalid",
            &path,
        )
    })
}
/// Publication uses the existing exclusive protected staging/no-replace native
/// path and reads the exact secret back before returning. Existing pins refuse.
pub fn publish_session_pin(
    state: &NativeStateFiles,
    session: &SessionId,
    token: &Secret,
) -> Result<()> {
    let (_, path) = pin_path(state, session.as_str())?;
    validate_token(token.expose(), session, &path)?;
    let launch_root = state.root().join("launch");
    state.prepare_directory(&launch_root)?;
    let launch_files = NativeStateFiles::open(&launch_root)?;
    let directory = launch_root.join(session_launch_id(session)?.as_str());
    launch_files.prepare_directory(&directory)?;
    let files = NativeStateFiles::open(&directory)?;
    let mut staged = files.create_staging(&directory)?;
    staged
        .file
        .write_all(token.expose())
        .map_err(|e| io_error("write managed session pin", &staged.path, e))?;
    // Publication pins and flushes its own writer; the staging handle denies
    // a second Windows writer until it closes.
    drop(staged.file);
    files.publish_no_replace(&staged.path, &path)?;
    let observed = read_session_pin(state, session.as_str())?;
    if Sha256::digest(observed.expose()) != Sha256::digest(token.expose()) {
        return Err(failure(
            StateFileErrorCode::SourceChanged,
            "published session pin differs on readback",
            &path,
        ));
    }
    Ok(())
}
/// Caller revokes the credential in the store first. Removal preserves an edited
/// or replaced pin, and success independently witnesses native absence.
pub fn remove_session_pin(
    state: &NativeStateFiles,
    session: &SessionId,
    expected: [u8; 32],
) -> Result<()> {
    let (_, path) = pin_path(state, session.as_str())?;
    if state.readback(&path)?.is_none() {
        return Ok(());
    }
    let file = OwnedFile::open(&path)?.ok_or_else(|| {
        failure(
            StateFileErrorCode::SourceChanged,
            "session pin disappeared before removal custody",
            &path,
        )
    })?;
    file.remove(expected)?;
    if state.readback(&path)?.is_some() {
        return Err(failure(
            StateFileErrorCode::SourceChanged,
            "session pin remains after removal",
            &path,
        ));
    }
    Ok(())
}
