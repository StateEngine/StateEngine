//! Stock Codex may publish a hash-addressed alias to a socket in its own private
//! daemon directory. Pin both incarnations before sending any session secrets;
//! cold cleanup removes only those leaves, never the shared daemon directory.
use super::*;
use std::fs::Metadata;
use std::os::unix::{
    ffi::OsStrExt,
    fs::{FileTypeExt, MetadataExt},
};

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    session: se_types::SessionId,
    target: NativePath,
    listen_identity: (u64, u64),
    target_identity: (u64, u64),
    parent_identity: (u64, u64),
}
fn failure(reason: &str) -> SeError {
    se_core::scope::unreadable("Codex private endpoint custody", reason)
}
fn metadata(path: &Path) -> Result<Option<Metadata>> {
    match std::fs::symlink_metadata(path) {
        Ok(value) => Ok(Some(value)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(failure(&e.to_string())),
    }
}
fn identity(meta: &Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}
fn private_parent(path: &Path) -> Result<Metadata> {
    let _pin = se_proc::NativeStateFiles::open(path).map_err(native_error)?;
    metadata(path)?.ok_or_else(|| failure("private parent disappeared"))
}
fn original(socket: &Path, value: &Record) -> Result<Metadata> {
    if value.socket.to_local()? != socket || socket.file_name().is_none_or(|name| name != "s") {
        return Err(failure(
            "listen path differs from the original launch record",
        ));
    }
    let parent = private_parent(
        socket
            .parent()
            .ok_or_else(|| failure("missing listen parent"))?,
    )?;
    if identity(&parent) != (value.device, value.inode) {
        return Err(failure("original private listen directory was replaced"));
    }
    Ok(parent)
}
fn target(socket: &Path, listen: &Metadata, user: u32) -> Result<PathBuf> {
    if listen.uid() != user {
        return Err(failure("listen leaf has a different owner"));
    }
    if listen.file_type().is_socket() {
        return Ok(socket.to_owned());
    }
    if !listen.file_type().is_symlink() {
        return Err(failure("listen leaf is neither a socket nor a stock alias"));
    }
    let target = std::fs::read_link(socket).map_err(|e| failure(&e.to_string()))?;
    let hash = se_types::hex_lower(&Sha256::digest(socket.as_os_str().as_bytes()));
    let parent_name = format!("codex-daemon-{user}");
    if !target.is_absolute()
        || target.file_name().is_none_or(|name| name != hash.as_str())
        || target
            .parent()
            .and_then(Path::file_name)
            .is_none_or(|name| name != parent_name.as_str())
    {
        return Err(failure(
            "alias is not the stock hash-addressed endpoint for this exact listen path",
        ));
    }
    Ok(target)
}
fn socket_metadata(path: &Path, user: u32) -> Result<Metadata> {
    let value = metadata(path)?.ok_or_else(|| failure("actual socket is absent"))?;
    if !value.file_type().is_socket() || value.uid() != user || value.mode() & 0o7777 != 0o600 {
        return Err(failure(
            "actual endpoint must be a current-owner mode-0600 Unix socket",
        ));
    }
    Ok(value)
}
fn sidecar(record: &Path) -> PathBuf {
    record.with_file_name("codex-endpoint.json")
}
fn read_record(record: &Path) -> Result<Record> {
    let mut file = se_proc::OwnedFile::open(record)
        .map_err(native_error)?
        .ok_or_else(|| failure("original launch record is absent"))?;
    serde_json::from_slice(&file.read(8192).map_err(native_error)?)
        .map_err(|e| failure(&e.to_string()))
}
fn publish(path: &Path, endpoint: &Endpoint) -> Result<()> {
    let bytes = serde_json::to_vec(endpoint).map_err(|e| failure(&e.to_string()))?;
    let parent = path
        .parent()
        .ok_or_else(|| failure("missing journal parent"))?;
    let files = se_proc::NativeStateFiles::open(parent).map_err(native_error)?;
    let mut staged = files.create_staging(parent).map_err(native_error)?;
    staged
        .file
        .write_all(&bytes)
        .and_then(|()| staged.file.sync_all())
        .map_err(|e| failure(&e.to_string()))?;
    drop(staged.file);
    files
        .publish_no_replace(&staged.path, path)
        .map_err(native_error)?;
    let mut witness = se_proc::OwnedFile::open(path)
        .map_err(native_error)?
        .ok_or_else(|| failure("endpoint journal disappeared after publication"))?;
    if witness.read(8192).map_err(native_error)? != bytes {
        return Err(failure("endpoint journal readback differs"));
    }
    Ok(())
}
pub(super) fn prepare(socket: &Path, record: &Path, session: &se_types::SessionId) -> Result<()> {
    validate(socket, record, session, true)
}
pub(super) fn recover(socket: &Path, record: &Path, session: &se_types::SessionId) -> Result<()> {
    validate(socket, record, session, false)
}
fn validate(
    socket: &Path,
    record: &Path,
    session: &se_types::SessionId,
    publish_new: bool,
) -> Result<()> {
    let value = read_record(record)?;
    if &value.session != session {
        return Err(failure("launch record names a different session"));
    }
    let parent = original(socket, &value)?;
    let listen = metadata(socket)?.ok_or_else(|| failure("listen leaf is absent"))?;
    let target = target(socket, &listen, parent.uid())?;
    let target_parent = private_parent(
        target
            .parent()
            .ok_or_else(|| failure("missing target parent"))?,
    )?;
    let actual = socket_metadata(&target, parent.uid())?;
    let endpoint = Endpoint {
        session: session.clone(),
        target: NativePath::from_local(target)?,
        listen_identity: identity(&listen),
        target_identity: identity(&actual),
        parent_identity: identity(&target_parent),
    };
    let path = sidecar(record);
    if let Some(mut file) = se_proc::OwnedFile::open(&path).map_err(native_error)? {
        let pinned: Endpoint = serde_json::from_slice(&file.read(8192).map_err(native_error)?)
            .map_err(|e| failure(&e.to_string()))?;
        if pinned != endpoint {
            return Err(failure("endpoint incarnation differs from its journal"));
        }
    } else if publish_new {
        publish(&path, &endpoint)?;
    } else {
        return Err(failure(
            "the original endpoint identity journal is absent; no new custody was inferred",
        ));
    }
    // Read back the path identities after journal publication, before input.
    check(socket, &value, &endpoint)?;
    if metadata(socket)?.as_ref().map(identity) != Some(endpoint.listen_identity)
        || identity(&socket_metadata(
            &endpoint.target.to_local()?,
            parent.uid(),
        )?) != endpoint.target_identity
    {
        return Err(failure(
            "endpoint disappeared or changed before credential exchange",
        ));
    }
    Ok(())
}
fn check(socket: &Path, value: &Record, endpoint: &Endpoint) -> Result<()> {
    if endpoint.session != value.session {
        return Err(failure("endpoint journal names a different session"));
    }
    if metadata(
        socket
            .parent()
            .ok_or_else(|| failure("missing listen parent"))?,
    )?
    .is_some()
    {
        original(socket, value)?;
    }
    let target_path = endpoint.target.to_local()?;
    if let Some(listen) = metadata(socket)?
        && (identity(&listen) != endpoint.listen_identity
            || target(socket, &listen, listen.uid())? != target_path)
    {
        return Err(failure(
            "listen leaf was replaced; preserve the replacement",
        ));
    }
    let parent = target_path
        .parent()
        .ok_or_else(|| failure("missing target parent"))?;
    match metadata(parent)? {
        Some(_) => {
            let actual_parent = private_parent(parent)?;
            if identity(&actual_parent) != endpoint.parent_identity {
                return Err(failure(
                    "target directory was replaced; preserve the replacement",
                ));
            }
            if let Some(actual) = metadata(&target_path)?
                && (identity(&actual) != endpoint.target_identity
                    || !actual.file_type().is_socket()
                    || actual.uid() != actual_parent.uid()
                    || actual.mode() & 0o7777 != 0o600)
            {
                return Err(failure(
                    "target socket was replaced or widened; preserve it",
                ));
            }
        }
        None => {
            if metadata(&target_path)?.is_some() {
                return Err(failure("target remains without its parent"));
            }
        }
    }
    Ok(())
}
fn remove(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(failure(&e.to_string())),
    }
    if metadata(path)?.is_some() {
        return Err(failure("removed endpoint leaf reappeared"));
    }
    Ok(())
}
pub(super) fn retire(socket: &Path, record: &Path, value: &Record) -> Result<()> {
    let path = sidecar(record);
    let Some(mut file) = se_proc::OwnedFile::open(&path).map_err(native_error)? else {
        // Readiness may have failed before endpoint publication. The original
        // private directory and stock hash association still bound this leaf.
        if let Some(listen) = metadata(socket)? {
            let parent = original(socket, value)?;
            let target = target(socket, &listen, parent.uid())?;
            if metadata(&target)?.is_none() {
                let parent = target
                    .parent()
                    .ok_or_else(|| failure("missing target parent"))?;
                if metadata(parent)?.is_some() {
                    private_parent(parent)?;
                }
                if metadata(socket)?.as_ref().map(identity) != Some(identity(&listen)) {
                    return Err(failure("listen leaf changed before removal"));
                }
                remove(socket)?;
                return Ok(());
            }
            prepare(socket, record, &value.session)?;
            return retire(socket, record, value);
        }
        return Ok(());
    };
    let bytes = file.read(8192).map_err(native_error)?;
    let endpoint: Endpoint = serde_json::from_slice(&bytes).map_err(|e| failure(&e.to_string()))?;
    check(socket, value, &endpoint)?;
    let target = endpoint.target.to_local()?;
    remove(&target)?;
    if target != socket {
        remove(socket)?;
    }
    file.remove(Sha256::digest(&bytes).into())
        .map_err(native_error)
}
#[cfg(test)]
mod tests;
