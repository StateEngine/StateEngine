//! The Windows private endpoint for a Codex agent: the forwarder's AF_UNIX
//! socket in a private per-launch directory. This module keeps its own record
//! beside the launch record: the directory's native identity at creation, and
//! the socket leaf's identity and AF_UNIX tag when the host first checks it.
//! Removal compares and disposes through one handle; anything that changed is
//! preserved and reported, never repaired.
use se_local_socket::identity::ObjectId;
use se_types::{NativePath, Result, SeError, SessionId};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// The directory record, written when the launch creates the directory.
const DIRECTORY: &str = "codex-endpoint.json";
/// The socket leaf's identity, pinned when the host first checks it.
const LEAF: &str = "codex-endpoint-leaf.json";
/// The longest local socket path Windows accepts.
const LIMIT: usize = 107;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Directory {
    session: SessionId,
    socket: NativePath,
    directory: [u8; 32],
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Leaf {
    session: SessionId,
    leaf: [u8; 32],
}

fn failure(reason: &str) -> SeError {
    se_core::scope::unreadable("Codex private endpoint custody", reason)
}
fn native(error: impl std::fmt::Display) -> SeError {
    failure(&error.to_string())
}

/// The launch's own directory when its path fits, otherwise a short private
/// one under the data home named by the launch.
pub(crate) fn socket_path(
    launch: PathBuf,
    state_home: &Path,
    session: &SessionId,
) -> Result<PathBuf> {
    let preferred = launch.join("cx").join("s");
    let selected = if preferred.as_os_str().as_encoded_bytes().len() <= LIMIT {
        preferred
    } else {
        let launch = se_proc::session_launch_id(session).map_err(native)?;
        let name = se_types::hex_lower(&Sha256::digest(launch.as_str().as_bytes()));
        state_home.join("cx").join(&name[..16]).join("s")
    };
    if selected.as_os_str().as_encoded_bytes().len() > LIMIT {
        return Err(crate::harness::codex_rpc::incompatible(
            "the private local socket path is longer than Windows allows",
            "Move the StateEngine data home to a shorter folder and relaunch.",
        ));
    }
    Ok(selected)
}

/// The short fallback's shared `cx` root, held private while a launch creates
/// its directory under it.
pub(crate) fn hold_short_root(parent: &Path) -> Result<Option<se_proc::NativeStateFiles>> {
    match parent.parent() {
        Some(root) if root.file_name().is_some_and(|name| name == "cx") => {
            se_proc::NativeStateFiles::create(root)
                .map(Some)
                .map_err(native)
        }
        _ => Ok(None),
    }
}

fn beside(record: &Path, name: &str) -> Result<PathBuf> {
    Ok(record
        .parent()
        .ok_or_else(|| failure("missing launch directory"))?
        .join(name))
}

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<(T, Vec<u8>)>> {
    let Some(mut file) = se_proc::OwnedFile::open(path).map_err(native)? else {
        return Ok(None);
    };
    let bytes = file.read(8192).map_err(native)?;
    Ok(Some((
        serde_json::from_slice(&bytes).map_err(native)?,
        bytes,
    )))
}

fn publish(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    use std::io::Write;
    let bytes = serde_json::to_vec(value).map_err(native)?;
    let parent = path
        .parent()
        .ok_or_else(|| failure("missing launch directory"))?;
    let files = se_proc::NativeStateFiles::open(parent).map_err(native)?;
    let mut staged = files.create_staging(parent).map_err(native)?;
    staged
        .file
        .write_all(&bytes)
        .and_then(|()| staged.file.sync_all())
        .map_err(native)?;
    drop(staged.file);
    files.publish_no_replace(&staged.path, path).map_err(native)
}

fn remove(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(file) = se_proc::OwnedFile::open(path).map_err(native)? {
        file.remove(Sha256::digest(bytes).into()).map_err(native)?;
    }
    Ok(())
}

fn directory_id(parent: &Path) -> Result<ObjectId> {
    // Opening checks the directory's owner-only access.
    let _private = se_proc::NativeStateFiles::open(parent).map_err(native)?;
    ObjectId::directory(parent).map_err(native)
}

/// Right after the launch creates the private directory, before the forwarder
/// can bind in it.
pub(crate) fn record(socket: &Path, record: &Path, session: &SessionId) -> Result<()> {
    let parent = socket
        .parent()
        .ok_or_else(|| failure("missing listen parent"))?;
    publish(
        &beside(record, DIRECTORY)?,
        &Directory {
            session: session.clone(),
            socket: NativePath::from_local(socket.to_owned())?,
            directory: directory_id(parent)?.to_bytes(),
        },
    )
}

/// The recorded directory, when it names this session and socket.
fn recorded(
    socket: &Path,
    record: &Path,
    session: &SessionId,
) -> Result<Option<(Directory, Vec<u8>)>> {
    let Some((value, bytes)) = read::<Directory>(&beside(record, DIRECTORY)?)? else {
        return Ok(None);
    };
    if &value.session != session
        || value.socket.to_local()? != socket
        || socket.file_name().is_none_or(|name| name != "s")
    {
        return Err(failure("the endpoint record names another session or path"));
    }
    Ok(Some((value, bytes)))
}

fn leaf(record: &Path, session: &SessionId) -> Result<Option<(ObjectId, Vec<u8>)>> {
    let Some((pin, bytes)) = read::<Leaf>(&beside(record, LEAF)?)? else {
        return Ok(None);
    };
    if &pin.session != session {
        return Err(failure("the endpoint pin names another session"));
    }
    Ok(Some((ObjectId::from_bytes(pin.leaf), bytes)))
}

/// Before any session secret is sent: the recorded path and directory, and
/// the socket leaf, pinned the first time and compared on every later check.
pub(crate) fn check(socket: &Path, record: &Path, session: &SessionId) -> Result<()> {
    let (value, _) = recorded(socket, record, session)?
        .ok_or_else(|| failure("the endpoint record is absent"))?;
    let parent = socket
        .parent()
        .ok_or_else(|| failure("missing listen parent"))?;
    if directory_id(parent)?.to_bytes() != value.directory {
        return Err(failure("original private listen directory was replaced"));
    }
    let observed = ObjectId::local_socket(socket)
        .map_err(|e| failure(&format!("listen leaf is not the local socket: {e}")))?;
    match leaf(record, session)? {
        Some((pinned, _)) if pinned == observed => Ok(()),
        Some(_) => Err(failure("the socket leaf was replaced since it was pinned")),
        None => publish(
            &beside(record, LEAF)?,
            &Leaf {
                session: session.clone(),
                leaf: observed.to_bytes(),
            },
        ),
    }
}

/// After native exit: remove only the pinned leaf and the recorded directory,
/// each compared and disposed through one handle, then this module's records.
pub(crate) fn retire(socket: &Path, record: &Path, session: &SessionId) -> Result<()> {
    let parent = socket
        .parent()
        .ok_or_else(|| failure("missing listen parent"))?;
    let present = match std::fs::symlink_metadata(parent) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(native(e)),
        Ok(_) => true,
    };
    let Some((value, directory_bytes)) = recorded(socket, record, session)? else {
        return if present {
            Err(failure(
                "the directory remains without its endpoint record; it is preserved",
            ))
        } else {
            Ok(())
        };
    };
    let pinned = leaf(record, session)?;
    if present {
        match &pinned {
            Some((pin, _)) => {
                pin.remove_local_socket(socket)
                    .map_err(|e| failure(&format!("socket leaf: {e}")))?;
            }
            None if std::fs::symlink_metadata(socket).is_ok() => {
                return Err(failure("the socket leaf was never pinned; it is preserved"));
            }
            None => {}
        }
        ObjectId::from_bytes(value.directory)
            .remove_directory(parent)
            .map_err(|e| failure(&format!("private listen directory: {e}")))?;
    }
    if let Some((_, bytes)) = pinned {
        remove(&beside(record, LEAF)?, &bytes)?;
    }
    remove(&beside(record, DIRECTORY)?, &directory_bytes)
}
