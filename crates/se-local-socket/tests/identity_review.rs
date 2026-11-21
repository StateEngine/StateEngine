//! Protects: endpoint removal touches only the object its caller recorded.
#![cfg(unix)]
use se_local_socket::identity::{ObjectId, Removal};
use std::{
    fs, io,
    os::unix::net::UnixListener,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
type Check = Result<(), Box<dyn std::error::Error>>;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "se-socket-identity-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_replaced_socket_is_preserved_and_the_recorded_one_is_removed() -> Check {
    let scratch = Scratch::new()?;
    let socket = scratch.0.join("s");
    let _first = UnixListener::bind(&socket)?;
    let recorded = ObjectId::local_socket(&socket)?;
    // Keep the original inode allocated so the filesystem cannot recycle it
    // for the replacement socket.
    let replaced = scratch.0.join("replaced");
    let _second = UnixListener::bind(&replaced)?;
    fs::rename(&replaced, &socket)?;
    let refused = recorded.remove_local_socket(&socket);
    assert!(
        matches!(&refused, Err(error) if error.kind() == io::ErrorKind::InvalidData),
        "a replacement socket was not preserved: {refused:?}"
    );
    assert!(
        fs::symlink_metadata(&socket).is_ok(),
        "the replacement was removed"
    );
    let current = ObjectId::local_socket(&socket)?;
    assert_eq!(current.remove_local_socket(&socket)?, Removal::Removed);
    assert_eq!(current.remove_local_socket(&socket)?, Removal::Absent);
    Ok(())
}

#[test]
fn a_regular_file_is_never_taken_for_a_socket_or_directory() -> Check {
    let scratch = Scratch::new()?;
    let file = scratch.0.join("s");
    fs::write(&file, b"not a socket")?;
    assert!(
        ObjectId::local_socket(&file).is_err(),
        "a regular file read as a socket"
    );
    assert!(
        ObjectId::directory(&file).is_err(),
        "a regular file read as a directory"
    );
    let directory = ObjectId::directory(&scratch.0)?;
    let other = scratch.0.join("other");
    fs::create_dir(&other)?;
    assert!(
        directory.remove_directory(&other).is_err(),
        "a directory with another identity was removed"
    );
    assert!(other.is_dir());
    Ok(())
}
