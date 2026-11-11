//! Native file changes never inherit a previously qualified digest.
use super::*;
use se_proc::native_ipc::ExecutableStamp;
use std::{
    fs::{self, FileTimes, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
};
type Check = std::result::Result<(), Box<dyn std::error::Error>>;

struct Package {
    root: PathBuf,
    cli: PathBuf,
    server: PathBuf,
}
impl Package {
    fn new() -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let mut nonce = [0; 16];
        se_proc::fill_entropy(&mut nonce)?;
        let root =
            std::env::temp_dir().join(format!("image-review-{}", se_types::hex_lower(&nonce)));
        let mut directory = se_proc::NativeDirectoryCreation::begin();
        drop(directory.create(&root)?);
        let cli = root.join(if cfg!(windows) {
            "secode.exe"
        } else {
            "secode"
        });
        let server = root.join(if cfg!(windows) {
            "secode-server.exe"
        } else {
            "secode-server"
        });
        let package = Self { root, cli, server };
        for path in [&package.cli, &package.server] {
            fs::copy(std::env::current_exe()?, path)?;
        }
        Ok(package)
    }
}
impl Drop for Package {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.root) {
            eprintln!("image fixture cleanup failed: {error}");
        }
    }
}

fn edit_with_open_writer(
    path: &Path,
) -> std::result::Result<std::fs::File, Box<dyn std::error::Error>> {
    let before = fs::metadata(path)?;
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    file.seek(SeekFrom::End(-1))?;
    let mut byte = [0];
    file.read_exact(&mut byte)?;
    byte[0] ^= 1;
    file.seek(SeekFrom::End(-1))?;
    file.write_all(&byte)?;
    file.sync_all()?;
    file.set_times(FileTimes::new().set_modified(before.modified()?))?;
    assert_eq!(fs::metadata(path)?.len(), before.len());
    assert_eq!(fs::metadata(path)?.modified()?, before.modified()?);
    Ok(file)
}

fn edit_same_size_and_restore_mtime(path: &Path) -> Check {
    drop(edit_with_open_writer(path)?);
    Ok(())
}

#[test]
fn unchanged_native_images_keep_their_qualified_hashes() -> Check {
    let package = Package::new()?;
    let mut images = Images::open(&package.cli)?;
    assert!(ExecutableStamp::observe(&images.cli)?.is_some());
    assert!(ExecutableStamp::observe(&images.server)?.is_some());
    let expected = (images.cli_digest, images.server_digest);
    images.validate()?;
    images.validate()?;
    assert_eq!((images.cli_digest, images.server_digest), expected);
    Ok(())
}

#[test]
fn same_inode_size_and_mtime_edits_refuse_the_old_digest_for_either_image() -> Check {
    for server in [false, true] {
        let package = Package::new()?;
        let mut images = Images::open(&package.cli)?;
        let before = (images.cli_digest, images.server_digest);
        let path = if server {
            &package.server
        } else {
            &package.cli
        };
        edit_same_size_and_restore_mtime(path)?;
        assert!(
            images.validate().is_err(),
            "edited bytes reused a stale qualification"
        );
        let fresh = Images::open(&package.cli)?;
        assert_ne!((fresh.cli_digest, fresh.server_digest), before);
    }
    Ok(())
}

#[test]
fn a_retained_open_writer_cannot_hide_an_edit_from_native_validation() -> Check {
    for server in [false, true] {
        let package = Package::new()?;
        let mut images = Images::open(&package.cli)?;
        let path = if server {
            &package.server
        } else {
            &package.cli
        };
        let writer = edit_with_open_writer(path)?;
        assert!(
            images.validate().is_err(),
            "an open writer hid a same-size, restored-mtime edit"
        );
        drop(writer);
    }
    Ok(())
}

#[test]
fn replaced_inode_at_the_same_path_size_and_mtime_refuses_the_old_pin() -> Check {
    for server in [false, true] {
        let package = Package::new()?;
        let mut images = Images::open(&package.cli)?;
        let before = (images.cli_digest, images.server_digest);
        let path = if server {
            &package.server
        } else {
            &package.cli
        };
        let replacement = package.root.join("replacement");
        fs::copy(path, &replacement)?;
        edit_same_size_and_restore_mtime(&replacement)?;
        OpenOptions::new()
            .write(true)
            .open(&replacement)?
            .set_times(FileTimes::new().set_modified(fs::metadata(path)?.modified()?))?;
        fs::rename(replacement, path)?;
        assert!(
            images.validate().is_err(),
            "a replacement inherited the old pin"
        );
        let fresh = Images::open(&package.cli)?;
        assert_ne!((fresh.cli_digest, fresh.server_digest), before);
    }
    Ok(())
}

#[test]
fn script_images_still_require_fresh_byte_validation() -> Check {
    let package = Package::new()?;
    for path in [&package.cli, &package.server] {
        fs::write(path, b"#!/synthetic/interpreter\noriginal\n")?;
    }
    let mut images = Images::open(&package.cli)?;
    edit_same_size_and_restore_mtime(&package.server)?;
    assert!(
        images.validate().is_err(),
        "a script inherited a native cache key"
    );
    Ok(())
}
