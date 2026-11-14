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
    _root_owner: crate::test_directory::PrivateDirectory,
}
impl Package {
    fn new() -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let root_owner = crate::test_directory::private_case_directory()?;
        let root = root_owner.to_path_buf();
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
        for path in [&cli, &server] {
            fs::write(path, crate::harness::secode_image_fixture::image_bytes())?;
        }
        Ok(Self {
            root,
            cli,
            server,
            _root_owner: root_owner.cleanup_on_drop(),
        })
    }

    fn declare_bundle(&self) -> Check {
        let mut binaries = serde_json::Map::new();
        for (path, bin) in [(&self.cli, "secode"), (&self.server, "secode-server")] {
            let bytes = fs::read(path)?;
            binaries.insert(
                path.file_name()
                    .ok_or("fixture filename absent")?
                    .to_string_lossy()
                    .into_owned(),
                serde_json::json!({
                    "bin": bin,
                    "bytes": bytes.len(),
                    "sha256": se_types::hex_lower(&Sha256::digest(&bytes)),
                    "source_commit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "target": "synthetic-native-target"
                }),
            );
        }
        fs::write(
            self.root.join("release-manifest.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema": "secode.release.package.v1",
                "target": "synthetic-native-target",
                "binaries": binaries
            }))?,
        )?;
        Ok(())
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

#[test]
fn reuse_probe_between_probe_image_edits_require_fresh_qualification_and_refuse_stale_bundle_hashes()
-> Check {
    for server in [false, true] {
        let package = Package::new()?;
        package.declare_bundle()?;
        let mut previous = Images::open(&package.cli)?;
        assert!(previous.reusable(&package.cli)?);
        edit_same_size_and_restore_mtime(if server {
            &package.server
        } else {
            &package.cli
        })?;
        assert!(
            !previous.reusable(&package.cli)?,
            "changed bytes reused prior qualification"
        );
        assert!(
            Images::open(&package.cli).is_err(),
            "fresh qualification accepted a stale manifest"
        );
    }
    Ok(())
}

#[test]
fn reuse_probe_a_matching_updated_bundle_receives_new_qualification_before_reuse() -> Check {
    let package = Package::new()?;
    package.declare_bundle()?;
    let mut previous = Images::open(&package.cli)?;
    let original = previous.server_digest;
    edit_same_size_and_restore_mtime(&package.server)?;
    package.declare_bundle()?;
    assert!(!previous.reusable(&package.cli)?);
    let mut fresh = Images::open(&package.cli)?;
    assert_ne!(fresh.server_digest, original);
    assert!(fresh.reusable(&package.cli)?);
    Ok(())
}

#[test]
fn reuse_probe_a_manifest_change_between_probes_is_read_even_when_native_stamps_match() -> Check {
    let package = Package::new()?;
    package.declare_bundle()?;
    let mut previous = Images::open(&package.cli)?;
    assert!(previous.reusable(&package.cli)?);
    let path = package.root.join("release-manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    let key = package
        .server
        .file_name()
        .ok_or("fixture filename absent")?
        .to_string_lossy();
    manifest["binaries"][key.as_ref()]["sha256"] = serde_json::json!("00".repeat(32));
    fs::write(path, serde_json::to_vec(&manifest)?)?;
    assert!(
        previous.reusable(&package.cli).is_err(),
        "changed manifest inherited old qualification"
    );
    assert!(Images::open(&package.cli).is_err());
    Ok(())
}

#[test]
fn reuse_probe_script_packages_never_reuse_native_qualification_between_probes() -> Check {
    let package = Package::new()?;
    for path in [&package.cli, &package.server] {
        fs::write(path, b"#!/synthetic/interpreter\noriginal\n")?;
    }
    package.declare_bundle()?;
    let mut previous = Images::open(&package.cli)?;
    assert!(!previous.reusable(&package.cli)?);
    assert!(Images::open(&package.cli).is_ok());
    Ok(())
}
