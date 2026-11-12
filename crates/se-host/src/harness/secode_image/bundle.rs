//! Discover the native provider from this executable's physical package before
//! consulting PATH. An unreadable declared bundle never becomes no bundle.
use super::{Images, incompatible, unreadable};
use se_types::Result;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub fn discover() -> Result<Option<PathBuf>> {
    let executable = std::env::current_exe().map_err(|e| unreadable("SE Code bundle lookup", e))?;
    let parent = executable
        .parent()
        .ok_or_else(|| incompatible("host executable has no package directory"))?;
    let mut roots = vec![parent.to_owned()];
    if parent.file_name().is_some_and(|name| name == "stateengine")
        && let Some(root) = parent.parent()
    {
        roots.push(root.to_owned());
    }
    for root in roots {
        let Some(manifest) = read(&root)? else {
            continue;
        };
        let cli = root.join(if cfg!(windows) {
            "secode.exe"
        } else {
            "secode"
        });
        let mut images = Images::open(&cli)?;
        entries(&images, &manifest)?;
        images.validate()?;
        return Ok(Some(images.cli));
    }
    Ok(None)
}
pub(super) fn verify(images: &Images) -> Result<()> {
    let parent = images
        .cli
        .parent()
        .ok_or_else(|| incompatible("selected CLI has no package directory"))?;
    if let Some(manifest) = read(parent)? {
        entries(images, &manifest)?;
    }
    Ok(())
}
fn entries(images: &Images, manifest: &Value) -> Result<()> {
    let binaries = manifest["binaries"]
        .as_object()
        .ok_or_else(|| incompatible("bundle native-image inventory is absent"))?;
    let cli = binaries
        .get(if cfg!(windows) {
            "secode.exe"
        } else {
            "secode"
        })
        .ok_or_else(|| incompatible("bundle CLI entry is absent"))?;
    let server = binaries
        .get(if cfg!(windows) {
            "secode-server.exe"
        } else {
            "secode-server"
        })
        .ok_or_else(|| incompatible("bundle server entry is absent"))?;
    images.require_entry(false, cli)?;
    images.require_entry(true, server)?;
    let commit = cli["source_commit"]
        .as_str()
        .filter(|v| {
            v.len() == 40
                && v.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
        .ok_or_else(|| incompatible("bundle CLI source identity is absent or malformed"))?;
    if server["source_commit"] != commit
        || cli["target"] != manifest["target"]
        || server["target"] != manifest["target"]
    {
        return Err(incompatible(
            "bundle native images do not share the declared source and target",
        ));
    }
    Ok(())
}
fn read(root: &Path) -> Result<Option<Value>> {
    let path = root.join("release-manifest.json");
    let Some(mut pin) = se_proc::NativeSourcePin::open(&path)
        .map_err(|e| unreadable("SE Code bundle manifest", e))?
    else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    let mut offset = 0;
    loop {
        let chunk = pin
            .read_at(offset, 256 * 1024)
            .map_err(|e| unreadable("SE Code bundle manifest", e))?;
        if chunk.bytes.len() > (2 * 1024 * 1024usize).saturating_sub(bytes.len()) {
            return Err(incompatible("bundle manifest exceeds two MiB"));
        }
        bytes.extend_from_slice(&chunk.bytes);
        offset = chunk.next_offset;
        if chunk.end_of_file {
            break;
        }
    }
    pin.validate_path(&path)
        .map_err(|e| unreadable("SE Code bundle manifest readback", e))?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|e| unreadable("SE Code bundle manifest", e))?;
    if value["schema"] != "secode.release.package.v1" {
        return Err(incompatible("bundle manifest schema is unsupported"));
    }
    Ok(Some(value))
}
