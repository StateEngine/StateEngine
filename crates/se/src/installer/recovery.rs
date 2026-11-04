//! Resume only a protected journal bound to the original archive and paths.
use super::{args, native};
use crate::runtime::{InstallRecord, Installation};
use se_proc::{NativeInstallationClaim, NativeStateFiles, OwnedFile};
use se_types::{Result, Sha256};
use std::{collections::BTreeMap, ffi::OsString, io, path::Path};

fn read(path: &Path, limit: usize) -> Result<Option<Vec<u8>>> {
    OwnedFile::open(path)
        .map_err(native)?
        .map(|mut file| file.read(limit).map_err(native))
        .transpose()
}
fn required(path: &Path, limit: usize) -> Result<Vec<u8>> {
    read(path, limit)?.ok_or_else(|| args::invalid("the complete original partial journal"))
}
fn hash(path: &Path) -> Result<Sha256> {
    let mut file = OwnedFile::open(path)
        .map_err(native)?
        .ok_or_else(|| args::invalid("the matching original archive"))?;
    Ok(Sha256::from_bytes(file.sha256().map_err(native)?))
}
fn plain_tree(root: &Path) -> Result<()> {
    let mut pending = vec![root.to_owned()];
    let mut count = 0;
    while let Some(directory) = pending.pop() {
        NativeStateFiles::open(&directory).map_err(native)?;
        for entry in std::fs::read_dir(&directory)
            .map_err(|error| se_core::scope::unreadable("partial journal", &error.to_string()))?
        {
            let entry = entry.map_err(|error| {
                se_core::scope::unreadable("partial journal entry", &error.to_string())
            })?;
            count += 1;
            if count > 4096 {
                return Err(args::invalid("at most 4096 partial journal entries"));
            }
            let kind = entry.file_type().map_err(|error| {
                se_core::scope::unreadable("partial journal type", &error.to_string())
            })?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if !kind.is_file() || OwnedFile::open(&entry.path()).map_err(native)?.is_none() {
                return Err(args::invalid(
                    "native-owned regular journal files without links",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn check(arguments: &[OsString]) -> Result<i32> {
    if arguments.len() != 3 {
        return Err(args::invalid(
            "__install-recovery-check <selected data home>",
        ));
    }
    let home = args::path(&arguments[2])?;
    if home != crate::bootstrap::state_home(None)? {
        return Err(args::invalid("the selected platform data home"));
    }
    NativeInstallationClaim::inherited_created_directories().map_err(native)?;
    NativeStateFiles::open(&home).map_err(native)?;
    let stage = home.join("standalone-install.partial");
    plain_tree(&stage)?;
    let user = args::path(&std::env::var_os("HOME").ok_or_else(|| args::invalid("HOME"))?)?;
    let executable = std::env::current_exe()
        .map_err(|error| se_core::scope::unreadable("archive image", &error.to_string()))?;
    let archive = executable
        .parent()
        .ok_or_else(|| args::invalid("archive directory"))?;
    let assets = user.join(".local/share/stateengine/installation");
    let mut expected = BTreeMap::new();
    expected.insert(user.join(".local/bin/se"), hash(&archive.join("se"))?);
    for name in [
        "manifest.json",
        "build.json",
        "NOTICE.txt",
        "notices.tar",
        "uninstall.sh",
    ] {
        expected.insert(assets.join(name), hash(&archive.join(name))?);
    }
    let manifest = read(&stage.join("manifest.sha256"), 128)?;
    let plan = read(&stage.join("install.json"), 1024 * 1024)?;
    if manifest.is_none() || plan.is_none() {
        // No payload can be published until the complete write-ahead journal is
        // durable. A killed journal writer may be restarted only while every
        // product destination and the completed record are still absent.
        for path in expected
            .keys()
            .chain(std::iter::once(&home.join("standalone-install.json")))
        {
            match std::fs::symlink_metadata(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => (),
                Err(error) => {
                    return Err(se_core::scope::unreadable(
                        "partial destination",
                        &error.to_string(),
                    ));
                }
                Ok(_) => {
                    return Err(args::invalid(
                        "a complete journal before any published payload",
                    ));
                }
            }
        }
        println!("fresh\n\n");
        return Ok(0);
    }
    let manifest = manifest.ok_or_else(|| args::invalid("original archive digest"))?;
    if std::str::from_utf8(&manifest).ok().map(str::trim)
        != Some(hash(&archive.join("manifest.json"))?.hex().as_str())
    {
        return Err(args::invalid(
            "the same archive that started this partial install",
        ));
    }
    let record: InstallRecord =
        serde_json::from_slice(&plan.ok_or_else(|| args::invalid("original install plan"))?)
            .map_err(|error| args::invalid("a complete original install plan").with_cause(error))?;
    if record.schema != "stateengine-install/v1"
        || record.owner != crate::route::owner::observe(&[])?.os_owner()
    {
        return Err(args::invalid("the original native-owned installation plan"));
    }
    let mut fish = String::new();
    let config =
        std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| user.join(".config"), Into::into);
    let fish_path = config.join("fish/conf.d/stateengine.fish");
    if record.files.iter().any(|file| file.path == fish_path) {
        expected.insert(fish_path.clone(), hash(&stage.join("fish-config"))?);
        fish = fish_path
            .to_str()
            .ok_or_else(|| args::invalid("lossless fish path"))?
            .to_owned();
    }
    if record.files.len() != expected.len()
        || record
            .files
            .iter()
            .any(|file| expected.get(&file.path) != Some(&file.sha256))
    {
        return Err(args::invalid(
            "exact original archive files and selected installation paths",
        ));
    }
    let block = required(&stage.join("path-block"), 8192)?;
    let mut profiles = Vec::<String>::new();
    for edit in &record.path_edits {
        let name = Path::new(&edit.target)
            .strip_prefix(&user)
            .ok()
            .and_then(|path| path.to_str())
            .filter(|name| {
                matches!(
                    *name,
                    ".profile" | ".bash_profile" | ".bash_login" | ".zprofile"
                )
            })
            .ok_or_else(|| args::invalid("the original login profile paths"))?;
        if profiles.iter().any(|prior| prior == name) || edit.block.as_bytes() != block {
            return Err(args::invalid(
                "unique original login profiles and PATH block",
            ));
        }
        let digest = required(&stage.join(format!("{name}.digest")), 128)?;
        let expected_digest = edit
            .before_sha256
            .as_ref()
            .map_or_else(|| "absent".into(), Sha256::hex);
        let bytes = required(&stage.join(format!("{name}.bytes")), 64)?;
        if std::str::from_utf8(&digest).ok().map(str::trim) != Some(expected_digest.as_str())
            || std::str::from_utf8(&bytes)
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
                != edit.before_bytes
        {
            return Err(args::invalid(
                "the original profile prefix digest and length",
            ));
        }
        profiles.push(name.to_owned());
    }
    Installation {
        record_path: home.join("standalone-install.json"),
        record,
    }
    .plan()?;
    println!("resume\n{}\n{fish}", profiles.join(" "));
    Ok(0)
}
