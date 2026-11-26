//! Resume only a protected journal bound to the original archive and paths.
use super::{args, native};
use crate::runtime::{InstallRecord, Installation};
use se_proc::{NativeInstallationClaim, NativeStateFiles, OwnedFile};
use se_types::{Result, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    io,
    path::{Path, PathBuf},
};

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

fn remote_image_inventory(
    sums: &[u8],
    user: &Path,
    archive: &Path,
    expected: &mut BTreeMap<PathBuf, Sha256>,
) -> Result<()> {
    // The journal's exact-file comparison remains the binding check; this only
    // extends the expected set so a full-archive install can resume.
    let text = std::str::from_utf8(sums)
        .map_err(|_| args::invalid("the original archive checksum inventory"))?;
    for line in text.lines() {
        let (_, name) = line
            .split_once("  ")
            .filter(|(digest, name)| {
                digest.len() == 64
                    && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                    && !name.is_empty()
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_./+-".contains(&byte))
            })
            .ok_or_else(|| args::invalid("the original archive checksum inventory"))?;
        if name.starts_with("remote-images/")
            && name
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
        {
            expected.insert(
                user.join(".local/bin").join(name),
                hash(&archive.join(name))?,
            );
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
    let sums = read(&archive.join("SHA256SUMS"), 1024 * 1024)
        .map_err(|_| args::invalid("the original archive checksum inventory"))?
        .ok_or_else(|| args::invalid("the original archive checksum inventory"))?;
    remote_image_inventory(&sums, &user, archive, &mut expected)?;
    let manifest = read(&stage.join("manifest.sha256"), 128)?;
    let plan = read(&stage.join("install.json"), 1024 * 1024)?;
    if manifest.is_none() || plan.is_none() {
        fresh_destination_guard(&expected, &home)?;
        return Ok(0);
    }
    resume_plan(&user, archive, &stage, &home, expected, manifest, plan)
}

fn fresh_destination_guard(expected: &BTreeMap<PathBuf, Sha256>, home: &Path) -> Result<()> {
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
    println!("fresh 0\n\n");
    Ok(())
}

fn resume_plan(
    user: &Path,
    archive: &Path,
    stage: &Path,
    home: &Path,
    mut expected: BTreeMap<PathBuf, Sha256>,
    manifest: Option<Vec<u8>>,
    plan: Option<Vec<u8>>,
) -> Result<i32> {
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
    let fish = resume_fish_file(user, stage, &record, &mut expected)?;
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
    // The saved plan is the only eligibility source: recovery resumes the
    // exact full target paths from the verified journal, never names
    // recomputed from this run's flags or environment.
    let mut profiles = Vec::<String>::new();
    let mut bases = Vec::<String>::new();
    for edit in &record.path_edits {
        let base = profile_base(&edit.target)?;
        if bases.iter().any(|prior| prior == base) || edit.block.as_bytes() != block {
            return Err(args::invalid(
                "unique original login profiles and PATH block",
            ));
        }
        let digest = required(&stage.join(format!("{base}.digest")), 128)?;
        let expected_digest = edit
            .before_sha256
            .as_ref()
            .map_or_else(|| "absent".into(), Sha256::hex);
        let bytes = required(&stage.join(format!("{base}.bytes")), 64)?;
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
        bases.push(base.to_owned());
        profiles.push(edit.target.clone());
    }
    // Inherited custody from a replaced image: validated against the profile
    // allowlist and uniqueness only. It carries no sidecars or block to
    // replay, and nothing here becomes a pending write.
    let mut inherited_bases = Vec::<String>::new();
    for edit in &record.inherited_path_edits {
        let base = profile_base(&edit.target)?;
        if bases
            .iter()
            .chain(inherited_bases.iter())
            .any(|prior| prior == base)
        {
            return Err(args::invalid(
                "unique original login profiles and PATH block",
            ));
        }
        inherited_bases.push(base.to_owned());
    }
    Installation {
        record_path: home.join("standalone-install.json"),
        record,
    }
    .plan()?;
    if profiles.is_empty() {
        println!("resume 0\n{fish}");
    } else {
        println!("resume {}\n{}\n{fish}", profiles.len(), profiles.join("\n"));
    }
    Ok(0)
}

fn resume_fish_file(
    user: &Path,
    stage: &Path,
    record: &InstallRecord,
    expected: &mut BTreeMap<PathBuf, Sha256>,
) -> Result<String> {
    let Some(fish_entry) = record
        .files
        .iter()
        .find(|file| se_core::ops::installation::is_fish_path_file(&file.path.to_string_lossy()))
    else {
        return Ok(String::new());
    };
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map_or_else(|| user.join(".config"), Into::into);
    let fish_path = config.join("fish/conf.d/stateengine.fish");
    if OwnedFile::open(&stage.join("fish-config"))
        .map_err(native)?
        .is_some()
    {
        if fish_entry.path != fish_path {
            return Err(args::invalid(
                "exact original archive files and selected installation paths",
            ));
        }
        expected.insert(fish_path.clone(), hash(&stage.join("fish-config"))?);
        return fish_path
            .to_str()
            .ok_or_else(|| args::invalid("lossless fish path"))
            .map(str::to_owned);
    }
    // Inherited Fish PATH file from a `--no-modify-path` replacement:
    // verify the preserved file on disk without scheduling a rewrite.
    if hash(&fish_entry.path)? != fish_entry.sha256 {
        return Err(args::invalid("unchanged preserved Fish PATH file"));
    }
    expected.insert(fish_entry.path.clone(), fish_entry.sha256);
    Ok(String::new())
}

fn profile_base(target: &str) -> Result<&str> {
    let base = Path::new(target)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| args::invalid("the original profile paths"))?;
    if !matches!(
        base,
        ".profile" | ".bash_profile" | ".bash_login" | ".zprofile" | ".bashrc" | ".zshrc"
    ) {
        return Err(args::invalid("the original profile paths"));
    }
    Ok(base)
}
