//! Exact protected launch files, each published without replacement and read
//! back before the provider can execute. Changed files are never overwritten.
use super::*;
use crate::ConfigPlan;
use se_proc::NativeStateFiles;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u16,
    project: se_types::ProjectId,
    agent: se_types::AgentId,
    session: se_types::SessionId,
    lifecycle: se_types::LifecycleId,
    pin_sha256: se_types::Sha256,
    files: Vec<(NativePath, se_types::Sha256)>,
}
pub(super) fn manifest(
    home: &std::path::Path,
    plan: &se_core::ops::agent_launch::LaunchPlan,
    pin: [u8; 32],
    configuration: &ConfigPlan,
) -> Result<(PathBuf, Vec<u8>)> {
    let directory = directory(home, &plan.session)?;
    let files = configuration
        .ephemeral_files
        .iter()
        .map(|item| {
            let path = item.path.to_local()?;
            if path.parent() != Some(directory.as_path())
                || path
                    .file_name()
                    .is_none_or(|name| name == "custody.json" || name == "pin")
            {
                return Err(error(
                    "launch cleanup manifest",
                    "configuration path is outside the reserved immediate files",
                ));
            }
            Ok((
                item.path.clone(),
                se_types::Sha256::from_bytes(Sha256::digest(item.contents.expose()).into()),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    if files.len() > 16 {
        return Err(error(
            "launch configuration",
            "more than sixteen ephemeral files",
        ));
    }
    let manifest = Manifest {
        version: 1,
        project: plan.project.id.clone(),
        agent: plan.agent.id.clone(),
        session: plan.session.clone(),
        lifecycle: plan.lifecycle.clone(),
        pin_sha256: se_types::Sha256::from_bytes(pin),
        files,
    };
    Ok((
        directory.join("custody.json"),
        serde_json::to_vec(&manifest).map_err(|e| error("launch cleanup manifest", e))?,
    ))
}
pub(super) fn directory(home: &std::path::Path, session: &se_types::SessionId) -> Result<PathBuf> {
    Ok(home.join("launch").join(
        se_proc::session_launch_id(session)
            .map_err(|e| error("launch identity", e))?
            .as_str(),
    ))
}
pub(super) struct RestoredFiles {
    pub pin: [u8; 32],
    pub files: Vec<(PathBuf, [u8; 32])>,
}
pub(super) fn restore(
    home: &std::path::Path,
    meta: &super::owned::LifecycleMetadata,
) -> Result<Option<RestoredFiles>> {
    let directory = directory(home, &meta.session)?;
    let path = directory.join("custody.json");
    let Some(mut owned) =
        se_proc::OwnedFile::open(&path).map_err(|e| error("retained launch manifest", e))?
    else {
        return Ok(None);
    };
    let bytes = owned
        .read(65536)
        .map_err(|e| error("retained launch manifest", e))?;
    let manifest: Manifest =
        serde_json::from_slice(&bytes).map_err(|e| error("retained launch manifest", e))?;
    if manifest.version != 1
        || manifest.session != meta.session
        || manifest.lifecycle != meta.lifecycle
        || manifest.project != meta.project.id
        || manifest.agent != meta.agent.id
        || manifest.files.len() > 16
    {
        return Err(error(
            "retained launch manifest",
            "identity or finite file list differs",
        ));
    }
    let mut files = Vec::new();
    for (native, digest) in manifest.files {
        let item = native.to_local()?;
        if item.parent() != Some(directory.as_path())
            || item
                .file_name()
                .is_none_or(|name| name == "custody.json" || name == "pin")
        {
            return Err(error(
                "retained launch cleanup",
                "manifest names an unrelated path",
            ));
        }
        files.push((item, *digest.as_bytes()));
    }
    files.push((path, Sha256::digest(bytes).into()));
    Ok(Some(RestoredFiles {
        pin: *manifest.pin_sha256.as_bytes(),
        files,
    }))
}
pub(super) fn publish(
    home: &std::path::Path,
    session: &se_types::SessionId,
    pin: &se_types::Secret,
    configuration: ConfigPlan,
    manifest: (PathBuf, Vec<u8>),
) -> Result<Vec<(PathBuf, [u8; 32])>> {
    let state = NativeStateFiles::open(home).map_err(|e| error("launch state home", e))?;
    se_proc::publish_session_pin(&state, session, pin)
        .map_err(|e| error("session pin publication", e))?;
    if !configuration.edits.is_empty() {
        return Err(se_types::SeError::invalid(
            "launch integrations",
            "ephemeral protected files only",
        ));
    }
    let launch = se_proc::session_launch_id(session).map_err(|e| error("launch identity", e))?;
    let directory = home.join("launch").join(launch.as_str());
    let files = NativeStateFiles::open(&directory).map_err(|e| error("launch directory", e))?;
    let mut published = Vec::new();
    // Publish cleanup custody before any configuration or provider creation.
    // A crash later can remove only these exact, independently read-back bytes.
    let mut staging = files
        .create_staging(&directory)
        .map_err(|e| error("launch custody staging", e))?;
    staging
        .file
        .write_all(&manifest.1)
        .and_then(|()| staging.file.sync_all())
        .map_err(|e| error("launch custody durability", e))?;
    drop(staging.file);
    files
        .publish_no_replace(&staging.path, &manifest.0)
        .map_err(|e| error("launch custody publication", e))?;
    let mut owned = se_proc::OwnedFile::open(&manifest.0)
        .map_err(|e| error("launch custody readback", e))?
        .ok_or_else(|| error("launch custody readback", "published manifest absent"))?;
    if owned
        .read(65536)
        .map_err(|e| error("launch custody readback", e))?
        != manifest.1
    {
        return Err(error("launch custody readback", "bytes differ"));
    }
    published.push((manifest.0, Sha256::digest(&manifest.1).into()));
    for item in configuration.ephemeral_files {
        let path = item.path.to_local()?;
        if path.parent() != Some(directory.as_path()) {
            return Err(se_types::SeError::invalid(
                "launch configuration",
                "an immediate file in the exact protected launch directory",
            ));
        }
        let mut staged = files
            .create_staging(&directory)
            .map_err(|e| error("launch configuration staging", e))?;
        staged
            .file
            .write_all(item.contents.expose())
            .and_then(|()| staged.file.sync_all())
            .map_err(|e| error("durable launch configuration", e))?;
        drop(staged.file);
        files
            .publish_no_replace(&staged.path, &path)
            .map_err(|e| error("launch configuration publication", e))?;
        let mut reopened = files
            .readback(&path)
            .map_err(|e| error("launch configuration readback", e))?
            .ok_or_else(|| {
                se_core::scope::unreadable("launch configuration", "published file is absent")
            })?;
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        std::io::Read::by_ref(&mut reopened)
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|e| error("launch configuration readback", e))?;
        if bytes.as_slice() != item.contents.expose() {
            return Err(se_core::scope::unreadable(
                "launch configuration",
                "published bytes differ",
            ));
        }
        published.push((path, Sha256::digest(&bytes).into()));
    }
    Ok(published)
}
