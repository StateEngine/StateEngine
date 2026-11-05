//! Bundled provider-native adapter assets. Installation is private to this data
//! home, while credentials remain in the existing protected per-launch files.
use super::*;
#[cfg(feature = "listener")]
use se_proc::NativeStateFiles;
#[cfg(feature = "listener")]
use std::io::Read as _;
#[cfg(feature = "listener")]
use std::io::Write;

pub(crate) fn root(home: &Path) -> PathBuf {
    home.join("claude-mail")
}
#[cfg(feature = "listener")]
pub(crate) fn unavailable(directory: &Path, reason: &str) -> Result<OwnedLaunchFile> {
    file(
        &directory.join("claude-mail-unavailable.json"),
        &json!({"reason":reason}),
    )
}
fn failure(error: impl std::fmt::Display) -> SeError {
    se_core::scope::unreadable("attended Claude mail plugin", &error.to_string())
}
#[cfg(feature = "listener")]
fn directory(path: &Path) -> Result<NativeStateFiles> {
    NativeStateFiles::create(path).map_err(failure)
}
#[cfg(feature = "listener")]
fn publish(
    parent: &NativeStateFiles,
    name: &str,
    bytes: &[u8],
    immutable: bool,
) -> Result<PathBuf> {
    let path = parent.root().join(name);
    if let Some(file) = parent.readback(&path).map_err(failure)? {
        if immutable {
            let mut actual = Vec::new();
            file.take((bytes.len() + 1) as u64)
                .read_to_end(&mut actual)
                .map_err(failure)?;
            if actual != bytes {
                return Err(failure(
                    "installed bundled asset differs; preserve it and repair the plugin",
                ));
            }
        }
        return Ok(path);
    }
    let mut staged = parent.create_staging(parent.root()).map_err(failure)?;
    staged
        .file
        .write_all(bytes)
        .and_then(|()| staged.file.sync_all())
        .map_err(failure)?;
    drop(staged.file);
    match parent.publish_no_replace(&staged.path, &path) {
        Ok(()) => Ok(path),
        Err(error) => Err(failure(error)),
    }
}
#[cfg(feature = "listener")]
pub(crate) fn install(home: &Path) -> Result<PathBuf> {
    let root = root(home);
    directory(&root)?;
    use sha2::{Digest, Sha256};
    let version = se_types::hex_lower(&Sha256::digest(include_bytes!("bell.js")));
    let plugin = root.join(format!("v1-{}", &version[..16]));
    directory(&plugin)?;
    let manifest = directory(&plugin.join(".claude-plugin"))?;
    let hooks = directory(&plugin.join("hooks"))?;
    publish(&manifest, "plugin.json", br#"{"name":"stateengine-mail","version":"1.0.0","description":"Authenticated StateEngine mail notifications for this attended session"}"#, true)?;
    publish(
        &hooks,
        "hooks.json",
        br#"{"modules":["./register.js"]}"#,
        true,
    )?;
    publish(&hooks, "register.js", include_bytes!("bell.js"), true)?;
    directory(&root.join("data"))?;
    Ok(plugin)
}
#[cfg(feature = "listener")]
pub(crate) fn configuration(
    launch: &ClaudeLaunch<'_>,
    bells: &crate::http::mail::bell::Bells,
) -> Result<(PathBuf, OwnedLaunchFile)> {
    let plugin = install(launch.state_home)?;
    let data = directory(&root(launch.state_home).join("data"))?;
    let request = launch.request;
    let agent = &request.identity.agent;
    let project = &request.identity.project;
    let hold = publish(
        &data,
        &format!("{project}-{agent}-hold.json"),
        b"{\"held\":false}",
        false,
    )?;
    let status = publish(
        &data,
        &format!("{project}-{agent}-status.json"),
        b"{}",
        false,
    )?;
    let origin = format!("http://127.0.0.1:{}", launch.mcp_port);
    let key = bells.register(
        request.identity.session.clone(),
        agent.clone(),
        &request.mcp_bearer,
        origin.clone(),
        hold.clone(),
    )?;
    let config = json!({"session":request.identity.session,"project":request.identity.project,"agent":agent,
        "conversation":launch.conversation,"origin":origin,"key":key,"hold_file":hold,"status_file":status});
    Ok((
        plugin,
        file(&launch.launch_directory.join("claude-mail.json"), &config)?,
    ))
}

/// Absent/unreadable/starting/armed are different observations. This augments
/// the existing pending fact, never changes mail visibility or read markers.
pub fn pending_status(home: &Path, output: &mut se_core::ops::StatusOutput) {
    let Read::Present { value: project } = &output.project else {
        return;
    };
    let Some(agents) = &output.agents else {
        return;
    };
    for agent in agents
        .items()
        .iter()
        .filter(|a| a.provider == se_types::Provider::Claude && a.session.state == "running")
    {
        let path = root(home)
            .join("data")
            .join(format!("{}-{}-status.json", project.id, agent.id));
        let state = (|| -> Result<String> {
            let file = se_proc::OwnedFile::open(&path)
                .map_err(failure)?
                .ok_or_else(|| failure("plugin has not confirmed readiness"))?;
            let mut reader = file;
            let bytes = reader.read(4096).map_err(failure)?;
            let value: Value = serde_json::from_slice(&bytes)
                .map_err(|_| failure("plugin status is unreadable"))?;
            let session = agent.session.session_id.as_ref().map(|s| s.as_str());
            if value.get("session").and_then(Value::as_str) != session {
                return Err(failure("plugin status belongs to another launch"));
            }
            let updated = value
                .get("updated_ms")
                .and_then(Value::as_u64)
                .ok_or_else(|| failure("plugin status has no observation time"))?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(failure)?
                .as_millis();
            if now.abs_diff(u128::from(updated)) > 60_000 {
                return Err(failure("plugin readiness has expired"));
            }
            value
                .get("state")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| failure("plugin readiness is unavailable"))
        })();
        let description = match state {
            Ok(value) => format!("Attended Claude mail plugin: {value}."),
            Err(error) => {
                let unreadable = error.to_string().chars().take(1024).collect::<String>();
                let reason = (|| -> Option<String> {
                    let session = agent
                        .session
                        .session_id
                        .as_ref()?
                        .as_str()
                        .strip_prefix("ses_")?;
                    let path = home
                        .join("launch")
                        .join(format!("lch_{session}"))
                        .join("claude-mail-unavailable.json");
                    let mut file = se_proc::OwnedFile::open(&path).ok()??;
                    let value: Value = serde_json::from_slice(&file.read(4096).ok()?).ok()?;
                    let reason = value.get("reason")?.as_str()?;
                    (reason.len() <= 1024).then(|| reason.to_owned())
                })();
                format!(
                    "Attended Claude mail plugin unavailable: {}",
                    reason.as_deref().unwrap_or(&unreadable)
                )
            }
        };
        for pending in &mut output.pending {
            if pending.what == "unread agent mail" && pending.detail.contains(agent.id.as_str()) {
                pending.detail = pending.detail.replace(
                    "Automatic inbox wakeups are unavailable in attended Claude.",
                    &description,
                );
            }
        }
        if !description.contains("armed;") {
            output.pending.push(se_core::ops::PendingFact { what:"attended mail wake".into(), since:None,
                detail:format!("{} ({}): {description} Ask this agent to read its StateEngine inbox; a running window does not prove automatic delivery.",agent.name,agent.id) });
        }
    }
}
