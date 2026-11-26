//! The explicit adopt command trusts only its own exact discovered definitions.
//! Hashes and discovery keys come from the selected provider, never an imitation.
use super::*;

fn listed(registration: &Registration, root: &Path) -> Result<(Vec<Value>, [u8; 32])> {
    let before = crate::discovery_stamp(registration)?;
    let result = super::rpc::call(
        registration.provider.to_local()?,
        registration.config_home.to_local()?,
        root.to_owned(),
        "hooks/list",
        json!({"cwds":[root]}),
    )?;
    let data = result
        .get("data")
        .and_then(Value::as_array)
        .filter(|a| a.len() == 1)
        .and_then(|a| a.first())
        .ok_or_else(|| invalid("provider hook discovery for this project"))?;
    if !data
        .get("errors")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        return Err(invalid(
            "error-free provider hook discovery; capture and mail remain unconfirmed",
        ));
    }
    let rows = data
        .get("hooks")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| invalid("discovered provider hooks"))?;
    if before != crate::discovery_stamp(registration)? {
        return Err(invalid(
            "unchanged configuration and provider during hook discovery; repeat adoption setup",
        ));
    }
    Ok((rows, before))
}
/// The discovery key and hash of each of `entries` Codex lists. A required
/// lifecycle hook must be listed and enabled; an optional one, such as the
/// Atlas hook, is skipped when the owner has removed it.
fn select(
    registration: &Registration,
    rows: &[Value],
    entries: &[(String, Value)],
    required: &[(String, Value)],
) -> Result<Vec<(String, String)>> {
    let path = registration.settings.to_local()?;
    let mut selected = Vec::new();
    for entry @ (event, group) in entries {
        let event = format!("{}{}", event[..1].to_ascii_lowercase(), &event[1..]);
        let handler = group
            .get("hooks")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .ok_or_else(|| invalid("the exact installed hook handler"))?;
        let command = if cfg!(windows) {
            handler.get("commandWindows")
        } else {
            handler.get("command")
        };
        let matches = rows
            .iter()
            .filter(|row| {
                row.get("sourcePath")
                    .and_then(Value::as_str)
                    .is_some_and(|p| Path::new(p) == path)
                    && row.get("eventName").and_then(Value::as_str) == Some(event.as_str())
                    && row.get("command") == command
            })
            .collect::<Vec<_>>();
        if matches.is_empty() && !required.contains(entry) {
            continue;
        }
        if matches.len() != 1 || matches[0].get("enabled").and_then(Value::as_bool) != Some(true) {
            return Err(invalid(
                "Codex did not discover and enable the exact StateEngine hooks; capture and mail are unconfirmed",
            ));
        }
        let field = |key| {
            matches[0]
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| invalid("provider hook discovery key and hash"))
        };
        selected.push((field("key")?, field("currentHash")?));
    }
    Ok(selected)
}
/// Whether Codex reports this exact hook hash as trusted.
fn trusted(rows: &[Value], (key, hash): &(String, String)) -> bool {
    rows.iter().any(|r| {
        r.get("key").and_then(Value::as_str) == Some(key)
            && r.get("currentHash").and_then(Value::as_str) == Some(hash)
            && r.get("trustStatus").and_then(Value::as_str) == Some("trusted")
    })
}
/// Discovery already confirmed this configuration for this project.
fn current(registration: &Registration, root: &Path) -> Result<bool> {
    Ok(
        registration.discovery == Some(crate::discovery_stamp(registration)?)
            && registration
                .project(root)?
                .is_some_and(|p| p.discovery == registration.discovery),
    )
}
fn record(
    home: &Path,
    registration: &mut Registration,
    root: &Path,
    stamp: [u8; 32],
) -> Result<()> {
    registration.discovery = Some(stamp);
    let root = NativePath::from_local(root.to_owned())?;
    if let Some(project) = registration.projects.iter_mut().find(|p| p.root == root) {
        project.discovery = Some(stamp);
    }
    crate::publish_for(home, Kind::Codex, registration)
}
/// Fresh setup: trust every installed hook Codex lists, the optional Atlas hook
/// included, then require the provider to read them back as trusted. Only the
/// run that created the registration calls this.
pub(crate) fn install(
    home: &Path,
    registration: &mut Registration,
    root: &Path,
    required: &[(String, Value)],
) -> Result<()> {
    if current(registration, root)? {
        return Ok(());
    }
    let hooks = registration.hooks.clone();
    let discovered = select(
        registration,
        &listed(registration, root)?.0,
        &hooks,
        required,
    )?;
    let settings = registration.settings.to_local()?;
    let missing = crate::settings::missing_trust(&settings, &discovered)?;
    // Journal before writing trust, so an interrupted installation remains
    // reversible. A pre-existing owner decision is never replaced.
    for entry in &missing {
        if !registration.layout.trust.contains(entry) {
            registration.layout.trust.push(entry.clone());
        }
    }
    crate::publish_for(home, Kind::Codex, registration)?;
    crate::settings::trust(&settings, &missing)?;
    let (rows, stamp) = listed(registration, root)?;
    if select(registration, &rows, &hooks, required)? != discovered
        || !discovered.iter().all(|entry| trusted(&rows, entry))
    {
        return Err(invalid(
            "provider readback of trusted installed hooks; capture and mail are unconfirmed",
        ));
    }
    record(home, registration, root, stamp)
}
/// Every other run: read only. Codex must list, enable and trust each required
/// lifecycle hook StateEngine installed; the optional Atlas hook's state never
/// decides this. Trust is never written here, because an absent entry may be
/// one the owner removed.
pub(crate) fn verify(
    home: &Path,
    registration: &mut Registration,
    root: &Path,
    required: &[(String, Value)],
) -> Result<()> {
    if current(registration, root)? {
        return Ok(());
    }
    let lifecycle: Vec<_> = registration
        .hooks
        .iter()
        .filter(|entry| required.contains(entry))
        .cloned()
        .collect();
    let (rows, stamp) = listed(registration, root)?;
    let untrusted: Vec<_> = select(registration, &rows, &lifecycle, required)?
        .into_iter()
        .filter(|entry| !trusted(&rows, entry))
        .collect();
    if !untrusted.is_empty() {
        let settings = registration.settings.to_local()?;
        let mut error = invalid(&format!(
            "Codex trust for these StateEngine hooks in {}; it may have been removed or changed there, so it was not written again",
            settings.display()
        ));
        error.body = error.body.with_remedy(se_types::Remedy {
            text: format!(
                "{}\nThen run this command again.",
                crate::settings::trust_repair(&settings, &untrusted)?
            ),
            command: None,
        });
        return Err(error);
    }
    record(home, registration, root, stamp)
}
