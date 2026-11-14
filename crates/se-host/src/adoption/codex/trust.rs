//! The explicit adopt command trusts only its own exact discovered definitions.
//! Hashes and discovery keys come from the selected provider, never an imitation.
use super::*;

fn listed(registration: &Registration, root: &Path) -> Result<(Vec<Value>, [u8; 32])> {
    let before = super::super::discovery_stamp(registration)?;
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
    if before != super::super::discovery_stamp(registration)? {
        return Err(invalid(
            "unchanged configuration and provider during hook discovery; repeat adoption setup",
        ));
    }
    Ok((rows, before))
}
fn select(registration: &Registration, rows: &[Value]) -> Result<Vec<(String, String)>> {
    let path = registration.settings.to_local()?;
    let mut selected = Vec::new();
    for (event, group) in &registration.hooks {
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
pub fn install(home: &Path, registration: &mut Registration, root: &Path) -> Result<()> {
    if registration.discovery == Some(super::super::discovery_stamp(registration)?)
        && registration
            .project(root)?
            .is_some_and(|p| p.discovery == registration.discovery)
    {
        return Ok(());
    }
    let discovered = select(registration, &listed(registration, root)?.0)?;
    let missing =
        super::super::settings::missing_trust(&registration.settings.to_local()?, &discovered)?;
    // Journal before writing trust, so an interrupted installation remains
    // reversible. A pre-existing owner decision is never replaced.
    for entry in &missing {
        if !registration.layout.trust.contains(entry) {
            registration.layout.trust.push(entry.clone());
        }
    }
    super::super::publish_for(home, Kind::Codex, registration)?;
    super::super::settings::trust(&registration.settings.to_local()?, &discovered)?;
    let (rows, stamp) = listed(registration, root)?;
    if select(registration, &rows)? != discovered
        || discovered.iter().any(|(key, hash)| {
            !rows.iter().any(|r| {
                r.get("key").and_then(Value::as_str) == Some(key)
                    && r.get("currentHash").and_then(Value::as_str) == Some(hash)
                    && r.get("trustStatus").and_then(Value::as_str) == Some("trusted")
            })
        })
    {
        return Err(invalid(
            "provider readback of trusted installed hooks; capture and mail are unconfirmed",
        ));
    }
    registration.discovery = Some(stamp);
    let root = NativePath::from_local(root.to_owned())?;
    if let Some(project) = registration.projects.iter_mut().find(|p| p.root == root) {
        project.discovery = Some(stamp);
    }
    super::super::publish_for(home, Kind::Codex, registration)?;
    Ok(())
}
