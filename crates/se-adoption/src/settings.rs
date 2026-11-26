//! Merge and remove only exact journaled hook entries, preserving user edits.
use super::*;
use serde_json::{Value, json};
use std::path::PathBuf;
mod repair;
mod text;
mod toml;
pub use repair::trust_repair;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layout {
    pub created_file: bool,
    pub created_hooks: bool,
    pub created_events: Vec<String>,
    #[serde(default)]
    pub trust: Vec<(String, String)>,
    #[serde(default)]
    pub created_state: bool,
}
/// Exact entries already present before installation remain user-owned.
pub fn missing(path: &Path, entries: &[(String, Value)]) -> Result<Vec<(String, Value)>> {
    let (_, _, document) = read_document(path)?;
    let mut result = Vec::new();
    let hooks = document.get("hooks");
    if hooks.is_some_and(|value| !value.is_object()) {
        return Err(invalid(
            "an object-valued hooks setting; existing settings were preserved",
        ));
    }
    for (event, entry) in entries {
        match hooks.and_then(|hooks| hooks.get(event)) {
            None => result.push((event.clone(), entry.clone())),
            Some(value) => {
                let list = value.as_array().ok_or_else(|| {
                    invalid("array-valued provider hook events; existing settings were preserved")
                })?;
                if !list.contains(entry) {
                    result.push((event.clone(), entry.clone()));
                }
            }
        }
    }
    Ok(result)
}
pub(crate) const EVENTS: [(&str, &str, bool); 7] = [
    ("SessionStart", "start", false),
    ("UserPromptSubmit", "prompt", false),
    ("PostToolUse", "capture", true),
    ("Stop", "stop", false),
    ("SessionEnd", "end", false),
    ("SessionStart", "mail", true),
    ("Stop", "mail", true),
];
pub fn hooks(executable: &Path, home: &Path, atlas: bool) -> Result<Vec<(String, Value)>> {
    let image = executable
        .to_str()
        .ok_or_else(|| invalid("UTF-8 executable path"))?;
    let home = home.to_str().ok_or_else(|| invalid("UTF-8 home path"))?;
    let mut result = Vec::new();
    for (event, action, background) in EVENTS {
        // Exec form bypasses both Bash and PowerShell tokenization. Provider
        // policy owns failure handling, including a missing or broken image.
        let mut hook = json!({"type":"command", "command":image,
            "args":["__se-claude-adopt",home,action], "onFailure":"continue",
            "timeout":if action == "mail" { 2_000_000 } else if action == "end" { 2 } else { 30 }});
        if action == "mail" {
            hook["asyncRewake"] = json!(true);
        } else if background || action != "end" {
            hook["async"] = json!(true);
        }
        result.push((event.into(), json!({"hooks":[hook]})));
    }
    // Indexed context before a search or file read. It runs in the foreground
    // so the provider can add its output, finishes within its own deadline and
    // prints nothing when Atlas is unready or has no confident answer.
    if atlas {
        result.push((
        "PreToolUse".into(),
        json!({"matcher":ATLAS_MATCHER, "hooks":[{"type":"command", "command":image,
            "args":["--stateengine-private-atlas-hook",home,"claude"], "onFailure":"continue", "timeout":1}]}),
        ));
    }
    Ok(result)
}
/// The tools whose input can name a symbol search or one file to read.
pub(crate) const ATLAS_MATCHER: &str =
    "^(Grep|Read|Bash|exec_command|read_file|mcp__filesystem__read_file)$";
pub(super) fn read_document(path: &Path) -> Result<(Option<se_proc::OwnedFile>, Vec<u8>, Value)> {
    let Some(mut file) = se_proc::OwnedFile::open(path).map_err(access_error)? else {
        return Ok((None, vec![], json!({})));
    };
    let bytes = file.read(LIMIT).map_err(native)?;
    let value: Value = if is_toml(path) {
        toml::read(path, &bytes)?
    } else {
        se_mcp::wire::decode_json(&bytes, LIMIT)?
    };
    if !value.is_object() {
        return Err(invalid(
            "a provider settings object; existing bytes were preserved",
        ));
    }
    Ok((Some(file), bytes, value))
}
fn write_document(
    path: &Path,
    pin: Option<se_proc::OwnedFile>,
    before: &[u8],
    document: &Value,
    edits: &[text::Edit],
) -> Result<()> {
    let bytes = render(path, before, document, edits)?;
    store(path, pin, before, &bytes)
}
fn render(path: &Path, before: &[u8], document: &Value, edits: &[text::Edit]) -> Result<Vec<u8>> {
    let bytes = if is_toml(path) {
        toml::apply(path, before, document, edits)?
    } else {
        text::apply(before, document, edits)?
    };
    if bytes.len() > LIMIT {
        return Err(invalid("provider settings within one MiB"));
    }
    Ok(bytes)
}
/// Replace exactly `before` (or create the absent file) with `bytes`, then read
/// the exact bytes back.
fn store(path: &Path, pin: Option<se_proc::OwnedFile>, before: &[u8], bytes: &[u8]) -> Result<()> {
    if let Some(pin) = pin {
        writable(path, &pin)?;
        pin.replace(digest(before), bytes).map_err(native)?;
    } else {
        se_proc::OwnedFile::create_new(path, bytes).map_err(access_error)?;
    }
    let (_, actual, _) = read_document(path)?;
    if actual != bytes {
        return Err(invalid("exact provider settings readback"));
    }
    Ok(())
}
/// Appending entries, observed and rendered but not yet written. Its entries
/// and layout come from the same observed document whose exact bytes
/// [`commit`] replaces, so the journal claims only what this write adds.
pub struct Planned {
    pin: Option<se_proc::OwnedFile>,
    before: Vec<u8>,
    after: Option<Vec<u8>>,
    /// The entries this plan appends, exactly as observed missing.
    pub entries: Vec<(String, Value)>,
    /// What this plan creates in the observed file.
    pub layout: Layout,
}
/// Plan appending those of `entries` not already present. A changed owned
/// entry is preserved and is not silently reinstalled: the owner may have
/// deliberately disabled it.
pub fn plan(path: &Path, entries: &[(String, Value)]) -> Result<Planned> {
    let (pin, before, mut document) = read_document(path)?;
    let mut layout = Layout {
        created_file: pin.is_none(),
        created_hooks: document.get("hooks").is_none(),
        created_events: vec![],
        trust: vec![],
        created_state: document.get("hooks").and_then(|h| h.get("state")).is_none(),
    };
    let object = document
        .as_object_mut()
        .ok_or_else(|| invalid("settings object"))?;
    let hooks = object
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| {
            invalid("an object-valued hooks setting; existing settings were preserved")
        })?;
    let (mut edits, mut appended) = (Vec::new(), Vec::new());
    for (event, entry) in entries {
        if !hooks.contains_key(event) && !layout.created_events.contains(event) {
            layout.created_events.push(event.clone());
        }
        let list = hooks
            .entry(event)
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or_else(|| {
                invalid("array-valued provider hook events; existing settings were preserved")
            })?;
        if !list.contains(entry) {
            list.push(entry.clone());
            edits.push(text::Edit::Append(event.clone(), entry.clone()));
            appended.push((event.clone(), entry.clone()));
        }
    }
    let after = if edits.is_empty() {
        None
    } else {
        Some(render(path, &before, &document, &edits)?)
    };
    Ok(Planned {
        pin,
        before,
        after,
        entries: appended,
        layout,
    })
}
/// Write a plan; `false` when it appends nothing.
pub fn commit(path: &Path, planned: Planned) -> Result<bool> {
    let Some(after) = planned.after else {
        return Ok(false);
    };
    store(path, planned.pin, &planned.before, &after)?;
    Ok(true)
}
/// Separate witnessed outcomes for one provider's settings edit and registration revocation.
#[cfg_attr(not(feature = "listener"), allow(dead_code))]
pub(crate) struct UninstallSteps {
    pub settings_edited: Option<PathBuf>,
    pub registration_revoked: Option<PathBuf>,
}
/// Failure during one provider's uninstall, preserving any achieved settings
/// edit and naming the exact path where the refusal occurred.
#[cfg_attr(not(feature = "listener"), allow(dead_code))]
pub(crate) struct UninstallFailure {
    pub settings_edited: Option<PathBuf>,
    pub failed_path: PathBuf,
    pub error: SeError,
}
pub fn uninstall(home: &Path) -> Result<Vec<PathBuf>> {
    uninstall_for(home, Kind::Claude)
}
pub fn uninstall_for(home: &Path, kind: Kind) -> Result<Vec<PathBuf>> {
    match uninstall_steps(home, kind) {
        Ok(steps) => Ok(steps.settings_edited.into_iter().collect()),
        Err(failure) => Err(failure.error),
    }
}
fn remove_registered_entries(
    document: &mut Value,
    registration: &super::Registration,
) -> (bool, Vec<text::Edit>) {
    let mut changed = false;
    let mut edits = Vec::new();
    if let Some(hooks) = document.get_mut("hooks").and_then(Value::as_object_mut) {
        for (event, entry) in &registration.hooks {
            if let Some(list) = hooks.get_mut(event).and_then(Value::as_array_mut) {
                // Remove one occurrence per journal entry. Identical user
                // duplicates remain user-owned rather than being wiped out.
                if let Some(index) = list.iter().position(|value| value == entry) {
                    list.remove(index);
                    edits.push(text::Edit::Remove(event.clone(), index));
                    changed = true;
                }
            }
        }
    }
    if let Some(hooks) = document.get_mut("hooks").and_then(Value::as_object_mut) {
        if let Some(state) = hooks.get_mut("state").and_then(Value::as_object_mut) {
            for (key, hash) in &registration.layout.trust {
                if state.get(key) == Some(&json!({"trusted_hash":hash})) {
                    state.remove(key);
                    edits.push(text::Edit::RemoveTrust(key.clone()));
                    changed = true;
                }
            }
            if state.is_empty() && registration.layout.created_state {
                hooks.remove("state");
                edits.push(text::Edit::RemoveTrustState);
                changed = true;
            }
        }
        for event in &registration.layout.created_events {
            if hooks
                .get(event)
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
            {
                hooks.remove(event);
                edits.push(text::Edit::RemoveEvent(event.clone()));
                changed = true;
            }
        }
        if registration.layout.created_hooks && hooks.is_empty() {
            document.as_object_mut().map(|o| o.remove("hooks"));
            edits.push(text::Edit::RemoveHooks);
            changed = true;
        }
    }
    (changed, edits)
}
pub(crate) fn uninstall_steps(
    home: &Path,
    kind: Kind,
) -> std::result::Result<UninstallSteps, UninstallFailure> {
    let journal = home.join(kind.journal());
    let Some(registration) = super::read_for(home, kind).map_err(|error| UninstallFailure {
        settings_edited: None,
        failed_path: journal.clone(),
        error,
    })?
    else {
        return Ok(UninstallSteps {
            settings_edited: None,
            registration_revoked: None,
        });
    };
    let path = registration
        .settings
        .to_local()
        .map_err(|error| UninstallFailure {
            settings_edited: None,
            failed_path: journal.clone(),
            error,
        })?;
    let (pin, before, mut document) = read_document(&path).map_err(|error| UninstallFailure {
        settings_edited: None,
        failed_path: path.clone(),
        error,
    })?;
    let (changed, edits) = remove_registered_entries(&mut document, &registration);
    let mut settings_edited = None;
    if changed {
        let write_result = (|| -> Result<()> {
            if let Some(pin) = &pin {
                writable(&path, pin)?;
            }
            if registration.layout.created_file
                && document.as_object().is_some_and(serde_json::Map::is_empty)
            {
                if let Some(pin) = pin {
                    pin.remove(digest(&before)).map_err(native)?;
                }
            } else {
                write_document(&path, pin, &before, &document, &edits)?;
            }
            Ok(())
        })();
        if let Err(error) = write_result {
            return Err(UninstallFailure {
                settings_edited: None,
                failed_path: path,
                error,
            });
        }
        settings_edited = Some(path);
    }
    // Revocation is independent of edited hooks: an edited command can remain
    // in the provider, but without this registration it is an inert success.
    if let Err(error) = super::remove_for(home, kind) {
        return Err(UninstallFailure {
            settings_edited,
            failed_path: journal,
            error,
        });
    }
    Ok(UninstallSteps {
        settings_edited,
        registration_revoked: Some(journal),
    })
}

fn is_toml(path: &Path) -> bool {
    path.extension().is_some_and(|e| e == "toml")
}
/// Trust only exact newly installed entries that the provider discovered.
pub fn trust(path: &Path, entries: &[(String, String)]) -> Result<()> {
    let (pin, before, mut document) = read_document(path)?;
    let mut edits = Vec::new();
    let hooks = document
        .as_object_mut()
        .ok_or_else(|| invalid("settings object"))?
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| invalid("hooks table"))?;
    let state = hooks
        .entry("state")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| invalid("hook state table"))?;
    for (key, hash) in entries {
        let expected = json!({"trusted_hash":hash});
        match state.get(key) {
            Some(value) if value == &expected => (),
            Some(_) => {
                return Err(invalid(
                    "unchanged owner hook trust decisions; edited state was preserved",
                ));
            }
            None => {
                state.insert(key.clone(), expected);
                edits.push(text::Edit::Trust(key.clone(), hash.clone()));
            }
        }
    }
    if !edits.is_empty() {
        write_document(path, pin, &before, &document, &edits)?;
    }
    Ok(())
}

pub fn missing_trust(path: &Path, entries: &[(String, String)]) -> Result<Vec<(String, String)>> {
    let (_, _, document) = read_document(path)?;
    let mut missing = Vec::new();
    let state = document.get("hooks").and_then(|h| h.get("state"));
    for (key, hash) in entries {
        match state.and_then(|s| s.get(key)) {
            None => missing.push((key.clone(), hash.clone())),
            Some(value) if value == &json!({"trusted_hash":hash}) => (),
            Some(_) => {
                return Err(invalid(
                    "unchanged owner hook trust decisions; edited state was preserved",
                ));
            }
        }
    }
    Ok(missing)
}

fn refusal(path: &Path, reason: String, next_step: String) -> SeError {
    SeError::new(se_types::Detail::SourceUnreadable(
        se_types::details::SourceUnreadable {
            subject: path.display().to_string(),
            reason,
            next_step,
        },
    ))
}
fn access_error(error: se_proc::StateFileError) -> SeError {
    let path = &error.path;
    let next = if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        "Set CODEX_HOME (Codex) or CLAUDE_CONFIG_DIR (Claude Code) to the directory containing the real configuration file, or replace the symbolic link with a regular file; then retry the original command.".into()
    } else if error.operation == "require owner-only native regular file/directory"
        || (error.code == se_proc::StateFileErrorCode::LocationUnsafe
            && error.operation.contains("DACL"))
    {
        #[cfg(unix)]
        {
            format!(
                "Make this directory private with chmod 700 -- {}; then retry the original command.",
                quoted(path)
            )
        }
        #[cfg(windows)]
        {
            "In this path's Advanced Security properties, disable inheritance, remove other accounts' access, and grant full control to your account and SYSTEM; then retry the original command.".into()
        }
    } else {
        "Restore access to this exact provider settings path, keeping regular files and directories in place of links; then retry the original command.".into()
    };
    refusal(path, error.to_string(), next).with_cause(error)
}
fn writable(path: &Path, file: &se_proc::OwnedFile) -> Result<()> {
    let permissions = file.permissions().map_err(access_error)?;
    #[cfg(unix)]
    let readonly = {
        use std::os::unix::fs::PermissionsExt;
        permissions.mode() & 0o200 == 0
    };
    #[cfg(windows)]
    let readonly = permissions.readonly();
    if readonly {
        #[cfg(unix)]
        let next = format!(
            "Allow owner writes with chmod u+w -- {}; then retry the original command.",
            quoted(path)
        );
        #[cfg(windows)]
        let next = format!(
            "Clear the read-only attribute of {} in its Properties, then retry the original command.",
            path.display()
        );
        return Err(refusal(
            path,
            "Provider configuration is read-only; its bytes were preserved.".into(),
            next,
        ));
    }
    Ok(())
}
#[cfg(unix)]
fn quoted(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}
#[cfg(all(feature = "listener", any(target_os = "linux", windows)))]
pub(crate) fn prepare(home: &Path, path: &Path) -> Result<()> {
    // Check before even --version: the provider can create temporary directories.
    if let (Some(file), _, _) = read_document(path)? {
        writable(path, &file)?;
    } else {
        se_proc::OwnedFile::ensure_parent_directory(home).map_err(access_error)?;
    }
    Ok(())
}
