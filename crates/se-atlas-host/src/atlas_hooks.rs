//! Best-effort, index-only context on the provider's critical path. No text
//! search, source body or HitBody API is used; permission decisions are untouched.
use crate::{
    atlas_queries::{readable, request_project},
    atlas_runtime::{read_port::AtlasOwnerPort, record_fence::RecordFeedTicket},
};
use se_atlas::{
    query::{QueryReader, hooks::HookTarget},
    source::RegisteredSource,
};
use se_core::ops::{AtlasAugment, AtlasHookOutput, AtlasHookTarget};
use se_store::{Admission, Scope, Snapshot};
use se_types::{Result, code::*};
use std::time::Instant;

pub fn owner_augment<R: Snapshot>(
    owner: &AtlasOwnerPort,
    _ticket: Option<RecordFeedTicket>,
    input: &AtlasAugment,
    read: &mut R,
    admission: &Admission,
) -> Result<AtlasHookOutput> {
    let Some(end) = input.deadline.filter(|end| *end > se_atlas::clock::now()) else {
        return Ok(AtlasHookOutput::default());
    };
    // An uncertain index/authority/IO/deadline is no augmentation, never a block.
    // Public Atlas operations retain these errors; this private hint is optional.
    let text = augment_v5(owner, input, read, admission).ok().flatten();
    Ok(AtlasHookOutput {
        stdout: text
            .filter(|_| se_atlas::clock::now() < end)
            .unwrap_or_default(),
    })
}

/// Index-only context for the target; never starts a build or reads source.
fn augment_v5<R: Snapshot>(
    owner: &AtlasOwnerPort,
    input: &AtlasAugment,
    read: &mut R,
    admission: &Admission,
) -> Result<Option<String>> {
    let Scope::Project(project) = &admission.scope else {
        return Ok(None);
    };
    let root = input.root.as_ref();
    request_project(owner, read, project, root)?;
    if !readable(&owner.summary(project, root)?) {
        return Ok(None);
    }
    let engine = owner.engine(project, root)?;
    match &input.target {
        AtlasHookTarget::Symbol(name) => symbol(&engine, name.as_str()),
        AtlasHookTarget::File(path) => outline(&engine, &path.to_local()?),
    }
}

fn encode(text: &str) -> Option<String> {
    let output=serde_json::to_string(&serde_json::json!({"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":text}})).ok()?;
    (output.len() <= 600).then_some(output)
}
fn add(text: &mut String, line: String) {
    let next = format!("{text}\n{line}");
    if encode(&next).is_some() {
        *text = next;
    }
}
fn linked(text: &mut String, mentions: usize) {
    if mentions != 0 {
        add(text, format!("linked (sample): {mentions} messages"));
    }
}
fn symbol(engine: &se_atlas_service::Root, name: &str) -> Result<Option<String>> {
    let Some(found) = engine.hook_symbol(name)? else {
        return Ok(None);
    };
    let mut text = format!(
        "Atlas indexed context (sample): definition {} {}:{}",
        found.name, found.path, found.line
    );
    linked(&mut text, found.mentions);
    for caller in found.callers {
        add(&mut text, format!("caller {caller}"));
    }
    Ok(encode(&text))
}
fn outline(engine: &se_atlas_service::Root, path: &std::path::Path) -> Result<Option<String>> {
    let Ok(relative) = path.strip_prefix(&engine.spec().source) else {
        return Ok(None);
    };
    let Some(relative) = relative.to_str() else {
        return Ok(None);
    };
    let relative = relative.replace(std::path::MAIN_SEPARATOR, "/");
    let Some(found) = engine.hook_outline(&relative)? else {
        return Ok(None);
    };
    let mut text = format!("Atlas outline (sample): {}", found.path);
    linked(&mut text, found.mentions);
    for (name, line) in found.symbols {
        add(&mut text, format!("{name}:{line}"));
    }
    Ok(encode(&text))
}

/// The legacy cache reader's hook adapter, kept until that reader is removed.
/// Executes against an already scoped reader; never opens a cache or starts work.
pub fn augment(
    reader: &mut QueryReader<'_, '_, '_>,
    source: &RegisteredSource<crate::atlas_source::NativeAtlasSource>,
    input: &AtlasAugment,
) -> Result<AtlasHookOutput> {
    let Some(end) = input.deadline.filter(|end| *end > se_atlas::clock::now()) else {
        return Ok(AtlasHookOutput::default());
    };
    let text = match &input.target {
        AtlasHookTarget::Symbol(name) => legacy_symbol(reader, name, end)?,
        AtlasHookTarget::File(path) => legacy_outline(reader, source, &path.to_local()?, end)?,
    };
    Ok(AtlasHookOutput {
        stdout: text
            .filter(|_| se_atlas::clock::now() < end)
            .unwrap_or_default(),
    })
}
fn location(pointer: &CodePointer) -> String {
    match &pointer.span {
        Some(span) => format!("{}:{}", pointer.path.as_str(), span.start.line),
        None => pointer.path.as_str().to_owned(),
    }
}
fn legacy_symbol(
    reader: &mut QueryReader<'_, '_, '_>,
    name: &QueryText,
    end: Instant,
) -> Result<Option<String>> {
    let Some(context) = reader.hook_context(HookTarget::Symbol(name.as_str()), end)? else {
        return Ok(None);
    };
    let [symbol] = context.symbols.as_slice() else {
        return Ok(None);
    };
    let mut text = format!(
        "Atlas indexed context (sample): definition {} {}",
        symbol.name,
        location(&context.file)
    );
    linked(&mut text, context.linked.messages as usize);
    for caller in context.callers {
        add(&mut text, format!("caller {}", location(&caller)));
    }
    Ok(encode(&text).filter(|_| se_atlas::clock::now() < end))
}
fn legacy_outline(
    reader: &mut QueryReader<'_, '_, '_>,
    source: &RegisteredSource<crate::atlas_source::NativeAtlasSource>,
    path: &std::path::Path,
    end: Instant,
) -> Result<Option<String>> {
    let root = &source.scope.registration.canonical_source_root;
    let Ok(relative) = path.strip_prefix(root) else {
        return Ok(None);
    };
    let Some(relative) = relative.to_str() else {
        return Ok(None);
    };
    let relative = RelativePath::new(relative.replace(std::path::MAIN_SEPARATOR, "/"))?;
    let Some(file) = source.open(&relative)? else {
        return Ok(None);
    };
    if file.identity()?.size < 32768 || !file.validate_path()? {
        return Ok(None);
    }
    drop(file);
    let Some(outline) = reader.hook_context(HookTarget::File(&relative), end)? else {
        return Ok(None);
    };
    let mut text = format!("Atlas outline (sample): {}", outline.file.path.as_str());
    linked(&mut text, outline.linked.messages as usize);
    for symbol in outline.symbols {
        add(
            &mut text,
            format!("{}:{}", symbol.name, symbol.span.start.line),
        );
    }
    Ok(encode(&text).filter(|_| se_atlas::clock::now() < end))
}

/// Classify only simple search tools and explicit single-file reads. Shell text
/// is never executed here, and ambiguous shell syntax is intentionally ignored.
pub fn classify(payload: &serde_json::Value) -> Option<AtlasHookTarget> {
    if payload.get("hook_event_name")?.as_str()? != "PreToolUse" {
        return None;
    }
    let name = payload.get("tool_name")?.as_str()?;
    let input = payload.get("tool_input")?;
    let symbol = |name: &str| {
        let query = QueryText::new(name).ok()?;
        let request = AtlasAugment {
            target: AtlasHookTarget::Symbol(query),
            root: None,
            deadline: None,
        };
        se_core::ops::inputs::Validate::validate(&request).ok()?;
        Some(request.target)
    };
    let file = |value: &str| {
        let value = std::path::PathBuf::from(value);
        let value = if value.is_absolute() {
            value
        } else {
            let cwd = std::path::PathBuf::from(payload.get("cwd")?.as_str()?);
            if !cwd.is_absolute() {
                return None;
            }
            cwd.join(value)
        };
        if value
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return None;
        }
        Some(AtlasHookTarget::File(
            se_types::NativePath::from_local(value).ok()?,
        ))
    };
    match name {
        "Grep" if input.get("-i").and_then(serde_json::Value::as_bool) != Some(true) => {
            symbol(input.get("pattern")?.as_str()?)
        }
        "Read" | "read_file" | "mcp__filesystem__read_file" => file(
            input
                .get("file_path")
                .or_else(|| input.get("path"))?
                .as_str()?,
        ),
        "Bash" | "exec_command" => {
            let command = input
                .get("command")
                .or_else(|| input.get("cmd"))?
                .as_str()?;
            if command.contains([
                ';', '|', '&', '>', '<', '$', '`', '\n', '\r', '\\', '\'', '"',
            ]) {
                return None;
            }
            let words: Vec<_> = command.split_ascii_whitespace().take(5).collect();
            match words.as_slice() {
                ["rg" | "grep", query] => symbol(query),
                ["rg" | "grep", "-n" | "-F" | "--fixed-strings", query] => symbol(query),
                ["cat", path] => file(path),
                _ => None,
            }
        }
        _ => None,
    }
}
/// Both providers accept the same nonblocking PreToolUse additionalContext.
/// No permissionDecision, updatedInput or blocking exit is emitted.
pub fn hook_configuration(
    executable: &std::path::Path,
    home: &std::path::Path,
) -> Option<serde_json::Value> {
    let quote = |path: &std::path::Path| {
        let text = path.to_str()?;
        if cfg!(windows) {
            // The command runs through a provider shell. Refuse shell expansion
            // spellings rather than altering a trusted executable/home path.
            (!text.contains(['"', '%', '!', '$', '`', '\n', '\r'])).then(|| format!("\"{text}\""))
        } else {
            Some(format!("'{}'", text.replace('\'', "'\\''")))
        }
    };
    let command = format!(
        "{} --stateengine-private-atlas-hook {}",
        quote(executable)?,
        quote(home)?
    );
    Some(
        serde_json::json!({"PreToolUse":[{"matcher":"^(Grep|Read|Bash|exec_command|read_file|mcp__filesystem__read_file)$","hooks":[{"type":"command","command":command,"timeout":1}]}]}),
    )
}

#[cfg(test)]
mod tests;
