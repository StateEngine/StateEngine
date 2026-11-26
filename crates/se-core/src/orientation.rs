//! First-turn orientation, fitted into the space the assembled packet left.
//! It is stateless context: nothing is acknowledged or advanced by showing it.
use crate::{
    ops::continuity::{ResumeOutput, SessionContextOutput, packet::wire_bytes},
    scope,
};
use se_types::{Result, code::Orientation};
use sha2::{Digest, Sha256};

/// Bytes an orientation may take, at most, in any packet.
pub const ALLOCATION: usize = 1024;

fn encoded(value: &Orientation) -> Result<usize> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|e| scope::unreadable("orientation encoding", &e.to_string()))
}

/// Drop whole entries until the orientation fits `limit`: assignments past
/// the first, then hubs, then areas. `None` when even the smallest form does
/// not fit; the caller then attaches nothing.
fn fit(mut value: Orientation, limit: usize) -> Result<Option<Orientation>> {
    let limit = limit.min(ALLOCATION);
    loop {
        if encoded(&value)? <= limit {
            return Ok(Some(value));
        }
        let map = value.map.as_mut();
        if value.assignments.len() > 1 {
            value.assignments.pop();
            value.more_assignments = true;
        } else if let Some(map) = map.filter(|map| !map.hubs.is_empty() || !map.areas.is_empty()) {
            if map.hubs.pop().is_none() {
                map.areas.pop();
            }
            map.complete = false;
        } else if value.map.take().is_some() {
            value.map_note = Some("left out by the packet byte budget".into());
        } else if value.assignments.pop().is_some() {
            value.more_assignments = true;
        } else {
            return Ok(None);
        }
    }
}

/// Attach to a resume packet without exceeding its byte budget.
pub fn attach_resume(output: &mut ResumeOutput, value: Orientation) -> Result<()> {
    if output.orientation.is_some() {
        return Ok(());
    }
    let base = wire_bytes("se.resume/v1", output)?;
    let mut limit = (output.budget.limit_bytes as usize).saturating_sub(base);
    let mut value = Some(value);
    while let Some(candidate) = value.take() {
        let Some(fitted) = fit(candidate, limit)? else {
            return Ok(());
        };
        output.orientation = Some(fitted.clone());
        for _ in 0..8 {
            let bytes = wire_bytes("se.resume/v1", output)? as u64;
            if bytes == output.budget.used_bytes {
                break;
            }
            output.budget.used_bytes = bytes;
        }
        let bytes = wire_bytes("se.resume/v1", output)?;
        if bytes <= output.budget.limit_bytes as usize {
            return Ok(());
        }
        output.orientation = None;
        output.budget.used_bytes = base as u64;
        limit = limit.saturating_sub(bytes - output.budget.limit_bytes as usize + 1);
        value = Some(fitted);
    }
    Ok(())
}

/// Add the orientation to a JSON model input object, if it fits `byte_budget`.
fn insert(text: &str, value: Orientation, byte_budget: usize) -> Result<Option<String>> {
    let mut model: serde_json::Value =
        serde_json::from_str(text).map_err(|e| scope::unreadable("model input", &e.to_string()))?;
    let object = model
        .as_object_mut()
        .ok_or_else(|| scope::unreadable("model input", "object required"))?;
    if object.contains_key("orientation") {
        return Ok(None);
    }
    let mut limit = byte_budget.saturating_sub(text.len());
    let mut value = Some(value);
    while let Some(candidate) = value.take() {
        let Some(fitted) = fit(candidate, limit)? else {
            return Ok(None);
        };
        object.insert(
            "orientation".into(),
            serde_json::to_value(&fitted)
                .map_err(|e| scope::unreadable("orientation", &e.to_string()))?,
        );
        let encoded = serde_json::to_string(&object)
            .map_err(|e| scope::unreadable("model input", &e.to_string()))?;
        if encoded.len() <= byte_budget {
            return Ok(Some(encoded));
        }
        object.remove("orientation");
        limit = limit.saturating_sub(encoded.len() - byte_budget + 1);
        value = Some(fitted);
    }
    Ok(None)
}

/// The linked session consumer's model input gets the same orientation.
pub fn attach_context(
    output: &mut SessionContextOutput,
    value: Orientation,
    byte_budget: u32,
) -> Result<()> {
    let base = wire_bytes("secode.session-context-v1", output)?;
    let room = (byte_budget as usize).saturating_sub(base) + output.assembled_model_input.len();
    let Some(text) = insert(&output.assembled_model_input, value, room)? else {
        return Ok(());
    };
    let old_text = std::mem::replace(&mut output.assembled_model_input, text);
    let old_id = std::mem::replace(
        &mut output.packet_id,
        format!(
            "{:x}",
            Sha256::digest(output.assembled_model_input.as_bytes())
        ),
    );
    let old_size = std::mem::replace(
        &mut output.byte_size,
        output.assembled_model_input.len() as u64,
    );
    if wire_bytes("secode.session-context-v1", output)? > byte_budget as usize {
        output.assembled_model_input = old_text;
        output.packet_id = old_id;
        output.byte_size = old_size;
    }
    Ok(())
}

/// Native consumers budget their raw model input directly.
pub fn attach_model_input(text: &mut String, value: Orientation, byte_budget: u32) -> Result<()> {
    if let Some(updated) = insert(text, value, byte_budget as usize)? {
        *text = updated;
    }
    Ok(())
}
