//! Exact owned JSON entry reversal. File/digest pins protect foreign edits;
//! an unknown locator or changed document remains a named conflict.
use super::*;
use se_store::{EventBody, IntegrationState, ProjectionRecord};
use sha2::{Digest, Sha256};
use std::path::Path;
#[derive(Clone)]
pub(super) struct IntegrationEffect {
    pub action: String,
    pub state: IntegrationState,
    pub digest: Option<[u8; 32]>,
    pub failure: Option<String>,
    pub observed_at: String,
}
pub(super) fn reverse(head: &ProjectionRecord) -> Result<IntegrationEffect> {
    let EventBody::IntegrationRecorded {
        path,
        key,
        written_sha256,
        ..
    } = &head.current.body
    else {
        return Err(se_core::scope::unreadable(
            "integration reversal",
            "wrong projection",
        ));
    };
    let path = path.to_local()?;
    let result = reverse_owned(&path, key, *written_sha256);
    let (action, state, digest, failure) = match result {
        Ok((action, digest)) => (action, IntegrationState::Removed, digest, None),
        Err(failure) => (
            "conflict-kept",
            IntegrationState::Conflict,
            None,
            Some(failure.to_string()),
        ),
    };
    Ok(IntegrationEffect {
        action: action.into(),
        state,
        digest,
        failure,
        observed_at: se_core::ops::receipt::timestamp(crate::runtime::start::now_unix_micros()?)?,
    })
}
fn reverse_owned(
    path: &Path,
    key: &str,
    expected: Option<[u8; 32]>,
) -> Result<(&'static str, Option<[u8; 32]>)> {
    let Some(mut file) =
        se_proc::OwnedFile::open(path).map_err(|e| error("owned integration", e))?
    else {
        return Ok(("absent", None));
    };
    let bytes = file
        .read(1024 * 1024)
        .map_err(|e| error("owned integration read", e))?;
    let mut document: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| error("owned integration JSON", e))?;
    let (parent, leaf) = if key.starts_with('/') {
        let (parent, leaf) = key.rsplit_once('/').ok_or_else(|| {
            se_types::SeError::invalid("owned integration locator", "a JSON object pointer")
        })?;
        (parent, decode(leaf)?)
    } else {
        ("", key.to_owned())
    };
    let Some(object) = document
        .pointer_mut(parent)
        .and_then(serde_json::Value::as_object_mut)
    else {
        return Err(se_core::scope::unreadable(
            "owned integration locator",
            "the recorded object pointer is absent or has changed type",
        ));
    };
    if !object.contains_key(&leaf) {
        // A strict JSON pointer has one unambiguous meaning. A legacy bare key
        // cannot prove an absent nested entry and is preserved for reconciliation.
        if key.starts_with('/') {
            return Ok(("absent", Some(Sha256::digest(&bytes).into())));
        }
        return Err(se_core::scope::unreadable(
            "owned integration locator",
            "the bare key is not present at the document root; preserve this unknown locator",
        ));
    }
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if expected != Some(digest) {
        return Err(se_core::scope::unreadable(
            "owned integration entry",
            "the file differs from the recorded write; preserve user changes",
        ));
    }
    object.remove(&leaf);
    let replaced = serde_json::to_vec_pretty(&document)
        .map_err(|e| error("owned integration serialization", e))?;
    file.replace(digest, &replaced)
        .map_err(|e| error("owned integration replacement", e))?;
    let mut reopened = se_proc::OwnedFile::open(path)
        .map_err(|e| error("integration readback", e))?
        .ok_or_else(|| {
            se_core::scope::unreadable("integration readback", "the replaced file is absent")
        })?;
    let observed = reopened
        .read(1024 * 1024)
        .map_err(|e| error("integration readback", e))?;
    if observed != replaced {
        return Err(se_core::scope::unreadable(
            "integration readback",
            "bytes changed after reversal",
        ));
    }
    Ok(("reversed", Some(Sha256::digest(&observed).into())))
}
fn decode(value: &str) -> Result<String> {
    let mut decoded = String::new();
    let mut units = value.chars();
    while let Some(unit) = units.next() {
        if unit != '~' {
            decoded.push(unit);
            continue;
        }
        decoded.push(match units.next() {
            Some('0') => '~',
            Some('1') => '/',
            _ => {
                return Err(se_types::SeError::invalid(
                    "owned integration locator",
                    "a canonical RFC 6901 object pointer",
                ));
            }
        });
    }
    Ok(decoded)
}
