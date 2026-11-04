//! Read-only, retained Node source custody. No store snapshot or writer enters
//! this module, and decoded source values never execute callbacks or Node code.
use crate::client::lease::Deadline;
use se_core::scope;
use se_proc::NativeSourcePin;
use se_store::{ImportCheckpoint, SourceEvidence};
use se_types::{NativePath, Read, Result, SeError};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, time::SystemTime};

const CHUNK: usize = 256 * 1024;
const ROW: usize = 1024 * 1024;
pub(super) struct SourceFile {
    pin: NativeSourcePin,
    path: NativePath,
    hash: Sha256,
    raw_hash: Sha256,
    offset: u64,
    row: u64,
    read_offset: u64,
    buffer: Vec<u8>,
    consumed: usize,
    modified: Option<SystemTime>,
    document: bool,
}
pub(super) struct Row {
    pub value: Option<serde_json::Value>,
    pub code: Option<&'static str>,
    pub evidence: SourceEvidence,
    pub prefix: [u8; 32],
    pub line_hash: [u8; 32],
    pub raw_prefix: [u8; 32],
    pub next_offset: u64,
    pub next_row: u64,
}
fn native(error: se_proc::StateFileError) -> SeError {
    scope::unreadable("retained Node history source", &error.to_string())
}
fn changed() -> SeError {
    SeError::new(se_types::Detail::StateConflict(se_types::details::StateConflict {
        subject:"Node history source".into(),
        reason:"its native identity or already consumed byte prefix changed; the original checkpoint is retained".into(),
        next_step:"Restore the original source copy, or select a separately preserved source incarnation; do not reset its import cursor.".into(),
    }))
}
impl SourceFile {
    pub(super) fn open(
        path: PathBuf,
        checkpoint: Option<&ImportCheckpoint>,
        deadline: &Deadline,
    ) -> Result<Read<Self>> {
        deadline.remaining()?;
        let Some(mut pin) = NativeSourcePin::open(&path).map_err(native)? else {
            if checkpoint.is_some() {
                return Err(changed());
            }
            return Ok(Read::Absent {
                checked: "named Node source file is absent under native no-follow custody".into(),
            });
        };
        let modified = std::fs::metadata(&path)
            .map_err(|e| scope::unreadable("Node source metadata", &e.to_string()))?
            .modified()
            .ok();
        let mut hash = Sha256::new();
        hash.update(pin.identity());
        let (offset, row) = checkpoint
            .map(|p| (p.byte_offset, p.row_offset))
            .unwrap_or((0, 0));
        let mut raw_hash = Sha256::new();
        prefix(&mut pin, &mut hash, offset, deadline, Some(&mut raw_hash))?;
        if let Some(checkpoint) = checkpoint
            && <[u8; 32]>::from(hash.clone().finalize()) != checkpoint.source_sha256
        {
            return Err(changed());
        }
        let document = path
            .extension()
            .is_some_and(|extension| extension == "json");
        Ok(Read::Present {
            value: Self {
                pin,
                path: NativePath::from_local(path)?,
                hash,
                raw_hash,
                offset,
                row,
                read_offset: offset,
                buffer: Vec::new(),
                consumed: 0,
                modified,
                document,
            },
        })
    }
    pub(super) fn evidence(&self) -> SourceEvidence {
        SourceEvidence {
            path: Some(self.path.clone()),
            incarnation: self.pin.identity().to_vec(),
            offset: 0,
            length: self.offset,
            sha256: Some(self.raw_hash.clone().finalize().into()),
        }
    }
    /// Re-prove the discovery registry's exact snapshot before importing its
    /// roots. Appended rows wait for the next discovery pass.
    pub(super) fn verify_anchor(
        &mut self,
        expected: &SourceEvidence,
        deadline: &Deadline,
    ) -> Result<()> {
        if expected.offset != 0
            || expected.path.as_ref() != Some(&self.path)
            || expected.incarnation != self.pin.identity()
            || self.offset > expected.length
        {
            return Err(changed());
        }
        let mut bound = Sha256::new();
        let mut raw = Sha256::new();
        prefix(
            &mut self.pin,
            &mut bound,
            expected.length,
            deadline,
            Some(&mut raw),
        )?;
        if Some(<[u8; 32]>::from(raw.finalize())) != expected.sha256 {
            return Err(changed());
        }
        self.pin.validate_path(self.pin.path()).map_err(native)
    }
    pub(super) fn source_key(path: &NativePath) -> Result<Vec<u8>> {
        Ok(Sha256::digest(
            serde_json::to_vec(path)
                .map_err(|e| scope::unreadable("Node source path", &e.to_string()))?,
        )
        .to_vec())
    }
    pub(super) fn next(&mut self, deadline: &Deadline) -> Result<Option<Row>> {
        let start = self.offset;
        let mut bytes = Vec::new();
        let mut row_hash = Sha256::new();
        let mut hash = self.hash.clone();
        let mut raw_hash = self.raw_hash.clone();
        let mut size = 0u64;
        loop {
            deadline.remaining()?;
            if self.consumed == self.buffer.len() {
                let chunk = self.pin.read_at(self.read_offset, CHUNK).map_err(native)?;
                if chunk.bytes.is_empty() {
                    if size == 0 && !(self.document && self.row == 0) {
                        return Ok(None);
                    }
                    // A final JSON value without LF is a real source row. A torn
                    // value receives its own ImportUnreadable range, never zero rows.
                    break;
                }
                self.read_offset = chunk.next_offset;
                self.buffer = chunk.bytes;
                self.consumed = 0;
            }
            let remaining = &self.buffer[self.consumed..];
            let length = if self.document {
                remaining.len()
            } else {
                remaining
                    .iter()
                    .position(|b| *b == b'\n')
                    .map(|n| n + 1)
                    .unwrap_or(remaining.len())
            };
            let part = &remaining[..length];
            size = size.checked_add(length as u64).ok_or_else(changed)?;
            row_hash.update(part);
            hash.update(part);
            raw_hash.update(part);
            if size <= ROW as u64 {
                bytes.extend_from_slice(part);
            }
            self.consumed += length;
            if !self.document && part.last() == Some(&b'\n') {
                break;
            }
        }
        self.pin.validate_path(self.pin.path()).map_err(native)?;
        let (value, code) = if size > ROW as u64 {
            (None, Some("row-too-large"))
        } else {
            match std::str::from_utf8(&bytes) {
                Err(_) => (None, Some("source-invalid-utf8")),
                Ok(text) if text.trim().is_empty() => (None, Some("blank-row")),
                Ok(text) => match serde_json::from_str(text) {
                    Ok(value) => (Some(value), None),
                    Err(_) => (None, Some("source-malformed-json")),
                },
            }
        };
        self.offset = self.offset.checked_add(size).ok_or_else(changed)?;
        self.row = self.row.checked_add(1).ok_or_else(changed)?;
        self.hash = hash;
        self.raw_hash = raw_hash;
        Ok(Some(Row {
            value,
            code,
            evidence: SourceEvidence {
                path: Some(self.path.clone()),
                incarnation: self.pin.identity().to_vec(),
                offset: start,
                length: size,
                sha256: Some(row_hash.finalize().into()),
            },
            prefix: self.hash.clone().finalize().into(),
            line_hash: Sha256::digest(bytes.strip_suffix(b"\n").unwrap_or(&bytes)).into(),
            raw_prefix: self.raw_hash.clone().finalize().into(),
            next_offset: self.offset,
            next_row: self.row,
        }))
    }
    /// Called before committing the decoded row. A concurrent append is legal;
    /// a changed consumed prefix is not. Immutable copies avoid repeated scans.
    pub(super) fn verify(&mut self, deadline: &Deadline) -> Result<()> {
        self.pin.validate_path(self.pin.path()).map_err(native)?;
        let metadata = std::fs::metadata(self.pin.path())
            .map_err(|e| scope::unreadable("Node source metadata", &e.to_string()))?;
        let modified = metadata.modified().ok();
        if modified.is_none() || self.modified.is_none() || modified != self.modified {
            let mut hash = Sha256::new();
            hash.update(self.pin.identity());
            prefix(&mut self.pin, &mut hash, self.offset, deadline, None)?;
            if <[u8; 32]>::from(hash.finalize()) != <[u8; 32]>::from(self.hash.clone().finalize()) {
                return Err(changed());
            }
        }
        self.modified = modified;
        self.pin.validate_path(self.pin.path()).map_err(native)
    }
}
fn prefix(
    pin: &mut NativeSourcePin,
    hash: &mut Sha256,
    end: u64,
    deadline: &Deadline,
    mut raw_hash: Option<&mut Sha256>,
) -> Result<()> {
    let mut offset = 0;
    while offset < end {
        deadline.remaining()?;
        let chunk = pin
            .read_at(
                offset,
                usize::try_from((end - offset).min(CHUNK as u64)).map_err(|_| changed())?,
            )
            .map_err(native)?;
        if chunk.bytes.is_empty() {
            return Err(changed());
        }
        offset = chunk.next_offset;
        hash.update(&chunk.bytes);
        if let Some(raw) = raw_hash.as_deref_mut() {
            raw.update(&chunk.bytes);
        }
    }
    Ok(())
}
