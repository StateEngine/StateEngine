//! Protected, bounded text handles. The native name is retired while empty;
//! only the held file contains text, and dropping any queued/rejected handle
//! reclaims it without a pathname race or a persistent orphan.
use crate::{connection, error::*, *};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    sync::Mutex,
};

pub struct StagedText {
    file: Mutex<File>,
    store: StoreId,
    incarnation: u64,
    generation: u64,
    length: u64,
    digest: [u8; 32],
}
impl StagedTextValue for StagedText {
    fn byte_length(&self) -> u64 {
        self.length
    }
    fn sha256(&self) -> [u8; 32] {
        self.digest
    }
}
impl StagedText {
    pub(crate) fn materialize(
        &self,
        info: &StoreInfo,
        identity: &LeaseIdentity,
    ) -> StoreResult<String> {
        if self.store != info.id
            || self.incarnation != info.incarnation
            || self.generation != identity.generation
        {
            return Err(fail(
                StoreErrorCode::GenerationChanged,
                "staged text belongs to another store/incarnation/generation",
            ));
        }
        let mut file = self
            .file
            .lock()
            .map_err(|_| invalid("staged text handle poisoned"))?;
        file.seek(SeekFrom::Start(0)).map_err(stream_error)?;
        let mut bytes = Vec::with_capacity(self.length as usize);
        Read::by_ref(&mut *file)
            .take(self.length + 1)
            .read_to_end(&mut bytes)
            .map_err(stream_error)?;
        if bytes.len() as u64 != self.length || Sha256::digest(&bytes).as_slice() != self.digest {
            return Err(fail(
                StoreErrorCode::SourceChanged,
                "staged text length/hash changed",
            ));
        }
        String::from_utf8(bytes).map_err(|_| invalid("staged text is not UTF-8"))
    }
}
fn stream_error(error: std::io::Error) -> Box<StoreError> {
    fail(
        if error.kind() == std::io::ErrorKind::StorageFull {
            StoreErrorCode::DiskFull
        } else {
            StoreErrorCode::Unreadable
        },
        format!("staged text stream: {error}"),
    )
}
pub(crate) fn stage(
    path: &Path,
    info: &StoreInfo,
    identity: &LeaseIdentity,
    source: &mut dyn Read,
    maximum: u64,
    lease: &dyn RuntimeLease,
) -> StoreResult<StagedText> {
    let actual = connection::validate_lease(info, lease, identity.mode)?;
    if actual.generation != identity.generation {
        return Err(fail(
            StoreErrorCode::GenerationChanged,
            "staging lease generation changed",
        ));
    }
    if maximum > 1024 * 1024 {
        return Err(fail(
            StoreErrorCode::BodyTooLarge,
            "staged text maximum exceeds 1 MiB",
        ));
    }
    let directory = path
        .parent()
        .ok_or_else(|| invalid("state directory missing"))?
        .join("staging");
    lease.files().prepare_directory(&directory)?;
    let ProtectedStaging { path, mut file } = lease.files().create_staging(&directory)?;
    // Native removal compares the exact empty digest, syncs the parent and
    // witnesses absence. Windows uses POSIX disposition; the held file survives.
    lease
        .files()
        .remove_owned(&path, Sha256::digest([]).into())
        .map_err(|mut e| {
            e.cause.push_str(&format!(
                "; empty staging retirement failed at {}",
                path.display()
            ));
            e
        })?;
    let mut hash = Sha256::new();
    let mut length = 0u64;
    let mut buffer = [0u8; 16 * 1024 + 3];
    let mut carry = 0;
    loop {
        let available = (maximum + 1 - length).min((buffer.len() - carry) as u64) as usize;
        let read = source
            .read(&mut buffer[carry..carry + available])
            .map_err(stream_error)?;
        if read == 0 {
            if carry != 0 {
                return Err(invalid("staged text ends inside a UTF-8 sequence"));
            }
            break;
        }
        length = length
            .checked_add(read as u64)
            .ok_or_else(|| invalid("staged length overflow"))?;
        if length > maximum {
            return Err(fail(
                StoreErrorCode::BodyTooLarge,
                format!("staged text exceeds {maximum} bytes; source cursor is unchanged"),
            ));
        }
        let filled = carry + read;
        let valid = match std::str::from_utf8(&buffer[..filled]) {
            Ok(_) => filled,
            Err(e) if e.error_len().is_none() => e.valid_up_to(),
            Err(_) => return Err(invalid("staged text is not UTF-8")),
        };
        hash.update(&buffer[..valid]);
        file.write_all(&buffer[..valid]).map_err(stream_error)?;
        carry = filled - valid;
        buffer.copy_within(valid..filled, 0);
    }
    Ok(StagedText {
        file: Mutex::new(file),
        store: info.id.clone(),
        incarnation: info.incarnation,
        generation: identity.generation,
        length,
        digest: hash.finalize().into(),
    })
}

pub(crate) fn texts(body: &mut EventBody<InputText>) -> Vec<&mut InputText> {
    use EventBody::*;
    match body {
        MessageSent { body, .. } => vec![body],
        WorkingStateSet { text, .. } | SessionTurn { text, .. } => vec![text],
        DecisionProposed {
            statement,
            rationale,
            ..
        } => std::iter::once(statement)
            .chain(rationale.iter_mut())
            .collect(),
        DecisionRejected { reason, .. }
        | DecisionRetracted { reason, .. }
        | SessionEnded { reason, .. }
        | SessionRevoked { reason, .. }
        | CredentialRevoked { reason, .. } => vec![reason],
        RecoveryRecorded { receipt, .. } => vec![receipt],
        _ => Vec::new(),
    }
}
pub(crate) fn prepare(
    mut batch: AtomicBatch,
    info: &StoreInfo,
    identity: &LeaseIdentity,
) -> StoreResult<AtomicBatch> {
    for event in &mut batch.events {
        for text in texts(&mut event.body) {
            if let InputText::Staged(staged) = text {
                *text = InputText::Inline(staged.materialize(info, identity)?);
            }
        }
    }
    Ok(batch)
}
