//! Bounded source reads over a retained native root. No ambient path/cwd opens.
use crate::{errors::AtlasResult, lifecycle::*, model::*, scope::Scope};
use se_types::{Detail, SeError, code::AtlasText, details};
use std::{
    io::{Read, Seek, SeekFrom},
    time::{Duration, Instant},
};
/// Safe native adapter contract: every component is opened no-follow below the
/// retained registered root. None means independently confirmed absence; denied,
/// non-UTF8 names, links and replaced roots are errors, never missing files.
pub trait SourceAccess {
    fn physical_root(&self) -> AtlasResult<[u8; 32]>;
    fn case_mode(&self) -> CaseMode;
    fn open(&self, path: &RelativePath) -> AtlasResult<Option<Box<dyn SourceFile + '_>>>;
}
pub trait SourceFile: Read + Seek {
    fn identity(&self) -> AtlasResult<FileIdentity>;
    /// Reopen/revalidate the spelling against this native file, including root custody.
    fn validate_path(&self) -> AtlasResult<bool>;
}
pub struct RegisteredSource<A> {
    pub scope: Scope,
    access: A,
}
impl<A: SourceAccess> RegisteredSource<A> {
    pub fn new(scope: Scope, access: A) -> AtlasResult<Self> {
        if access.physical_root()? != scope.physical_root {
            return Err(SeError::invalid(
                "Atlas source",
                "the registered physical root",
            ));
        }
        Ok(Self { scope, access })
    }
    /// One retained, root-validated file for streaming Text reads. Consumers
    /// enforce their byte/deadline bound, recheck identity and validate_path
    /// before accepting hits. The borrow cannot outlive this registered root.
    pub fn open(&self, path: &RelativePath) -> AtlasResult<Option<Box<dyn SourceFile + '_>>> {
        if self.access.physical_root()? != self.scope.physical_root {
            return Err(source_error(
                path,
                "registered physical root changed; explicitly rebind",
            ));
        }
        self.access.open(path)
    }
}
impl<A: SourceAccess> AtlasSource for RegisteredSource<A> {
    fn case_mode(&self) -> CaseMode {
        self.access.case_mode()
    }
    fn read(&self, path: &RelativePath, budget: ParseBudget) -> AtlasResult<SourceRead> {
        if budget.max_source_bytes == 0
            || budget.max_source_bytes > 512 * 1024
            || budget.max_work.is_zero()
            || budget.max_work > Duration::from_millis(200)
        {
            return Err(SeError::invalid(
                "Atlas parse budget",
                "1..524288 source bytes and 1..200 ms",
            ));
        }
        let deadline = Instant::now() + budget.max_work;
        let Some(mut file) = self.open(path)? else {
            return Ok(SourceRead::Removed);
        };
        let before = file.identity()?;
        if before.size > u64::from(budget.max_source_bytes) {
            return Ok(SourceRead::Deferred {
                identity: before,
                reason: CoverageReason::SourceBytesLimit,
            });
        }
        if before.size > u64::from(budget.reserved_bytes) {
            return Err(SeError::new(Detail::AtlasResourceBudget(
                details::AtlasResourceBudget {
                    resource: "Atlas source arena".into(),
                    requested: before.size,
                    available: u64::from(budget.reserved_bytes),
                },
            )));
        }
        let mut bytes = Vec::with_capacity(before.size as usize);
        let hash = stream(
            &mut *file,
            path,
            before.size,
            deadline,
            budget.max_work,
            |chunk| {
                bytes.extend_from_slice(chunk);
            },
        )?;
        if file.identity()? != before || !file.validate_path()? {
            return Err(changed());
        }
        Ok(SourceRead::Bytes(SourceSnapshot {
            path: path.clone(),
            identity: before,
            content_hash: hash,
            bytes,
        }))
    }
    fn verify(&self, snapshot: &SourceSnapshot) -> AtlasResult<SourceVerification> {
        let Some(mut file) = self.open(&snapshot.path)? else {
            return Ok(SourceVerification::Removed);
        };
        let identity = file.identity()?;
        if identity.size > 512 * 1024 {
            return Err(source_error(
                &snapshot.path,
                "snapshot exceeds parser admission",
            ));
        }
        if identity != snapshot.identity {
            return Ok(SourceVerification::Changed);
        }
        let hash = stream(
            &mut *file,
            &snapshot.path,
            identity.size,
            Instant::now() + Duration::from_millis(200),
            Duration::from_millis(200),
            |_| {},
        )?;
        if file.identity()? != identity || !file.validate_path()? || hash != snapshot.content_hash {
            return Ok(SourceVerification::Changed);
        }
        Ok(SourceVerification::Unchanged)
    }
    fn read_chunk(
        &self,
        path: &RelativePath,
        offset: u64,
        max_bytes: u32,
    ) -> AtlasResult<Option<SourceChunk>> {
        if !(1..=16384).contains(&max_bytes) {
            return Err(SeError::invalid("Atlas source chunk", "1..16384 bytes"));
        }
        let Some(mut file) = self.open(path)? else {
            return Ok(None);
        };
        let before = file.identity()?;
        if before.size > 64 * 1024 * 1024 || offset > before.size {
            return Err(source_error(
                path,
                "text file exceeds 64 MiB or offset is beyond EOF",
            ));
        }
        let count = (before.size - offset).min(u64::from(max_bytes)) as usize;
        let mut bytes = vec![0; count];
        let mut again = vec![0; count];
        let deadline = Instant::now() + Duration::from_millis(200);
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| source_error(path, e))?;
        file.read_exact(&mut bytes)
            .map_err(|e| source_error(path, e))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| source_error(path, e))?;
        file.read_exact(&mut again)
            .map_err(|e| source_error(path, e))?;
        if Instant::now() >= deadline {
            return Err(source_timeout(Duration::from_millis(200)));
        }
        if bytes != again || file.identity()? != before || !file.validate_path()? {
            return Err(changed());
        }
        let range_hash = ContentHash(*blake3::hash(&bytes).as_bytes());
        let eof = offset + count as u64 == before.size;
        Ok(Some(SourceChunk {
            path: path.clone(),
            identity: before,
            offset,
            bytes,
            end_of_file: eof,
            range_hash,
            content_revision: (offset == 0 && eof).then_some(range_hash),
        }))
    }
}
fn stream(
    file: &mut dyn SourceFile,
    path: &RelativePath,
    expected: u64,
    deadline: Instant,
    budget: Duration,
    mut consume: impl FnMut(&[u8]),
) -> AtlasResult<ContentHash> {
    let mut hash = blake3::Hasher::new();
    let mut buffer = [0; 16384];
    let mut size = 0u64;
    loop {
        if Instant::now() >= deadline {
            return Err(source_timeout(budget));
        }
        let count = file.read(&mut buffer).map_err(|e| source_error(path, e))?;
        if count == 0 {
            break;
        }
        size = size.checked_add(count as u64).ok_or_else(changed)?;
        if size > expected {
            return Err(changed());
        }
        hash.update(&buffer[..count]);
        consume(&buffer[..count]);
    }
    if Instant::now() >= deadline {
        return Err(source_timeout(budget));
    }
    if size != expected {
        return Err(changed());
    }
    Ok(ContentHash(*hash.finalize().as_bytes()))
}
fn source_error(path: &RelativePath, error: impl std::fmt::Display) -> SeError {
    SeError::new(Detail::AtlasSourceUnreadable(
        details::AtlasSourceUnreadable {
            path: path.as_str().into(),
            reason: error.to_string(),
        },
    ))
}
fn changed() -> SeError {
    SeError::new(Detail::RevisionConflict(details::RevisionConflict {
        entity: "Atlas source snapshot".into(),
        expected: "the retained file and verified bytes".into(),
        current: "source changed during read; retry from the registered root".into(),
    }))
}
fn source_timeout(budget: Duration) -> SeError {
    SeError::new(Detail::DeadlineExceeded(details::DeadlineExceeded {
        op: "Atlas source read".into(),
        deadline_ms: budget.as_millis() as u64,
    }))
}
