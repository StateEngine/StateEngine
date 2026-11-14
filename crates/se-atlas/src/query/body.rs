use super::*;
use std::io::{Read as _, SeekFrom};
/// A stored declaration span is displayed only after the live whole-file hash
/// agrees. This also covers bodyless declarations without inventing body hashes.
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(super) fn source(
    env: &QueryEnv<'_>,
    pointer: &mut CodePointer,
    end: Instant,
) -> AtlasResult<Option<HitBody>> {
    let source = env.source.ok_or_else(|| {
        se_types::SeError::invalid(
            "Atlas source bodies",
            "the registered native source adapter",
        )
    })?;
    let Some(mut file) = source.open_stream(&pointer.path)? else {
        pointer.freshness = SnapshotFreshness::Stale;
        return Ok(None);
    };
    let before = file.identity()?;
    if before.size > 64 * 1024 * 1024 {
        return Ok(None);
    }
    let start = pointer.span.map_or(0, |s| s.start_byte);
    let stop = pointer.span.map_or(before.size, |s| s.end_byte);
    if stop > before.size || start > stop {
        pointer.freshness = SnapshotFreshness::Stale;
        return Ok(None);
    }
    let mut hash = blake3::Hasher::new();
    let mut buffer = [0; 16_384];
    let mut offset = 0u64;
    let mut excerpt = Vec::with_capacity(12 * 1024);
    let mut lines = 0;
    let mut cut = false;
    loop {
        if crate::clock::now() >= end {
            return Err(capacity("Atlas full-body work deadline", 1, 0));
        }
        let count = file
            .read(&mut buffer)
            .map_err(|e| source_error(&pointer.path, e))?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        for (index, byte) in buffer[..count].iter().enumerate() {
            let at = offset + index as u64;
            if at >= start && at < stop {
                if excerpt.len() == 12 * 1024 || lines == 40 {
                    cut = true;
                    continue;
                }
                excerpt.push(*byte);
                if *byte == b'\n' {
                    lines += 1;
                }
            }
        }
        offset += count as u64;
        if offset > before.size {
            pointer.freshness = SnapshotFreshness::Stale;
            return Ok(None);
        }
    }
    let revision = ContentHash(*hash.finalize().as_bytes());
    if offset != before.size
        || file.identity()? != before
        || !file.validate_path()?
        || pointer
            .content_hash
            .is_some_and(|indexed| indexed != revision)
    {
        pointer.freshness = SnapshotFreshness::Stale;
        return Ok(None);
    }
    // The excerpt must agree on a second read, even on filesystems whose
    // timestamps do not detect every byte write.
    file.seek(SeekFrom::Start(start))
        .map_err(|e| source_error(&pointer.path, e))?;
    let mut again = vec![0; excerpt.len()];
    file.read_exact(&mut again)
        .map_err(|e| source_error(&pointer.path, e))?;
    if again != excerpt || file.identity()? != before || !file.validate_path()? {
        pointer.freshness = SnapshotFreshness::Stale;
        return Ok(None);
    }
    let text = match String::from_utf8(excerpt) {
        Ok(text) => text,
        Err(error) if cut && error.utf8_error().error_len().is_none() => {
            let end = error.utf8_error().valid_up_to();
            let mut bytes = error.into_bytes();
            bytes.truncate(end);
            String::from_utf8(bytes).map_err(cache_error)?
        }
        Err(error) => return Err(source_error(&pointer.path, error)),
    };
    let first = pointer.span.map_or(
        Position {
            line: 1,
            byte_column: 0,
        },
        |s| s.start,
    );
    let end_position = if let Some((_, last)) = text.rsplit_once('\n') {
        Position {
            line: first.line + text.bytes().filter(|b| *b == b'\n').count() as u32,
            byte_column: last.len() as u32,
        }
    } else {
        Position {
            line: first.line,
            byte_column: first.byte_column + text.len() as u32,
        }
    };
    let span = Span {
        start: first,
        end: end_position,
        start_byte: start,
        end_byte: start + text.len() as u64,
    };
    HitBody::new(
        BodyOrigin::LiveSource {
            file: pointer.file,
            path: pointer.path.clone(),
            span,
            range_hash: ContentHash(*blake3::hash(text.as_bytes()).as_bytes()),
            content_hash: Some(revision),
            matches_index: pointer.content_hash.map(|old| old == revision),
        },
        text,
        !cut,
    )
    .map(Some)
}
pub(super) fn source_error(
    path: &RelativePath,
    error: impl std::fmt::Display,
) -> se_types::SeError {
    se_types::SeError::new(se_types::Detail::AtlasSourceUnreadable(
        se_types::details::AtlasSourceUnreadable {
            path: path.as_str().into(),
            reason: error.to_string(),
        },
    ))
}
