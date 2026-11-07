//! A live reader can verify EOF at its cursor without finalizing a partial tail.
use super::*;

pub(in crate::runtime::capture) fn unresolved_at_eof(
    context: &ExecutionContext,
    admission: &se_store::Admission,
    source: &mut BoundTranscript,
    deadline: &Deadline,
) -> Result<Option<(u64, se_types::EventId)>> {
    deadline.remaining()?;
    check_scope(admission, &source.binding)?;
    let mut read =
        super::super::super::executor::checked_pooled_phase(&context.reads, context.generation)?
            .into_snapshot(read_scope(admission))
            .map_err(|error| store_error(&error))?;
    let outcome = read.capture_outcome(source.source, None);
    let outcome = super::super::super::executor::close_read(
        outcome.map_err(|error| store_error(&error)),
        read.close(),
    )?;
    let failure = match outcome {
        Read::Present { value } if matches!(value.body, EventBody::CaptureFailed { .. }) => {
            value.header.event
        }
        Read::Present { value } if matches!(value.body, EventBody::CaptureVerified { .. }) => {
            return Ok(None);
        }
        Read::Absent { .. } => return Ok(None),
        _ => {
            return Err(scope::unreadable(
                "capture verification",
                "the current capture outcome is unavailable",
            ));
        }
    };
    let cursor = cursor(context, admission, source, false)?;
    source
        .pin
        .validate_path(&source.binding.path.to_local()?)
        .map_err(native_error)?;
    verify_prefix(source, cursor.evidence.as_ref(), deadline)?;
    let tail = source.pin.read_at(cursor.offset, 1).map_err(native_error)?;
    Ok((tail.bytes.is_empty() && tail.end_of_file).then_some((cursor.offset, failure)))
}
