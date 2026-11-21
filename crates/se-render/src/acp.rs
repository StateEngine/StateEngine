use se_core::ops::AcpRuntimeView;
use se_types::Read;
use std::io::{self, Write};
pub(super) fn runtime(
    value: &Read<AcpRuntimeView>,
    prefix: &str,
    out: &mut impl Write,
) -> io::Result<()> {
    match value {
        Read::Present { value } => {
            writeln!(out, "{prefix}Agent activity: {}", value.activity)?;
            if let Some(mode) = &value.mode {
                writeln!(out, "{prefix}Harness mode: {mode}")?;
            }
            if let Some(reason) = &value.last_permission_refusal {
                writeln!(out, "{prefix}Tool request refused: {reason}")?;
            }
            if let Some(reply) = &value.provisional_reply
                && !reply.text.is_empty()
            {
                writeln!(
                    out,
                    "{prefix}Provisional reply ({} earlier bytes omitted): {}",
                    reply.omitted_bytes, reply.text
                )?;
            }
            if let Some(failure) = &value.failure {
                writeln!(out, "{prefix}Protocol failed: {}", failure.message())?;
            }
        }
        Read::Absent { checked } => {
            writeln!(out, "{prefix}Protocol connection: absent ({checked})")?
        }
        Read::Unknown { what } => writeln!(out, "{prefix}Protocol connection: unknown ({what})")?,
        Read::Unreadable { reason, .. } => {
            writeln!(out, "{prefix}Protocol connection: unreadable ({reason})")?
        }
    }
    Ok(())
}
