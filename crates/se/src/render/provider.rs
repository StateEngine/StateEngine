use se_core::ops::ProviderActivityView;
use se_types::Read;
use std::io::{self, Write};

pub(crate) fn activity(
    value: &Read<ProviderActivityView>,
    prefix: &str,
    out: &mut impl Write,
) -> io::Result<()> {
    match value {
        Read::Present { value } => {
            writeln!(out, "{prefix}Provider activity: {}", value.activity)?;
            writeln!(out, "{prefix}{}", value.detail)?;
            if let Some(seconds) = value.quiet_seconds {
                writeln!(
                    out,
                    "{prefix}Seconds since last turn observation: {seconds}"
                )?;
            }
            if let Some(next) = &value.next_step {
                writeln!(out, "{prefix}Next: {next}")?;
            }
        }
        Read::Absent { checked } => writeln!(out, "{prefix}Provider activity: absent ({checked})")?,
        Read::Unknown { what } => writeln!(out, "{prefix}Provider activity: unknown ({what})")?,
        Read::Unreadable { reason, .. } => {
            writeln!(out, "{prefix}Provider activity: unreadable ({reason})")?
        }
    }
    Ok(())
}
