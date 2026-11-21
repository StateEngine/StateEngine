use se_core::ops::{CodexLoginView, ProviderActivityView};
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
            if let Some(at) = &value.mail_paced_until {
                writeln!(
                    out,
                    "{prefix}New mail is delivered; the next wake for it is paced until {at}."
                )?;
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

pub(crate) fn codex_login(
    value: &Read<CodexLoginView>,
    prefix: &str,
    out: &mut impl Write,
) -> io::Result<()> {
    match value {
        Read::Present { value } => match &value.account {
            Some(account) => writeln!(out, "{prefix}Codex login: {account} ({})", value.home),
            None => writeln!(out, "{prefix}Codex login: {}", value.home),
        },
        Read::Absent { checked } => writeln!(out, "{prefix}Codex login: absent ({checked})"),
        Read::Unknown { what } => writeln!(out, "{prefix}Codex login: unknown ({what})"),
        Read::Unreadable { reason, .. } => {
            writeln!(out, "{prefix}Codex login: unreadable ({reason})")
        }
    }
}
