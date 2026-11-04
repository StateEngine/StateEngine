use se_core::ops::outputs::Notification;
use std::io::{self, Write};
pub(crate) fn render(value: &Notification, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "Notification: {}", value.intent)?;
    for row in &value.recipients {
        writeln!(
            out,
            "  {}: {}{}",
            row.recipient.name,
            row.state,
            row.code
                .as_ref()
                .map(|c| format!(" ({c})"))
                .unwrap_or_default()
        )?;
    }
    Ok(())
}
