use se_core::ops::outputs::{Delivery, MessageRow, Notification};
use std::io::{self, Write};

pub(crate) fn delivery(value: &Delivery, out: &mut impl Write) -> io::Result<()> {
    let state = match value.state.as_str() {
        "pending" => "not observed",
        "delivered" => "accepted by provider",
        "not-applicable" => "not applicable",
        other => other,
    };
    writeln!(
        out,
        "Notification delivery: {state} (not a read or completion receipt)"
    )
}

pub(crate) fn message_state(value: &MessageRow, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "Recipient state: {}", value.disposition.state)?;
    delivery(&value.delivery, out)
}

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
