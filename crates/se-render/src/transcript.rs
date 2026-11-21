use se_types::Read;
use std::io::{self, Write};

pub fn render(value: &se_core::ops::transcript::View, out: &mut impl Write) -> io::Result<()> {
    match &value.last_compaction {
        Read::Present { value } => writeln!(
            out,
            "The provider shortened its earlier conversation context at transcript byte {} [{}].",
            value.record.position.offset, value.event_id
        ),
        Read::Unreadable { reason, .. } => {
            writeln!(out, "Conversation context history unavailable: {reason}")
        }
        Read::Unknown { .. } => writeln!(
            out,
            "Earlier conversation context changes have not been checked."
        ),
        Read::Absent { .. } => Ok(()),
    }
}
