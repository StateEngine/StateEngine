use se_types::Read;
use std::io::{self, Write};

pub fn render(value: &se_core::ops::transcript::View, out: &mut impl Write) -> io::Result<()> {
    match &value.last_compaction {
        Read::Present { value } => writeln!(
            out,
            "Provider compacted its conversation at transcript byte {} [{}].",
            value.record.position.offset, value.event_id
        ),
        Read::Unreadable { reason, .. } => {
            writeln!(out, "Compaction history unavailable: {reason}")
        }
        Read::Unknown { what } => writeln!(out, "Compaction history unknown: {what}"),
        Read::Absent { .. } => Ok(()),
    }
}
