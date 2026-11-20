use se_core::ops::GuideOutput;
use std::io::{self, Write};

pub(super) fn output(value: &GuideOutput, out: &mut impl Write) -> io::Result<()> {
    match value {
        GuideOutput::Index { topics } => {
            writeln!(out, "StateEngine guide\n")?;
            for topic in topics {
                writeln!(out, "{} — {}\n  {}", topic.name, topic.title, topic.summary)?;
            }
            writeln!(out, "\nRead one topic: se guide TOPIC")?;
            writeln!(out, "Command options: se help COMMAND")?;
            writeln!(
                out,
                "MCP: stateengine_help (omit topic for the index; set topic to read one)"
            )
        }
        GuideOutput::Topic { title, body, .. } => writeln!(out, "{title}\n\n{body}"),
    }
}
