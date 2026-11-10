use se_core::ops::{SecodeBindingView, SecodeRuntimeView};
use se_types::Read;
use std::io::{self, Write};

pub(crate) fn launch(value: &Read<SecodeBindingView>, out: &mut impl Write) -> io::Result<()> {
    match value {
        Read::Present { value } => {
            writeln!(
                out,
                "Private service PID {} (recorded at launch)",
                value.service_process.fields().pid
            )?;
            writeln!(
                out,
                "Input accepted by the service; this does not confirm a model response."
            )
        }
        Read::Absent { checked } => writeln!(out, "Private service binding absent: {checked}"),
        Read::Unknown { what } => writeln!(out, "Private service binding not checked: {what}"),
        Read::Unreadable { reason, .. } => {
            writeln!(out, "Private service binding unreadable: {reason}")
        }
    }
}
pub(crate) fn runtime(
    value: &Read<SecodeRuntimeView>,
    indent: &str,
    out: &mut impl Write,
) -> io::Result<()> {
    match value {
        Read::Present { value } => {
            writeln!(
                out,
                "{indent}Private service: {}; execution {}",
                value.service_state,
                if value.active { "active" } else { "idle" }
            )?;
            writeln!(
                out,
                "{indent}Current model: {}; effective permissions: {}",
                value.model, value.permission_preset
            )?;
            writeln!(
                out,
                "{indent}Pending approvals: {}",
                value.pending_permissions
            )?;
            fact("Initial input", &value.initial_input, indent, out)?;
            fact("Output stream", &value.output_stream, indent, out)
        }
        Read::Absent { checked } => writeln!(out, "{indent}Private service absent: {checked}"),
        Read::Unknown { what } => writeln!(out, "{indent}Private service not checked: {what}"),
        Read::Unreadable { reason, .. } => {
            writeln!(out, "{indent}Private service unreadable: {reason}")
        }
    }
}
fn fact(label: &str, value: &Read<String>, indent: &str, out: &mut impl Write) -> io::Result<()> {
    match value {
        Read::Present { value } => writeln!(out, "{indent}{label}: {value}"),
        Read::Absent { checked } => writeln!(out, "{indent}{label} absent: {checked}"),
        Read::Unknown { what } => writeln!(out, "{indent}{label} not checked: {what}"),
        Read::Unreadable { reason, .. } => writeln!(out, "{indent}{label} unreadable: {reason}"),
    }
}
