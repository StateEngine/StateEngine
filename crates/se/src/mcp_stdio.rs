//! Bounded newline JSON-RPC transport. Method decoding and execution live in
//! se-host's common MCP consumer; stdout contains protocol frames only.
use se_host::client::wire::{MAX_FRAME_BYTES, encode_json};
use se_types::{Result, SeError};
use std::io::{BufRead, Read, Write};
use zeroize::Zeroizing;

pub fn serve(mut dispatch: impl FnMut(&[u8]) -> Result<Option<serde_json::Value>>) -> Result<u8> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    loop {
        let mut bytes = Zeroizing::new(Vec::new());
        let read = input.by_ref().take(MAX_FRAME_BYTES as u64 + 1)
            .read_until(b'\n', &mut bytes).map_err(|error| io_error("MCP stdin", error))?;
        if read == 0 { return Ok(0); }
        if bytes.len() > MAX_FRAME_BYTES || bytes.last() != Some(&b'\n') {
            let refusal = serde_json::json!({"jsonrpc":"2.0","id":null,
                "error":{"code":-32700,"message":"MCP requires one complete newline-terminated frame of at most 1 MiB"}});
            write(&mut output, &refusal)?;
            return Err(SeError::invalid("MCP frame", "a complete newline-terminated frame of at most 1 MiB"));
        }
        if let Some(reply) = dispatch(&bytes)? { write(&mut output, &reply)?; }
    }
}
fn write(output: &mut impl Write, reply: &serde_json::Value) -> Result<()> {
    // Encode before writing: the newline is part of the final byte budget.
    let bytes = encode_json(reply, MAX_FRAME_BYTES - 1)?;
    output.write_all(bytes.as_bytes()).and_then(|()| output.write_all(b"\n"))
        .and_then(|()| output.flush()).map_err(|error| io_error("MCP stdout", error))
}
fn io_error(subject: &str, error: std::io::Error) -> SeError {
    SeError::new(se_types::Detail::SourceUnreadable(se_types::details::SourceUnreadable {
        subject: subject.into(), reason: error.to_string(),
        next_step: "Restore the MCP pipe; after a lost reply, retry only with the original operation key".into(),
    })).with_cause(error)
}
