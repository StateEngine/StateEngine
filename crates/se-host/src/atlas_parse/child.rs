use super::*;
use std::io::{self, Write};
/// Serialization is bounded before the native frame writer sees a record.
struct Frame(Vec<u8>);
impl Write for Frame {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > se_proc::atlas_worker::FRAME_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "parser record exceeds frame limit",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn send(channel: &mut WorkerChannel, reply: protocol::Reply) -> AtlasResult<()> {
    let mut frame = Frame(Vec::with_capacity(se_proc::atlas_worker::FRAME_BYTES));
    serde_json::to_writer(&mut frame, &reply).map_err(failure)?;
    channel.send(&frame.0).map_err(failure)
}
pub(crate) fn run(channel: &mut WorkerChannel, bytes: &[u8]) -> AtlasResult<u8> {
    let result = (|| {
        let request: protocol::Request = serde_json::from_slice(bytes).map_err(failure)?;
        if !request.parse_only || request.profile.language != request.language {
            return Err(failure("parse-only request and matching profile required"));
        }
        let source = request.source()?;
        let SourceRead::Bytes(snapshot) = source.read(&request.path, request.budget)? else {
            return Err(failure(
                "parse source is no longer readable within its reservation",
            ));
        };
        if snapshot.identity != request.identity || snapshot.content_hash != request.content_hash {
            return Err(failure("parse source changed before worker read"));
        }
        let mut parser =
            se_atlas::parse::SemanticParser::new(source.scope.clone(), vec![request.profile])?;
        parser.set_resource_guard(crate::atlas_cold::parser_memory_guard);
        let parsed = parser.parse(&snapshot, request.language, request.budget)?;
        // Native tree and parser scratch are gone before any row is returned.
        drop(parser);
        send(
            channel,
            protocol::Reply::Start {
                file: parsed.file,
                language: parsed.language,
                hash: parsed.content_hash,
                coverage: parsed.coverage,
            },
        )?;
        for row in parsed.symbols {
            send(channel, protocol::Reply::Symbol(row))?;
        }
        for row in parsed.imports {
            send(channel, protocol::Reply::Import(row))?;
        }
        for row in parsed.references {
            send(channel, protocol::Reply::Reference(row))?;
        }
        for row in parsed.scopes {
            send(channel, protocol::Reply::Scope(row))?;
        }
        send(channel, protocol::Reply::Done)
    })();
    let success = result.is_ok();
    if let Err(error) = result {
        send(channel, protocol::Reply::Failed { error: error.body })?;
    }
    channel.await_reap().map_err(failure)?;
    Ok(if success { 0 } else { 1 })
}
