//! Exercise the production native-pin scanner, including retries and cold joins.
use super::*;
use crate::test_directory as cleanup_directory;
use se_core::ops::transcript::tool::{Outcome, Phase, Target};
use se_store::RecordIdentity;
use serde_json::{Value, json};
type Check = std::result::Result<(), Box<dyn std::error::Error>>;

fn source(
    rows: &[Value],
) -> std::result::Result<
    (
        cleanup_directory::PrivateDirectory,
        BoundTranscript,
        Vec<u8>,
    ),
    Box<dyn std::error::Error>,
> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("se-tools-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&directory)?;
    let root_owner = cleanup_directory::PrivateDirectory::adopt(directory.clone());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
    }
    let path = directory.join("transcript.jsonl");
    let mut bytes = Vec::new();
    for row in rows {
        bytes.extend(serde_json::to_vec(row)?);
        bytes.push(b'\n');
    }
    std::fs::write(&path, &bytes)?;
    let pin = se_proc::NativeSourcePin::open(&path)?.ok_or("missing source")?;
    let source = BoundTranscript {
        binding: crate::TranscriptPin {
            identity: crate::SessionIdentity {
                project: se_types::ProjectId::from_parts(1, [3; 10])?,
                agent: se_types::AgentId::from_parts(1, [4; 10])?,
                session: se_types::SessionId::from_parts(1, [1; 10])?,
            },
            conversation: "tools-native".parse()?,
            path: se_types::NativePath::from_local(path)?,
            file_identity: se_types::Sha256::from_bytes(pin.identity()),
        },
        queue: Default::default(),
        tools: Default::default(),
        source: se_store::RecordId::from_parts(1, [2; 10])?,
        pin,
    };
    Ok((root_owner, source, bytes))
}
fn scan(
    source: &mut BoundTranscript,
    offset: u64,
    provider: se_store::Provider,
) -> Result<Option<TrustedCapture>> {
    next(
        source,
        se_store::Revision {
            value: std::num::NonZeroU64::MIN,
        },
        offset,
        provider,
        &Deadline::idle()?.stage(std::time::Duration::from_secs(10))?,
        true,
    )
}
fn cleanup(source: BoundTranscript) -> Check {
    let path = source.pin.path().to_path_buf();
    drop(source);
    std::fs::remove_file(&path)?;
    std::fs::remove_dir(path.parent().ok_or("parent")?)?;
    Ok(())
}
fn call(n: usize) -> Value {
    json!({"type":"tool_use","id":format!("call-{n}"),"name":"Edit","input":{"file_path":format!("{n}.rs")}})
}
fn assistant(blocks: Vec<Value>) -> Value {
    json!({"type":"assistant","uuid":"assistant-native","sessionId":"tools-native",
        "cwd":"/native/work","message":{"role":"assistant","content":blocks}})
}
#[test]
fn tool_only_progress_keeps_exact_ranges_and_cold_call_result_identity() -> Check {
    let rows = [
        assistant(vec![call(0)]),
        json!({"type":"user","uuid":"result-native",
        "sessionId":"tools-native","message":{"role":"user","content":[{
            "type":"tool_result","tool_use_id":"call-0","is_error":false,"content":"PRIVATE_OUTPUT"}]}}),
    ];
    let (_root_owner, mut source, bytes) = source(&rows)?;
    let first = scan(&mut source, 0, se_store::Provider::Claude)?.ok_or("called fact missing")?;
    assert_eq!(first.request.role, se_store::Role::System);
    let record = Record::decode(first.request.text.as_str())?;
    let called = record.captured_tool.ok_or("called metadata")?;
    assert_eq!(called.phase, Phase::Called);
    let end = first.request.new_offset;
    assert_eq!(called.position.offset, 0);
    assert_eq!(called.position.length, end);
    assert_eq!(
        first.request.evidence.sha256,
        Some(Sha256::digest(&bytes[..end as usize]).into())
    );
    let retry = scan(&mut source, 0, se_store::Provider::Claude)?.ok_or("retry lost")?;
    assert_eq!(retry.request.text.as_str(), first.request.text.as_str());
    source.tools.clear(); // Simulate a fresh runtime, retaining only the native pin/cursor.
    let second = scan(&mut source, end, se_store::Provider::Claude)?.ok_or("result missing")?;
    let result = Record::decode(second.request.text.as_str())?
        .captured_tool
        .ok_or("result metadata")?;
    assert_eq!(
        serde_json::to_value(result.native)?,
        serde_json::to_value(called.native)?
    );
    assert!(matches!(result.outcome, Outcome::Succeeded));
    assert_eq!(
        serde_json::to_value(result.target)?,
        serde_json::to_value(called.target)?
    );
    assert_eq!(result.position.offset, end);
    assert_eq!(second.request.new_offset, bytes.len() as u64);
    assert!(!second.request.text.as_str().contains("PRIVATE_OUTPUT"));
    cleanup(source)
}
#[test]
fn metadata_bound_flushes_prior_noise_and_never_skips_an_overfull_native_record() -> Check {
    let noise = json!({"type":"file-history-snapshot","snapshot":{}});
    let (_root_owner, mut source, bytes) =
        source(&[noise.clone(), assistant((0..32).map(call).collect())])?;
    let first = scan(&mut source, 0, se_store::Provider::Claude)?.ok_or("noise prefix missing")?;
    let boundary = serde_json::to_vec(&noise)?.len() as u64 + 1;
    assert_eq!(first.request.new_offset, boundary);
    assert_eq!(Record::decode(first.request.text.as_str())?.count, Some(1));
    let tools = scan(&mut source, boundary, se_store::Provider::Claude)?.ok_or("tools missing")?;
    assert_eq!(tools.request.metadata.len(), 31);
    assert_eq!(tools.request.new_offset, bytes.len() as u64);
    assert!(
        tools
            .request
            .metadata
            .iter()
            .all(|m| m.record.captured_tool.is_some())
    );
    cleanup(source)?;
    let (_overfull_owner, mut overfull, _) =
        self::source(&[assistant((0..33).map(call).collect())])?;
    assert!(scan(&mut overfull, 0, se_store::Provider::Claude).is_err());
    assert!(
        overfull.tools.is_empty(),
        "refused record retained speculative progress"
    );
    assert!(scan(&mut overfull, 0, se_store::Provider::Claude).is_err());
    cleanup(overfull)
}
#[test]
fn codex_pin_retains_file_and_mcp_facts_without_turn_text_or_patch_content() -> Check {
    let row = |item: Value| {
        json!({"type":"event_msg","payload":{"type":"item_completed",
        "thread_id":"tools-native","turn_id":"actual-turn","item":item}})
    };
    let rows = [
        row(
            json!({"type":"FileChange","id":"file-item","status":"Completed",
        "changes":[{"path":"actual.rs","diff":"PRIVATE_PATCH"}]}),
        ),
        row(
            json!({"type":"McpToolCall","id":"mcp-item","tool":"search","status":"Failed",
            "arguments":{"query":"actual query"}}),
        ),
    ];
    let (_root_owner, mut source, bytes) = source(&rows)?;
    let first = scan(&mut source, 0, se_store::Provider::Codex)?.ok_or("file fact")?;
    let file = Record::decode(first.request.text.as_str())?
        .captured_tool
        .ok_or("file metadata")?;
    assert!(matches!(file.outcome, Outcome::Succeeded));
    assert!(matches!(file.target, Target::Paths(ref paths) if paths[0].spelling == "actual.rs"));
    assert!(!first.request.text.as_str().contains("PRIVATE_PATCH"));
    let second = scan(
        &mut source,
        first.request.new_offset,
        se_store::Provider::Codex,
    )?
    .ok_or("MCP fact")?;
    let mcp = Record::decode(second.request.text.as_str())?
        .captured_tool
        .ok_or("MCP metadata")?;
    assert!(matches!(mcp.outcome, Outcome::Failed));
    assert!(matches!(mcp.target, Target::Query(ref text) if text == "actual query"));
    assert_eq!(second.request.new_offset, bytes.len() as u64);
    assert_eq!(
        second.request.evidence.sha256,
        Some(Sha256::digest(&bytes[first.request.new_offset as usize..]).into())
    );
    cleanup(source)
}
