//! Public catalogue, CLI and MCP presentation checks; not a live-owner witness.
use se_core::{ops::*, registry::Feature};
use se_host::{McpBackend, McpReply};
use se_types::{Result, Secret, code::*};
use serde_json::{Value, json};
use std::sync::Arc;
type Check = std::result::Result<(), Box<dyn std::error::Error>>;
#[test]
fn five_tools_and_cli_routes_share_closed_bounded_inputs() -> Check {
    let tools = mcp_tools()?;
    for name in ["find", "refs", "impact", "changes", "outline"] {
        assert!(
            tools
                .iter()
                .any(|tool| tool.name == format!("stateengine_atlas_{name}"))
        );
        let meta = CATALOGUE
            .iter()
            .find(|meta| meta.name == format!("atlas.{name}"))
            .ok_or("operation absent")?;
        assert_eq!(meta.feature, Feature::Atlas);
        assert!(!meta.mutates());
    }
    let minimal = decode_tool("stateengine_atlas_find", json!({"query":"alpha"}))?;
    let options = minimal.atlas_options().ok_or("options absent")?;
    assert_eq!(options.limit, 10);
    assert_eq!(options.byte_budget, 4096);
    assert_eq!(options.format, AtlasFormat::Compact);
    for bad in [
        json!({"query":"alpha","actor":"other"}),
        json!({"query":"alpha","byte_budget":1}),
        json!({"query":"alpha","limit":51}),
        json!({"query":"alpha","kind":"All"}),
    ] {
        assert!(decode_tool("stateengine_atlas_find", bad).is_err());
    }
    for argv in [
        vec![
            "se",
            "atlas",
            "find",
            "packet budget",
            "--kind",
            "message",
            "--mode",
            "phrase",
        ],
        vec!["se", "atlas", "refs", "alpha.rs", "--file"],
        vec![
            "se", "atlas", "impact", "alpha", "--path", "alpha.rs", "--depth", "1",
        ],
        vec!["se", "atlas", "changes", "--since", "1700000000000"],
        vec!["se", "atlas", "outline", "alpha.rs"],
    ] {
        let matches = cli_command().try_get_matches_from(argv)?;
        let operation = from_matches(&matches)?;
        operation.validate()?;
        assert!(operation.atlas_options().is_some());
    }
    let invalid =
        cli_command().try_get_matches_from(["se", "atlas", "impact", "alpha", "--depth", "4"])?;
    assert!(from_matches(&invalid).is_err());
    Ok(())
}
fn answer() -> std::result::Result<AnyOutput, Box<dyn std::error::Error>> {
    let index = IndexSummary {
        memory: None,
        project: se_types::ProjectId::from_parts(1, [1; 10])?,
        root: RootId::from_parts(1, [2; 10])?,
        epoch: Some(CacheEpoch::from_parts(1, [3; 10])?),
        generation: Some(Generation(1)),
        state: IndexState::Current,
        coverage: serde_json::from_value(
            json!({"discovered_files":0,"indexed_files":0,"partial_files":0,"deferred_files":0,"failed_files":0,"discovery_complete":true,"stale_files":0,"resolved_references":0,"name_only_references":0,"watched_directories":0,"unwatched_directories":0,"watch_discovery_complete":true,"watch_stats_started":null,"watch_activation_attempts":0,"watch_limited_activations":0,"reasons":[]}),
        )?,
    };
    Ok(AtlasFindOutput {
        answer: Answer {
            index,
            snapshot_advanced: false,
            epoch_retired: false,
            data: se_types::Read::Unknown {
                what: "fixture has no verified index".into(),
            },
        },
    }
    .into())
}
struct PresentationBackend {
    output: Value,
    calls: usize,
}
impl McpBackend for PresentationBackend {
    async fn check_session(&mut self, _: Arc<Secret>) -> Result<()> {
        Ok(())
    }
    async fn call(&mut self, _: Arc<Secret>, operation: AnyOp) -> Result<Value> {
        operation.validate()?;
        self.calls += 1;
        Ok(self.output.clone())
    }
    fn response_limit(&self) -> usize {
        32768
    }
}
#[test]
fn mcp_compact_and_json_each_have_one_honest_budgeted_representation() -> Check {
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let output = answer()?;
    assert_ne!(output.exit_code(), 0);
    let mut backend = PresentationBackend {
        output: serde_json::to_value(output)?,
        calls: 0,
    };
    for json_format in [false, true] {
        let mut arguments = json!({"query":"alpha"});
        if json_format {
            arguments["format"] = "json".into();
        }
        let request = serde_json::to_vec(
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"stateengine_atlas_find","arguments":arguments}}),
        )?;
        let McpReply::Json(reply) = runtime.block_on(se_host::mcp::dispatch(
            &request,
            Some(Arc::new(Secret::new(vec![7; 32])?)),
            &mut backend,
        )) else {
            return Err("missing reply".into());
        };
        assert!(serde_json::to_vec(&reply)?.len() <= 4096);
        let result = &reply["result"];
        assert_eq!(result["isError"], false);
        assert!(
            result.get("structuredContent").is_none(),
            "result was duplicated"
        );
        assert_eq!(result["content"].as_array().map(Vec::len), Some(1));
        let text = result["content"][0]["text"].as_str().ok_or("text absent")?;
        if json_format {
            let value: Value = serde_json::from_str(text)?;
            assert_eq!(value["schema"], "se.code-hits/v1");
            assert!(text.contains("fixture has no verified index"));
        } else {
            assert!(text.starts_with("[atlas current; anonymous cap 2000000 B; shared grammar pages unqualified; joined unqualified]"));
            assert!(text.contains("unknown: fixture has no verified index"));
        }
    }
    assert_eq!(backend.calls, 2);
    Ok(())
}
