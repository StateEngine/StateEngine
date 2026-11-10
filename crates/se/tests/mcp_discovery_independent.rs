//! Real stdio discovery must expose the same complete catalogue as HTTP.
//! Catalogue bytes are also a model-context cost, separate from transport limits.
#![cfg(any(target_os = "linux", windows))]
use se_host::*;
use se_store::*;
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::Path, process::Stdio, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[path = "../../se-host/tests/support/wave2_host_fixture.rs"]
mod support;
use support::*;

fn tool_names(reply: &Value) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let tools = reply["result"]["tools"]
        .as_array()
        .ok_or_else(|| format!("discovery did not return tools: {reply}"))?;
    let mut names = BTreeSet::new();
    for tool in tools {
        let name = tool["name"].as_str().ok_or("tool name absent")?;
        require(names.insert(name.into()), format!("duplicate tool: {name}"))?;
        require(
            tool["inputSchema"].is_object(),
            format!("schema absent: {name}"),
        )?;
    }
    require(!names.is_empty(), "empty discovery catalogue")?;
    require(
        reply["result"].get("nextCursor").is_none(),
        "unexpected partial catalogue",
    )?;
    Ok(names)
}

async fn stdio_list(home: &Path, capability: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_se"));
    command.args(["--home"]).arg(home).args(["mcp", "--stdio"]);
    for (name, _) in std::env::vars_os() {
        let text = name.to_string_lossy();
        if text.starts_with("SE_")
            || text.starts_with("STATEENGINE_")
            || text.starts_with("SECODE_")
            || matches!(text.as_ref(), "CLAUDECODE" | "CODEX_THREAD_ID" | "CODEX_CI")
        {
            command.env_remove(name);
        }
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let mut input = child.stdin.take().ok_or("stdio input absent")?;
    for request in [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2024-11-05","capabilities":{},
            "clientInfo":{"name":"synthetic-discovery-client","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{
            "_meta":{"stateengine.session-capability-v1":capability}}}),
    ] {
        input.write_all(&serde_json::to_vec(&request)?).await?;
        input.write_all(b"\n").await?;
    }
    drop(input);
    let stdout = child.stdout.take().ok_or("stdio output absent")?;
    let mut bytes = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(20),
        stdout.take(1_048_577).read_to_end(&mut bytes),
    )
    .await??;
    require(
        bytes.len() <= 1_048_576,
        "stdio output exceeded bounded frame read",
    )?;
    let status = tokio::time::timeout(Duration::from_secs(5), child.wait()).await??;
    require(status.success(), format!("stdio process failed: {status}"))?;
    let replies = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(serde_json::from_slice::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    require(
        replies.len() == 2,
        format!("unexpected stdio replies: {replies:?}"),
    )?;
    require(
        replies[0]["id"] == 1 && replies[0]["result"]["protocolVersion"].is_string(),
        format!("initialize failed: {}", replies[0]),
    )?;
    require(
        replies[1]["id"] == 2 && replies[1]["jsonrpc"] == "2.0",
        "discovery envelope mismatch",
    )?;
    Ok(replies[1].clone())
}

#[test]
fn real_stdio_client_lists_every_available_registered_tool() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let (mut writer, lease) = direct(&f)?;
    let session = support::session::session()?;
    // Canonical capability shape, entirely synthetic, and never written to output.
    let capability = format!("sec1.{session}.{}", "A".repeat(43));
    let now = now()?;
    let mut events = vec![
        EventBody::ProfileSaved {
            agent: f.b.clone(),
            profile: se_store::Profile {
                provider: Provider::Claude,
                model: None,
                permission: PermissionProfile::WorkspaceWrite,
                named_profile: "default".into(),
                effort: None,
            },
            expected: Expected::Absent,
        },
        support::session::prepared(&f, &session, &f.b),
        support::session::activated(&session)?,
    ];
    for (purpose, secret) in [
        ("session", capability.as_str()),
        ("http", "synthetic-discovery-http-reader"),
    ] {
        let issued = credential(
            &session,
            purpose,
            secret,
            now + 300_000_000,
            now + 60_000_000,
        )?;
        let EventBody::CredentialIssued { credential: id, .. } = &issued else {
            return Err("credential shape".into());
        };
        let id = *id;
        events.push(issued);
        events.push(EventBody::CredentialActivated {
            credential: id,
            session: session.clone(),
            expected: revision(1)?,
            first_request: support::session::record()?,
        });
    }
    writer.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("discovery-fixture")?),
            events,
        )?,
        &*lease,
    )?;
    writer.close()?;
    drop(lease);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    runtime.block_on(async {
        let mut host = HostedRuntime::prepare(initialized, start(&f)?, runtime.handle().clone(), &bound()?).await?;
        host.configure(se_core::config_policy::ConfigFile::default())?;
        // The Linux product installs Atlas; its complete catalogue crosses the
        // former stdio cap. Other supported targets currently expose core tools.
        #[cfg(target_os = "linux")]
        host.install_native_atlas(
            Path::new(env!("CARGO_BIN_EXE_se")).to_path_buf(),
            NativeAtlasQualification::default(),
        )?;
        let (_coordinator, reconciliation) = LaunchCoordinator::install(
            &mut host,
            ProcessOptions {
                helper_executable: se_types::NativePath::from_local(Path::new(env!("CARGO_BIN_EXE_se")).to_path_buf())?,
                linux_delegation: se_proc::LinuxDelegation::CurrentScope,
                maximum_sessions: 2,
            },
            &bound()?,
        ).await?;
        require(reconciliation.unproved.is_empty(), "fresh discovery fixture has native reconciliation debt")?;
        let listener = host.listen(runtime.handle().clone(), &bound()?).await?;
        let port = host.http_port().ok_or("HTTP listener absent")?;
        let stop = host.local_stop();
        let client = async {
            let result: Check = async {
                let http = rpc(port, "synthetic-discovery-http-reader", "tools/list", json!({})).await?;
                let http_names = tool_names(&http)?;
                let stdio = stdio_list(&f.options.state_directory, &capability).await?;
                let stdio_names = tool_names(&stdio)?;
                require(stdio_names == http_names, "stdio and HTTP advertise different tools")?;
                let atlas_available = cfg!(target_os = "linux");
                let expected = se_core::ops::CATALOGUE.iter().filter_map(|meta| {
                    if !atlas_available && meta.feature == se_core::registry::Feature::Atlas { return None; }
                    match meta.mcp { se_core::registry::McpExposure::Tool { name, .. } => Some(name.to_owned()), _ => None }
                }).collect::<BTreeSet<_>>();
                require(stdio_names == expected, format!("incomplete registered discovery: actual={stdio_names:?}, expected={expected:?}"))?;
                let bytes = serde_json::to_vec(&stdio)?.len();
                catalogue_cost(stdio_names.len(), bytes)?;
                Ok(())
            }.await;
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), client).await;
        let report = exit.finish(&bound()?).await;
        let clean = report.transport_closed && report.endpoint_retired
            && matches!(report.storage, se_types::Read::Present { .. })
            && report.pending.is_empty() && report.errors.is_empty();
        if let Err(error) = result {
            return Err(format!("{error}; shutdown complete={clean}, pending={:?}, errors={:?}", report.pending, report.errors).into());
        }
        require(clean, format!("discovery runtime shutdown incomplete: pending={:?}, errors={:?}", report.pending, report.errors))
    })
}

#[test]
fn full_tool_catalogue_context_cost_stays_visible() -> Check {
    let tools = se_core::ops::mcp_tools()?;
    let count = tools.len();
    let reply = json!({"jsonrpc":"2.0","id":2,"result":{"tools":tools}});
    let bytes = serde_json::to_vec(&reply)?.len();
    catalogue_cost(count, bytes)
}

fn catalogue_cost(count: usize, bytes: usize) -> Check {
    println!("tools/list context cost: {count} tools, {bytes} JSON-RPC bytes");
    // A review tripwire, not a transport limit or an exact snapshot. Growth past
    // this headroom requires an explicit decision about every session's context.
    assert!(
        bytes <= 65_536,
        "tools/list context cost grew to {bytes} bytes for {count} tools; review catalogue descriptions and schemas before raising the 64 KiB tripwire"
    );
    Ok(())
}
