//! A real TCP MCP session cannot gain the owner's identity-label operation.
//! Typed session state establishes authentication; no provider launch is claimed.
#![cfg(any(target_os = "linux", windows))]
use se_host::*;
use se_store::*;
use serde_json::json;
#[path = "../../se-host/tests/support/wave2_host_fixture.rs"]
mod support;
use support::*;

#[test]
fn authenticated_mcp_keeps_rename_owner_only() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let (mut writer, lease) = direct(&f)?;
    let session = support::session::session()?;
    let now = now()?;
    let issued = credential(
        &session,
        "http",
        "synthetic-rename-reader",
        now + 300_000_000,
        now + 60_000_000,
    )?;
    let EventBody::CredentialIssued { credential: id, .. } = &issued else {
        return Err("credential shape".into());
    };
    let id = *id;
    writer.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("rename-mcp-fixture")?),
            vec![
                support::session::prepared(&f, &session, &f.b),
                support::session::activated(&session)?,
                issued,
                EventBody::CredentialActivated {
                    credential: id,
                    session,
                    expected: revision(1)?,
                    first_request: support::session::record()?,
                },
            ],
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
        let listener = host.listen(runtime.handle().clone(), &bound()?).await?;
        let port = host.http_port().ok_or("HTTP listener absent")?;
        let stop = host.local_stop();
        let client = async {
            let result: Check = async {
                let listed = rpc(port, "synthetic-rename-reader", "tools/list", json!({})).await?;
                let tools = listed["result"]["tools"].as_array().ok_or("tool catalogue absent")?;
                require(tools.iter().any(|t|t["name"]=="stateengine_whoami"), "positive MCP identity tool absent")?;
                require(!tools.iter().any(|t|t["name"]=="stateengine_agent_rename"), "owner rename advertised to a model session")?;
                let before = rpc(port, "synthetic-rename-reader", "tools/call", json!({"name":"stateengine_whoami","arguments":{}})).await?;
                require(before["result"]["isError"] == false, format!("positive session identity refused: {before}"))?;
                let identity = before["result"]["structuredContent"]["agent"].clone();
                require(identity["id"] == f.b.as_str() && identity["name"].is_string(), "positive session identity incomplete")?;
                let refused = rpc(port, "synthetic-rename-reader", "tools/call", json!({"name":"stateengine_agent_rename","arguments":{"agent":f.b.as_str(),"name":"Unexpected","idempotency_key":"synthetic-rename-attempt"}})).await?;
                require(refused.get("error").is_some() || refused["result"]["isError"] == true, format!("model session gained owner rename: {refused}"))?;
                let after = rpc(port, "synthetic-rename-reader", "tools/call", json!({"name":"stateengine_whoami","arguments":{}})).await?;
                require(after["result"]["isError"] == false, "identity became unavailable after refused rename")?;
                require(after["result"]["structuredContent"]["agent"] == identity, "refused MCP rename changed saved identity")?;
                Ok(())
            }.await;
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), client).await;
        let report = exit.finish(&bound()?).await;
        require(report.transport_closed && report.endpoint_retired, "listener shutdown incomplete")?;
        result
    })
}
