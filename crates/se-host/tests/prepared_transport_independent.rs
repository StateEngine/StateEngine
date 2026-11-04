//! Real TCP and native IPC verify possession; typed session facts do not claim C3.
#![cfg(all(feature = "listener", target_os = "linux"))]
use se_host::{
    client::{BlockingIpcClient, lease::ClientCredential},
    *,
};
use se_store::WriterClient;
use se_types::Secret;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    future::{Future, poll_fn},
    task::Poll,
    time::Duration,
};
#[path = "support/wave2_host_fixture.rs"]
mod support;
use support::*;

async fn native(endpoint: EndpointRecord) -> Result<String, Box<dyn std::error::Error>> {
    Ok(tokio::task::spawn_blocking(move || {
        let result = BlockingIpcClient::connect_authenticated(
            &endpoint,
            ClientCredential::Session(
                Secret::new(b"prepared-native".to_vec()).map_err(|e| e.to_string())?,
            ),
            positive(1024 * 1024).map_err(|e| e.to_string())?,
            &options(),
        );
        match result {
            Ok(_) => Err("Prepared native operation was admitted".to_string()),
            Err(error) => Ok(error.to_string()),
        }
    })
    .await??)
}
fn check(fenced: bool) -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut host =
            HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        let proofs = PreparedRequestProofs::new(2);
        host.install_prepared_request_proofs(proofs.clone())?;
        require(
            host.install_prepared_request_proofs(proofs.clone())
                .is_err(),
            "duplicate proof registry accepted",
        )?;
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let endpoint = listener.endpoint().clone();
        let port = host.http_port().ok_or("HTTP port absent")?;
        let stop = host.local_stop();
        let execution = host.execution_context();
        let client = async {
            let result: Check = async {
                if fenced {
                    old_stop_unproved(&f, &execution.writer).await?;
                }
                let s = session::session()?;
                let now = now()?;
                execution
                    .writer
                    .submit(f.batch(
                        f.owner_project(),
                        Some(fixture::request(&format!(
                            "fixture-prepared_transport_independent-69-{}",
                            serial()
                        ))?),
                        vec![
                            session::prepared(&f, &s, &f.a),
                            credential(
                                &s,
                                "http",
                                "prepared-http",
                                now + 300_000_000,
                                now + 60_000_000,
                            )?,
                            credential(
                                &s,
                                "session",
                                "prepared-native",
                                now + 300_000_000,
                                now + 60_000_000,
                            )?,
                        ],
                    )?)?
                    .await?;
                proofs.register(
                    s.clone(),
                    1,
                    Sha256::digest(b"prepared-native").into(),
                    Sha256::digest(b"prepared-http").into(),
                )?;
                let listed = rpc(port, "prepared-http", "tools/list", json!({})).await?;
                require(
                    listed["result"]["tools"]
                        .as_array()
                        .is_some_and(|x| !x.is_empty()),
                    format!("Prepared discovery: {listed}"),
                )?;
                let deadline = bound()?;
                let mut waiting = Box::pin(proofs.wait(&s, &deadline));
                require(
                    poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx).is_pending())).await,
                    "one purpose completed first-use proofs",
                )?;
                drop(waiting);
                let refused = native(endpoint.clone()).await?;
                if fenced {
                    let mut short = options();
                    short.timeout = Duration::from_millis(80);
                    require(
                        proofs
                            .wait(&s, &se_host::client::lease::Deadline::from_options(&short)?)
                            .await
                            .is_err(),
                        "StopUnproved discovery granted readiness",
                    )?;
                    require(
                        refused.contains("stop") || refused.contains("Stop"),
                        format!("fence reason lost: {refused}"),
                    )?;
                } else {
                    let first = proofs.wait(&s, &bound()?).await?;
                    require(
                        first.http_request != first.session_request,
                        "request identities were conflated",
                    )?;
                    require(
                        refused.contains("active") || refused.contains("Active"),
                        format!("native refusal lost activation reason: {refused}"),
                    )?;
                    rpc(port, "prepared-http", "tools/list", json!({})).await?;
                    native(endpoint).await?;
                    let repeated = proofs.wait(&s, &bound()?).await?;
                    require(
                        first.http_request == repeated.http_request
                            && first.session_request == repeated.session_request,
                        "transport replay replaced first request identities",
                    )?;
                    let call = rpc(
                        port,
                        "prepared-http",
                        "tools/call",
                        json!({"name":"stateengine_working_state_get","arguments":{}}),
                    )
                    .await?;
                    require(
                        call["result"]["structuredContent"]["code"] == "session-not-active",
                        format!("possession invented C3: {call}"),
                    )?;
                }
                Ok(())
            }
            .await;
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), client).await;
        let report = exit.finish(&bound()?).await;
        require(
            report.transport_closed && report.endpoint_retired,
            "host transport cleanup incomplete",
        )?;
        result
    })
}
#[test]
fn real_verifiers_publish_both_first_requests_without_admitting_prepared_operations() -> Check {
    check(false)
}
#[test]
fn earlier_unproved_stop_prevents_real_discovery_from_completing_proofs() -> Check {
    check(true)
}
