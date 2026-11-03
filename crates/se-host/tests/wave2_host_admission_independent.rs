//! Public runtime + real TCP judges. Typed store facts set up authority states;
//! they are not claims of native launch, readiness or C3 activation.
#![cfg(all(feature = "listener", any(target_os = "linux", windows)))]
use se_host::*;
use se_store::*;
use serde_json::json;
#[path = "support/wave2_host_fixture.rs"]
mod support;
use support::*;

/// Protects: only a live current Prepared bearer gets the retryable activation
/// refusal. Expiry, revocation, purpose and supersession are checked first.
#[test]
fn prepared_refusals_validate_authority_before_naming_activation() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let (mut d, lease) = direct(&f)?;
    let now = now()?;
    let s = session::session()?;
    let current = credential(
        &s,
        "http",
        "live-prepared",
        now + 300_000_000,
        now + 60_000_000,
    )?;
    let revoked = credential(&s, "http", "revoked", now + 300_000_000, now + 60_000_000)?;
    let EventBody::CredentialIssued {
        credential: revoked_id,
        ..
    } = revoked
    else {
        return Err("credential fixture".into());
    };
    d.append(
        f.batch(
            f.owner_project(),
            None,
            vec![
                session::prepared(&f, &s, &f.a),
                current,
                credential(
                    &s,
                    "session",
                    "wrong-purpose",
                    now + 300_000_000,
                    now + 60_000_000,
                )?,
                credential(&s, "http", "expired", now + 1_000_000, now + 1_000_000)?,
                credential(
                    &s,
                    "http",
                    "past-activation",
                    now + 300_000_000,
                    now + 1_000_000,
                )?,
                EventBody::CredentialIssued {
                    credential: revoked_id,
                    session: s.clone(),
                    purpose: "http".into(),
                    secret_sha256: {
                        use sha2::{Digest, Sha256};
                        Sha256::digest(b"revoked").into()
                    },
                    expires_at_us: now + 300_000_000,
                    activation_deadline_us: now + 60_000_000,
                    expected: Expected::Absent,
                },
                EventBody::CredentialRevoked {
                    credential: revoked_id,
                    expected: revision(1)?,
                    reason: InputText::Inline("test revocation".into()),
                },
            ],
        )?,
        &*lease,
    )?;
    d.close()?;
    drop(lease);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut host =
            HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let port = host.http_port().ok_or("published HTTP port absent")?;
        let stop = host.local_stop();
        let execution = host.execution_context();
        let client = async {
            let result: Check = async {
                let listed = rpc(port, "live-prepared", "tools/list", json!({})).await?;
                require(
                    listed["result"]["tools"]
                        .as_array()
                        .is_some_and(|tools| !tools.is_empty()),
                    format!("Prepared discovery refused: {listed}"),
                )?;
                let call = |bearer: String| async move {
                    rpc(
                        port,
                        &bearer,
                        "tools/call",
                        json!({"name":"stateengine_working_state_get","arguments":{}}),
                    )
                    .await
                };
                let live = call("live-prepared".into()).await?;
                require(
                    live["result"]["structuredContent"]["code"] == "session-not-active",
                    format!("live Prepared refusal: {live}"),
                )?;
                tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
                let mut failures = Vec::new();
                for token in ["expired", "past-activation", "revoked", "wrong-purpose"] {
                    let response = call(token.into()).await?;
                    if response["result"]["structuredContent"]["code"] != "capability-invalid" {
                        failures.push(format!("{token}: {response}"));
                    }
                }
                let successor = session::session()?;
                execution
                    .writer
                    .submit(f.batch(
                        f.owner_project(),
                        None,
                        vec![
                            session::prepared(&f, &successor, &f.a),
                            credential(
                                &successor,
                                "http",
                                "current-successor",
                                now + 300_000_000,
                                now + 60_000_000,
                            )?,
                        ],
                    )?)?
                    .await?;
                let old = call("live-prepared".into()).await?;
                if old["result"]["structuredContent"]["code"] != "capability-invalid" {
                    failures.push(format!("superseded: {old}"));
                }
                let next = call("current-successor".into()).await?;
                if next["result"]["structuredContent"]["code"] != "session-not-active" {
                    failures.push(format!("current successor: {next}"));
                }
                require(
                    failures.is_empty(),
                    format!("refusal ordering: {failures:?}"),
                )
            }
            .await;
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), client).await;
        let report = exit.finish(&bound()?).await;
        require(
            report.transport_closed && report.endpoint_retired,
            "transport cleanup pending",
        )?;
        result
    })
}

/// Protects: an unresolved earlier session fences the same agent's newer active
/// session. A different agent keeps its own valid authority through the same host.
#[test]
fn stop_unproved_fence_crosses_sessions_but_not_agent_principals() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let now = now()?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut host =
            HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        let execution = host.execution_context();
        old_stop_unproved(&f, &execution.writer).await?;
        for (agent, token) in [(&f.a, "newer-active"), (&f.b, "other-agent-active")] {
            let s = session::session()?;
            let issued = credential(&s, "http", token, now + 300_000_000, now + 60_000_000)?;
            let EventBody::CredentialIssued { credential: id, .. } = &issued else {
                return Err("credential fixture".into());
            };
            let id = *id;
            execution
                .writer
                .submit(f.batch(
                    f.owner_project(),
                    None,
                    vec![
                        session::prepared(&f, &s, agent),
                        issued,
                        session::activated(&s)?,
                        EventBody::CredentialActivated {
                            credential: id,
                            session: s,
                            expected: revision(1)?,
                            first_request: session::record()?,
                        },
                        EventBody::WorkingStateSet {
                            agent: agent.clone(),
                            text: InputText::Inline(format!("private:{token}")),
                            expected: Expected::Absent,
                        },
                    ],
                )?)?
                .await?;
        }
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let port = host.http_port().ok_or("published HTTP port absent")?;
        let stop = host.local_stop();
        let client = async {
            let result: Check = async {
                let blocked = rpc(
                    port,
                    "newer-active",
                    "tools/call",
                    json!({"name":"stateengine_working_state_get","arguments":{}}),
                )
                .await?;
                require(
                    blocked["result"]["structuredContent"]["code"] == "capability-invalid",
                    format!("new session crossed old StopUnproved fence: {blocked}"),
                )?;
                require(
                    !blocked.to_string().contains("private:newer-active"),
                    "blocked agent disclosed private state",
                )?;
                let other = rpc(
                    port,
                    "other-agent-active",
                    "tools/call",
                    json!({"name":"stateengine_working_state_get","arguments":{}}),
                )
                .await?;
                require(
                    other["result"]["isError"] == false
                        && other.to_string().contains("private:other-agent-active"),
                    format!("fence spread to another agent: {other}"),
                )
            }
            .await;
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), client).await;
        let report = exit.finish(&bound()?).await;
        require(
            report.transport_closed && report.endpoint_retired,
            "transport cleanup pending",
        )?;
        result
    })
}
