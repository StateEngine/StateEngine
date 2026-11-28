//! One owner-authenticated connection streams finite mail pages. Only commit
//! notifications reopen the store; transport keepalives never read SQLite.
use super::{AdmittedExchange, HostedRouter, admission::OperationMetadata};
use crate::{IpcResponse, IpcResult, OperationOutput, RawOperation, client::lease::Deadline};
use se_core::ops::{AnyOutput, MessageList};
use se_types::{Result, SeError};
use std::time::Duration;
use tokio::sync::watch;

pub(super) async fn serve(
    router: &HostedRouter,
    mut exchange: AdmittedExchange,
    mut input: MessageList,
    selections: Option<se_core::ops::CliSelections>,
    shutdown: &mut watch::Receiver<Option<Deadline>>,
) -> Result<()> {
    if input.newest {
        return Err(SeError::invalid(
            "mail follow",
            "follow streams oldest-first, so a newest-first cursor would miss mail sent after the first page; drop --follow for one-shot newest-first pages",
        ));
    }
    let selections = serde_json::to_value(&selections)
        .map_err(|error| SeError::invalid("mail follow selections", &error.to_string()))?;
    let mut commits = router.execution.mail_waits.commits.subscribe();
    let _work = router.execution.mail_waits.client_work()?;
    let mut drain = true;
    let mut initial = true;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(10));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    heartbeat.tick().await;
    loop {
        if drain {
            // Observe before the finite read, retaining any commit during it.
            commits.borrow_and_update();
            let deadline = super::serve::options(Duration::from_secs(30))?;
            let (returned, result) = page(router, exchange, &input, &selections, &deadline).await?;
            exchange = returned;
            let (output, more, display) = match result {
                Ok(output) => {
                    let AnyOutput::MessageList(page) = &output else {
                        return Err(SeError::invalid("mail follow page", "message-list output"));
                    };
                    input.cursor = Some(
                        page.value
                            .page
                            .window()
                            .fields()
                            .and_then(|fields| fields.end_cursor.clone())
                            .ok_or_else(|| {
                                SeError::invalid("mail follow page", "a resume cursor")
                            })?,
                    );
                    let more = page.value.page.next().is_some();
                    let display = initial
                        || !page.value.page.items().is_empty()
                        || !page.value.page.window().complete();
                    (
                        super::route::encode_executed(super::ExecutedCall {
                            output,
                            host_phases: Default::default(),
                            write_timings: None,
                            committed: None,
                            capture_commits: vec![],
                            capture_keys: vec![],
                        }),
                        more,
                        display,
                    )
                }
                Err(error) => {
                    send(&mut exchange, Err(error), true).await?;
                    return Ok(());
                }
            };
            if display {
                send(&mut exchange, output, false).await?;
                heartbeat.reset();
            }
            initial = false;
            drain = more;
            if drain {
                continue;
            }
        }
        tokio::select! { biased;
            _ = shutdown.changed() => return Ok(()),
            closed = exchange.wait_for_peer_close() => { closed?; return Ok(()); },
            _ = heartbeat.tick() => {
                // Lets a closed stdout/SSH pipe retire the client even while idle.
                send(&mut exchange, Ok(OperationOutput {
                    schema: "se.message-follow-idle".into(),
                    value: serde_json::json!({"cursor": input.cursor}),
                    window: None,
                }), false).await?;
            }
            changed = commits.changed() => { changed.map_err(|_| SeError::invalid("mail follow", "an open commit notifier"))?; drain = true; },
        }
    }
}

async fn page(
    router: &HostedRouter,
    exchange: AdmittedExchange,
    input: &MessageList,
    selections: &serde_json::Value,
    deadline: &Deadline,
) -> Result<(AdmittedExchange, Result<AnyOutput>)> {
    router.check_open()?;
    let owned = router.clone();
    let raw = RawOperation {
        name: "message.list".into(),
        key: None,
        arguments: serde_json::to_value(input)
            .map_err(|error| SeError::invalid("mail follow input", &error.to_string()))?,
    };
    let bound = deadline.clone();
    let selections = selections.clone();
    let (exchange, prepared) = router
        .execution
        .blocking
        .run(super::BlockingClass::Foreground, deadline, move || {
            let prepared = owned.context.with_operation(
                (
                    exchange.connection.connection.peer(),
                    exchange.connection.connection.connection_authority(),
                ),
                None,
                &exchange.connection.grant,
                raw,
                OperationMetadata {
                    selections: Some(selections),
                    presence: None,
                },
                |phase, call| {
                    super::planning::Planner::new(&owned.execution).prepare(phase, call, bound)
                },
            );
            Ok((exchange, prepared))
        })
        .await?;
    let output = match prepared {
        Ok(prepared) => prepared
            .execute(router.execution.clone(), Default::default())
            .await
            .map(|result| result.output),
        Err(error) => Err(error),
    };
    Ok((exchange, output))
}

async fn send(
    exchange: &mut AdmittedExchange,
    output: Result<OperationOutput>,
    terminal: bool,
) -> Result<()> {
    let result = match output {
        Ok(output) => IpcResult::Output(Box::new(output)),
        Err(error) => IpcResult::Error(super::route::envelope(&error)?),
    };
    let mut response = IpcResponse {
        version: se_types::API_VERSION,
        request_id: exchange.request_id,
        generation: exchange.connection.connection.negotiated().generation,
        result,
    };
    if let Err(error) = crate::client::wire::encode_response(
        &response,
        exchange
            .connection
            .connection
            .negotiated()
            .maximum_reply_bytes
            .get() as usize,
    ) {
        response.result = IpcResult::Error(super::route::envelope(&error)?);
    }
    let deadline = super::serve::options(Duration::from_secs(5))?;
    exchange
        .connection
        .connection
        .reply_part(&response, &deadline, terminal)
        .await
}

impl AdmittedExchange {
    /// Stream one bounded part of a long-lived reply with cancellation at the write boundary.
    pub(crate) async fn reply_stream_part_cancellable<F>(
        &mut self,
        output: Result<OperationOutput>,
        max_bytes: usize,
        terminal: bool,
        cancel: F,
    ) -> Result<crate::ipc::StreamWriteOutcome>
    where
        F: std::future::Future<Output = ()> + Unpin,
    {
        let result = match output {
            Ok(value) => IpcResult::Output(Box::new(value)),
            Err(error) => IpcResult::Error(super::route::envelope(&error)?),
        };
        let response = IpcResponse {
            version: se_types::API_VERSION,
            request_id: self.request_id,
            generation: self.connection.connection.negotiated().generation,
            result,
        };
        let deadline = super::serve::options(Duration::from_secs(5))?;
        self.connection
            .connection
            .reply_part_cancellable(&response, &deadline, max_bytes, terminal, cancel)
            .await
    }
}
