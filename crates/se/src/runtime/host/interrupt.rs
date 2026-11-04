//! Foreground Ctrl-C is an event, sharing the ordinary host drain and join.
use super::*;
use std::{
    future::{Future, poll_fn},
    pin::pin,
    task::Poll,
};
#[cfg(unix)]
type Signal = tokio::signal::unix::Signal;
#[cfg(windows)]
type Signal = tokio::signal::windows::CtrlC;

pub(super) fn listen() -> Result<Signal> {
    #[cfg(unix)]
    let result = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt());
    #[cfg(windows)]
    let result = tokio::signal::windows::ctrl_c();
    result.map_err(|error| {
        se_core::scope::unreadable("foreground Ctrl-C registration", &error.to_string())
            .with_cause(error)
    })
}
pub(super) async fn serve(
    mut host: se_host::HostedRuntime,
    listener: se_host::HostedListener,
    mut signal: Signal,
) -> se_host::HostServeExit {
    let stop = host.local_stop();
    let mut serving = pin!(host.serve(listener));
    let mut interrupted = pin!(signal.recv());
    let mut received = false;
    let mut failure = None;
    let mut exit = poll_fn(|cx| {
        if !received && let Poll::Ready(event) = interrupted.as_mut().poll(cx) {
            received = true;
            if event.is_none() {
                failure = Some(se_core::scope::unreadable(
                    "foreground Ctrl-C",
                    "the registered native event stream closed",
                ));
            }
            stop.request();
        }
        serving.as_mut().poll(cx)
    })
    .await;
    if let Some(error) = failure {
        exit.failure = Some(match exit.failure.take() {
            Some(original) => original.with_cause(error),
            None => error,
        });
    }
    exit
}
