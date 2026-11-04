//! Terminal and termination signals share the ordinary host drain and join.
use super::*;
use std::{
    future::{Future, poll_fn},
    pin::pin,
    task::{Context, Poll},
};
#[cfg(unix)]
pub(super) struct Signal([tokio::signal::unix::Signal; 3]);
#[cfg(windows)]
pub(super) struct Signal {
    interrupt: tokio::signal::windows::CtrlC,
    terminate: tokio::signal::windows::CtrlBreak,
    close: tokio::signal::windows::CtrlClose,
    logoff: tokio::signal::windows::CtrlLogoff,
    shutdown: tokio::signal::windows::CtrlShutdown,
}

impl Signal {
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<()>> {
        #[cfg(unix)]
        let events = self.0.iter_mut().map(|signal| signal.poll_recv(cx));
        #[cfg(windows)]
        let events = [
            self.interrupt.poll_recv(cx),
            self.terminate.poll_recv(cx),
            self.close.poll_recv(cx),
            self.logoff.poll_recv(cx),
            self.shutdown.poll_recv(cx),
        ]
        .into_iter();
        events
            .into_iter()
            .find(Poll::is_ready)
            .unwrap_or(Poll::Pending)
    }
}

pub(super) fn listen() -> Result<Signal> {
    #[cfg(unix)]
    let result = (|| {
        use tokio::signal::unix::{SignalKind, signal};
        Ok::<_, std::io::Error>(Signal([
            signal(SignalKind::interrupt())?,
            signal(SignalKind::terminate())?,
            signal(SignalKind::hangup())?,
        ]))
    })();
    #[cfg(windows)]
    let result = (|| {
        use tokio::signal::windows;
        Ok::<_, std::io::Error>(Signal {
            interrupt: windows::ctrl_c()?,
            terminate: windows::ctrl_break()?,
            close: windows::ctrl_close()?,
            logoff: windows::ctrl_logoff()?,
            shutdown: windows::ctrl_shutdown()?,
        })
    })();
    result.map_err(|error| {
        se_core::scope::unreadable(
            "foreground termination signal registration",
            &error.to_string(),
        )
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
    let mut interrupted = pin!(poll_fn(|cx| signal.poll_recv(cx)));
    let mut received = false;
    let mut failure = None;
    let mut exit = poll_fn(|cx| {
        if !received && let Poll::Ready(event) = interrupted.as_mut().poll(cx) {
            received = true;
            if event.is_none() {
                failure = Some(se_core::scope::unreadable(
                    "foreground termination signal",
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
