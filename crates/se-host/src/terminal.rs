//! Terminal termination cancels native blocking I/O and joins its signal task.
use se_types::{Result, SeError};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub struct Signals {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<std::thread::JoinHandle<()>>,
}
pub fn listen(cancelled: Arc<AtomicBool>) -> Result<Signals> {
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let (ready, started) = std::sync::mpsc::sync_channel(1);
    let task = std::thread::Builder::new()
        .name("mail-follow-signals".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready.send(Err(error));
                    return;
                }
            };
            runtime.block_on(async move {
                let signal = signals();
                match signal {
                    Ok(signal) => {
                        let _ = ready.send(Ok(()));
                        tokio::select! {
                            _ = signal.wait() => cancelled.store(true, Ordering::Release),
                            _ = stopped => (),
                        }
                    }
                    Err(error) => {
                        let _ = ready.send(Err(error));
                    }
                }
            });
        })
        .map_err(failure)?;
    let signals = Signals {
        stop: Some(stop),
        task: Some(task),
    };
    started.recv().map_err(failure)?.map_err(failure)?;
    Ok(signals)
}
fn failure(error: impl std::fmt::Display) -> SeError {
    SeError::invalid("mail follow signals", &error.to_string())
}
impl Drop for Signals {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}
#[cfg(unix)]
struct NativeSignals([tokio::signal::unix::Signal; 3]);
#[cfg(unix)]
fn signals() -> std::io::Result<NativeSignals> {
    use tokio::signal::unix::{SignalKind, signal};
    Ok(NativeSignals([
        signal(SignalKind::interrupt())?,
        signal(SignalKind::terminate())?,
        signal(SignalKind::hangup())?,
    ]))
}
#[cfg(unix)]
impl NativeSignals {
    async fn wait(mut self) {
        std::future::poll_fn(|cx| {
            self.0
                .iter_mut()
                .map(|s| s.poll_recv(cx))
                .find(std::task::Poll::is_ready)
                .unwrap_or(std::task::Poll::Pending)
        })
        .await;
    }
}
#[cfg(windows)]
struct NativeSignals(
    tokio::signal::windows::CtrlC,
    tokio::signal::windows::CtrlBreak,
    tokio::signal::windows::CtrlClose,
);
#[cfg(windows)]
fn signals() -> std::io::Result<NativeSignals> {
    use tokio::signal::windows::*;
    Ok(NativeSignals(ctrl_c()?, ctrl_break()?, ctrl_close()?))
}
#[cfg(windows)]
impl NativeSignals {
    async fn wait(mut self) {
        tokio::select! { _ = self.0.recv() => (), _ = self.1.recv() => (), _ = self.2.recv() => () }
    }
}
