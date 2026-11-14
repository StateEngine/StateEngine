use se_proc::NativeChildPipe;
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, ReadBuf},
    time::{Instant, Sleep, sleep},
};

pub(in crate::repository) fn stdout(pipe: tokio::process::ChildStdout) -> io::Result<Pipe> {
    Ok(Pipe::new(NativeChildPipe::new(pipe.into_owned_handle()?)))
}

pub(in crate::repository) fn stderr(pipe: tokio::process::ChildStderr) -> io::Result<Pipe> {
    Ok(Pipe::new(NativeChildPipe::new(pipe.into_owned_handle()?)))
}

/// No async read is started on the original synchronous Windows pipe. Taking
/// its handle first avoids creating a blocking task that cancellation cannot stop.
pub(in crate::repository) struct Pipe {
    native: NativeChildPipe,
    retry: Pin<Box<Sleep>>,
}

const RETRY: Duration = Duration::from_millis(5);

impl Pipe {
    fn new(native: NativeChildPipe) -> Self {
        Self {
            native,
            retry: Box::pin(sleep(RETRY)),
        }
    }
}

impl AsyncRead for Pipe {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        match self.native.read_available(buffer.initialize_unfilled()) {
            Ok(Some(count)) => {
                buffer.advance(count);
                Poll::Ready(Ok(()))
            }
            Err(error) => Poll::Ready(Err(error)),
            Ok(None) => {
                if self.retry.as_mut().poll(cx).is_ready() {
                    self.retry.as_mut().reset(Instant::now() + RETRY);
                    let _ = self.retry.as_mut().poll(cx);
                }
                Poll::Pending
            }
        }
    }
}
