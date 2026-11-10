//! Socket closure is witnessed after dropping TLS and its private buffers.
use super::*;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
pub(super) struct CloseObserved<S> {
    inner: Option<S>,
    output: Arc<Output>,
}
impl<S> CloseObserved<S> {
    pub fn new(inner: S, output: Arc<Output>) -> Self {
        Self {
            inner: Some(inner),
            output,
        }
    }
}
impl<S> Drop for CloseObserved<S> {
    fn drop(&mut self) {
        self.output.invalidate();
        drop(self.inner.take());
        self.output.closed.store(true, Ordering::Release);
    }
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "remote output fenced")
}
impl<S: AsyncRead + Unpin> AsyncRead for CloseObserved<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.output.invalid.load(Ordering::Acquire) {
            return Poll::Ready(Err(closed()));
        }
        match &mut this.inner {
            Some(inner) => Pin::new(inner).poll_read(cx, buf),
            None => Poll::Ready(Err(closed())),
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for CloseObserved<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.output.invalid.load(Ordering::Acquire) {
            return Poll::Ready(Err(closed()));
        }
        match &mut this.inner {
            Some(inner) => Pin::new(inner).poll_write(cx, bytes),
            None => Poll::Ready(Err(closed())),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.output.invalid.load(Ordering::Acquire) {
            return Poll::Ready(Err(closed()));
        }
        match &mut this.inner {
            Some(inner) => Pin::new(inner).poll_flush(cx),
            None => Poll::Ready(Err(closed())),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.inner {
            Some(inner) => Pin::new(inner).poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}
