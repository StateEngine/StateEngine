//! Bounded handshake I/O and a deadline observer around the standard WS parser.
//! The observer never accepts/decodes a message: tungstenite owns validation.
use super::{REMOTE_FRAME_BYTES, REMOTE_PREAUTH_BYTES};
use std::future::Future;
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep},
};

#[derive(Default)]
pub struct Controls {
    authenticated: AtomicBool,
    framing: AtomicBool,
    handshake_bytes: AtomicUsize,
}
impl Controls {
    pub fn authenticated(&self) {
        self.authenticated.store(true, Ordering::Release);
    }
    pub fn framing(&self) {
        self.framing.store(true, Ordering::Release);
    }
    fn remaining(&self) -> usize {
        if self.authenticated.load(Ordering::Acquire) {
            usize::MAX
        } else {
            REMOTE_PREAUTH_BYTES.saturating_sub(self.handshake_bytes.load(Ordering::Relaxed))
        }
    }
    fn count(&self, count: usize) {
        if !self.authenticated.load(Ordering::Acquire) {
            self.handshake_bytes.fetch_add(count, Ordering::Relaxed);
        }
    }
}
fn limit_error() -> io::Error {
    io::Error::other("remote pre-authentication aggregate byte limit")
}
pub struct BudgetIo<S> {
    inner: S,
    controls: Arc<Controls>,
}
impl<S> BudgetIo<S> {
    pub fn new(inner: S, controls: Arc<Controls>) -> Self {
        Self { inner, controls }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for BudgetIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let count = buf.remaining().min(this.controls.remaining()).min(8192);
        if count == 0 {
            return Poll::Ready(Err(limit_error()));
        }
        let mut storage = [0u8; 8192];
        let mut limited = ReadBuf::new(&mut storage[..count]);
        match Pin::new(&mut this.inner).poll_read(cx, &mut limited) {
            Poll::Ready(Ok(())) => {
                this.controls.count(limited.filled().len());
                buf.put_slice(limited.filled());
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for BudgetIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let count = bytes.len().min(this.controls.remaining());
        if count == 0 && !bytes.is_empty() {
            return Poll::Ready(Err(limit_error()));
        }
        match Pin::new(&mut this.inner).poll_write(cx, &bytes[..count]) {
            Poll::Ready(Ok(count)) => {
                this.controls.count(count);
                Poll::Ready(Ok(count))
            }
            other => other,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub struct FramedIo<S> {
    inner: S,
    controls: Arc<Controls>,
    observer: Observer,
}
impl<S> FramedIo<S> {
    pub fn new(inner: S, controls: Arc<Controls>) -> Self {
        Self {
            inner,
            controls,
            observer: Observer::default(),
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for FramedIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let framing = this.controls.framing.load(Ordering::Acquire);
        if framing && this.observer.expired(cx) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "remote partial-frame deadline",
            )));
        }
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if framing {
                    this.observer.observe(&buf.filled()[before..])?;
                    this.observer.arm(cx);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for FramedIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[derive(Default)]
struct Observer {
    header: [u8; 14],
    used: usize,
    needed: usize,
    remaining: u64,
    data: bool,
    final_fragment: bool,
    frame_until: Option<Instant>,
    message_until: Option<Instant>,
    timer: Option<Pin<Box<Sleep>>>,
}
impl Observer {
    fn deadline(&self) -> Option<Instant> {
        match (self.frame_until, self.message_until) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
    fn arm(&mut self, cx: &mut Context<'_>) {
        match self.deadline() {
            Some(until) => {
                if let Some(timer) = &mut self.timer {
                    timer.as_mut().reset(until);
                } else {
                    self.timer = Some(Box::pin(tokio::time::sleep_until(until)));
                }
                if let Some(timer) = &mut self.timer {
                    let _ = timer.as_mut().poll(cx);
                }
            }
            None => self.timer = None,
        }
    }
    fn expired(&mut self, cx: &mut Context<'_>) -> bool {
        self.timer
            .as_mut()
            .is_some_and(|timer| timer.as_mut().poll(cx).is_ready())
    }
    fn finish(&mut self) {
        if self.data && self.final_fragment {
            self.message_until = None;
        }
        self.frame_until = None;
        self.used = 0;
        self.needed = 0;
    }
    fn observe(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            if self.remaining != 0 {
                let take = bytes.len().min(self.remaining as usize);
                self.remaining -= take as u64;
                bytes = &bytes[take..];
                if self.remaining == 0 {
                    self.finish();
                }
                continue;
            }
            if self.used == 0 {
                let until = Instant::now() + Duration::from_secs(5);
                self.frame_until = Some(until);
                self.data = bytes[0] & 0x08 == 0;
                self.final_fragment = bytes[0] & 0x80 != 0;
                if self.data && self.message_until.is_none() {
                    self.message_until = Some(until);
                }
                self.needed = 2;
            }
            let take = bytes.len().min(self.needed - self.used);
            self.header[self.used..self.used + take].copy_from_slice(&bytes[..take]);
            self.used += take;
            bytes = &bytes[take..];
            if self.used != self.needed {
                continue;
            }
            let short = self.header[1] & 0x7f;
            let extended = match short {
                126 => 2,
                127 => 8,
                _ => 0,
            };
            let header_len = 2 + extended + if self.header[1] & 0x80 != 0 { 4 } else { 0 };
            if self.needed != header_len {
                self.needed = header_len;
                continue;
            }
            self.remaining = match short {
                126 => u16::from_be_bytes([self.header[2], self.header[3]]) as u64,
                127 => u64::from_be_bytes(
                    self.header[2..10]
                        .try_into()
                        .map_err(|_| io::Error::other("remote frame header"))?,
                ),
                n => n as u64,
            };
            if self.remaining > REMOTE_FRAME_BYTES as u64 {
                return Err(io::Error::other("remote frame byte limit"));
            }
            if self.remaining == 0 {
                self.finish();
            }
        }
        Ok(())
    }
}
