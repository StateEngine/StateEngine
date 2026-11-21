use se_proc::native_ipc::NativePipeReservation;
use std::{
    fs::File,
    io,
    os::windows::io::AsHandle,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::windows::named_pipe::{NamedPipeServer, ServerOptions},
};

pub struct Pipe {
    stream: NamedPipeServer,
    // Drop the reactor instance before releasing its protected name.
    _reservation: NativePipeReservation,
}

pub(super) async fn pipe(readable_by_child: bool) -> io::Result<(Pipe, File)> {
    let nonce = se_proc::random_secret().map_err(|error| io::Error::other(format!("{error:?}")))?;
    let suffix: String = nonce
        .expose()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let name = format!(r"\\.\pipe\se-child-{suffix}");
    let native_error = |error| io::Error::other(format!("{error}"));
    let reservation =
        NativePipeReservation::create(std::ffi::OsStr::new(&name)).map_err(native_error)?;
    // The occupied first instance retains the owner-only DACL. Later instances
    // use the same protected name, as the native IPC listener does.
    let stream = ServerOptions::new()
        .reject_remote_clients(true)
        .in_buffer_size(65536)
        .out_buffer_size(65536)
        .create(reservation.name())?;
    reservation
        .verify_reactor_instance(stream.as_handle())
        .map_err(native_error)?;
    let child = reservation
        .stdio_client(readable_by_child)
        .map_err(native_error)?;
    stream.connect().await?;
    Ok((
        Pipe {
            stream,
            _reservation: reservation,
        },
        child,
    ))
}

impl AsyncRead for Pipe {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for Pipe {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
