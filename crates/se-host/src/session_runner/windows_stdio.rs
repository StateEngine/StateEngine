//! Evented parent pipe ends with synchronous inherited provider streams.
use super::protocol::Bootstrap;
use crate::client::{lease::native_error, wire};
use se_proc::native_ipc::NativePipeReservation;
use se_types::{Result, SeError};
use std::{fs::File, process::Stdio};
use tokio::{
    net::windows::named_pipe::{NamedPipeServer, ServerOptions},
    process::{Child, Command},
};

pub(super) struct Spawned {
    pub child: Child,
    pub input: NamedPipeServer,
    pub stdout: NamedPipeServer,
    pub stderr: NamedPipeServer,
    pub reservations: [NativePipeReservation; 3],
}

async fn pipe(readable_by_child: bool) -> Result<(NamedPipeServer, File, NativePipeReservation)> {
    let nonce = se_proc::random_secret()
        .map_err(|error| SeError::invalid("provider stream nonce", &format!("{error:?}")))?;
    let suffix: String = nonce
        .expose()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let name = format!(r"\\.\pipe\se-provider-{suffix}");
    let reservation =
        NativePipeReservation::create(std::ffi::OsStr::new(&name)).map_err(native_error)?;
    // The occupied first instance retains the owner-only DACL. The reactor
    // owns a later overlapped instance, exactly as for authenticated local IPC.
    let server = ServerOptions::new()
        .reject_remote_clients(true)
        .in_buffer_size(65536)
        .out_buffer_size(65536)
        .create(reservation.name())
        .map_err(|error| wire::io_failure("create provider evented stream", error))?;
    use std::os::windows::io::AsHandle;
    reservation
        .verify_reactor_instance(server.as_handle())
        .map_err(native_error)?;
    let client = reservation
        .stdio_client(readable_by_child)
        .map_err(native_error)?;
    server
        .connect()
        .await
        .map_err(|error| wire::io_failure("connect provider evented stream", error))?;
    Ok((server, client, reservation))
}

pub(super) async fn spawn(plan: &Bootstrap) -> Result<Spawned> {
    let (input, child_input, input_reservation) = pipe(true).await?;
    let (stdout, child_stdout, stdout_reservation) = pipe(false).await?;
    let (stderr, child_stderr, stderr_reservation) = pipe(false).await?;
    let child = Command::new(plan.executable.to_local()?)
        .args(&plan.arguments)
        .stdin(Stdio::from(child_input))
        .stdout(Stdio::from(child_stdout))
        .stderr(Stdio::from(child_stderr))
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| wire::io_failure("start runner provider", error))?;
    Ok(Spawned {
        child,
        input,
        stdout,
        stderr,
        reservations: [input_reservation, stdout_reservation, stderr_reservation],
    })
}
