//! Host-side output bounds, release ordering and exact cleanup ownership.
use super::{
    clock::Expiry,
    custody::{Custody, Intent, Record},
    entry,
    identity::{ProcessPin, State},
    invalid, policy, process,
    protocol::{self, Frame, Launch},
    runtime::Runtime,
};
use crate::{NativeExecutablePin, NativeSourceRoot, atlas_worker::lease::Lease};
use std::{
    io::{self, Read},
    os::{
        fd::AsRawFd,
        unix::{net::UnixStream, process::ExitStatusExt},
    },
    path::Path,
    process::{Child, ExitStatus, Stdio},
    time::{Duration, Instant},
};

struct Session {
    child: Child,
    channel: UnixStream,
    git: Option<ProcessPin>,
    custody: Option<Custody>,
    intent: Option<Intent>,
    lease: Lease,
    could_have_git: bool,
    closed: bool,
}
impl Session {
    fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        // Give the living supervisor its normal cancellation/reap path first.
        if let Err(error) = self.channel.shutdown(std::net::Shutdown::Both)
            && error.raw_os_error() != Some(libc::ENOTCONN)
        {
            return Err(error);
        }
        let deadline = Instant::now() + Duration::from_millis(200);
        let graceful = Instant::now() + Duration::from_millis(50);
        while self.child.try_wait()?.is_none() && Instant::now() < graceful {
            std::thread::sleep(Duration::from_millis(1));
        }
        if let Some(git) = &self.git {
            git.terminate(deadline)?
        }
        process::reap_until(&mut self.child, deadline)?;
        if let Some(git) = &self.git {
            while git.state(deadline)? == State::Alive {
                std::thread::sleep(Duration::from_millis(1));
            }
        } else if self.could_have_git {
            return Err(invalid(
                "Git supervisor exited without its child receipt; retain creation intent and allocation",
            ));
        }
        if let Some(custody) = &self.custody {
            custody.retire(deadline)?;
            self.custody = None;
        }
        if let Some(intent) = &self.intent {
            intent.retire()?;
            self.intent = None;
        }
        self.closed = true;
        self.lease.release();
        Ok(())
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            self.lease.retain_on_failed_reap();
            eprintln!("Git tree cleanup remains unresolved: {error}");
        }
    }
}
fn drain(reader: &mut impl Read, out: &mut Vec<u8>, maximum: usize) -> io::Result<bool> {
    let mut bytes = [0; 4096];
    loop {
        match reader.read(&mut bytes) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                if count > maximum.saturating_sub(out.len()) {
                    return Err(invalid(
                        "Git bounded output overflow; lower the history window",
                    ));
                }
                out.extend_from_slice(&bytes[..count]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error),
        }
    }
}
fn receive_tree(
    session: &mut Session,
    supervisor: &ProcessPin,
    nonce: [u8; 32],
    expiry: Expiry,
) -> io::Result<ProcessPin> {
    loop {
        expiry.remaining()?;
        if process::ready(session.channel.as_raw_fd(), expiry)? {
            break;
        }
        if session.child.try_wait()?.is_some() {
            return Err(invalid(
                "Git supervisor exited before its native tree receipt",
            ));
        }
    }
    match protocol::receive(&mut session.channel, expiry)? {
        Frame::Tree {
            nonce: received,
            supervisor: claimed,
            git,
        } if received == nonce => {
            supervisor.verify(&claimed)?;
            ProcessPin::child(git.pid, supervisor.pid, expiry)?.verify(&git)?;
            Ok(git)
        }
        Frame::Refused {
            nonce: received,
            reason,
            child,
            reaped,
        } if received == nonce => Err(refused(session, supervisor, child, reaped, reason, expiry)?),
        _ => Err(invalid("Git native tree receipt is absent or mismatched")),
    }
}
/// An authenticated direct owner can report its exact child's reap even when the
/// child exited before the host received a birth receipt. Silence proves nothing.
fn refused(
    session: &mut Session,
    supervisor: &ProcessPin,
    child: Option<ProcessPin>,
    reaped: bool,
    reason: String,
    expiry: Expiry,
) -> io::Result<io::Error> {
    if reason.len() > 8192 {
        return Err(invalid("Git refusal diagnostic exceeds its bound"));
    }
    if let Some(pin) = child {
        if pin.pid == supervisor.pid
            || pin.boot != supervisor.boot
            || pin.uid != supervisor.uid
            || pin.image != supervisor.image
            || pin.digest != supervisor.digest
        {
            return Err(invalid("Git refused-child receipt differs from its helper"));
        }
        if let Some(existing) = &session.git {
            existing.verify(&pin)?;
        } else if pin.state(expiry.native_bound()?.deadline)? == State::Alive {
            ProcessPin::child(pin.pid, supervisor.pid, expiry)?.verify(&pin)?;
        }
        let alive = pin.state(expiry.native_bound()?.deadline)? == State::Alive;
        session.git = Some(pin);
        if reaped && alive {
            return Err(invalid(
                "Git owner claimed to reap a still-live native instance",
            ));
        }
    } else if reaped && session.git.is_none() {
        session.could_have_git = false;
    }
    Ok(invalid(&format!("Git contained reader refused: {reason}")))
}
struct Pipes {
    stdout: std::process::ChildStdout,
    stderr: std::process::ChildStderr,
    output: Vec<u8>,
    diagnostic: Vec<u8>,
}
impl Pipes {
    fn drain(&mut self) -> io::Result<bool> {
        let stdout = drain(
            &mut self.stdout,
            &mut self.output,
            super::super::OUTPUT_BYTES,
        )?;
        let stderr = drain(
            &mut self.stderr,
            &mut self.diagnostic,
            super::super::STDERR_BYTES,
        )?;
        Ok(stdout && stderr)
    }
    fn failure(&mut self, cause: io::Error, session: &mut Session) -> io::Error {
        let cleanup = session.close();
        let captured = self.drain();
        let mut message = cause.to_string();
        if let Err(error) = cleanup {
            message.push_str(&format!("; cleanup unresolved: {error}"));
        }
        match captured {
            Err(error) => message.push_str(&format!("; stderr/output capture failed: {error}")),
            Ok(false) => message.push_str("; output writer remains unobserved"),
            Ok(true) => (),
        }
        if !self.diagnostic.is_empty() {
            message.push_str(&format!(
                "; helper stderr: {}",
                String::from_utf8_lossy(&self.diagnostic)
            ));
        }
        io::Error::new(cause.kind(), message)
    }
}
struct Started {
    session: Session,
    supervisor: ProcessPin,
    pipes: Pipes,
}
fn authorize(
    helper: &Path,
    image: &Path,
    control: &Path,
    objects: &Path,
    roots: [&NativeSourceRoot; 2],
    arguments: Vec<String>,
    expiry: Expiry,
) -> io::Result<(Launch, Runtime)> {
    let helper = helper.canonicalize()?;
    let image = image.canonicalize()?;
    let runtime = Runtime::discover(&image, expiry)?;
    let policy = policy::build(&image, control, objects, &runtime)?;
    let host = ProcessPin::own(expiry)?;
    let mut nonce = [0; 32];
    crate::fill_entropy(&mut nonce).map_err(io::Error::other)?;
    let launch = Launch {
        schema: 1,
        nonce,
        expiry,
        host: host.clone(),
        parent: host.clone(),
        helper: se_types::NativePath::from_local(helper.clone()).map_err(io::Error::other)?,
        git: se_types::NativePath::from_local(image).map_err(io::Error::other)?,
        control: se_types::NativePath::from_local(control.to_owned()).map_err(io::Error::other)?,
        objects: se_types::NativePath::from_local(objects.to_owned()).map_err(io::Error::other)?,
        control_identity: roots[0].physical_identity()?,
        object_identity: roots[1].physical_identity()?,
        arguments,
        policy,
    };
    Ok((launch, runtime))
}
fn start(launch: &Launch, lease: Lease) -> io::Result<Started> {
    let expiry = launch.expiry;
    let helper = launch.helper.to_local().map_err(io::Error::other)?;
    let control = launch.control.to_local().map_err(io::Error::other)?;
    let invocation = NativeExecutablePin::open(&helper)
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("qualified Git supervisor helper is absent"))?
        .prepare()
        .map_err(io::Error::other)?;
    let (mut command, _creation) = invocation.command().map_err(io::Error::other)?;
    let (channel, child_channel) = UnixStream::pair()?;
    command
        .arg(entry::SUPERVISOR)
        .arg(expiry.argument())
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    process::prepare(&mut command, &child_channel, launch.host.pid)?;
    let intent = Intent::publish(&control, &launch.host, launch.nonce)?;
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            intent.retire()?;
            return Err(error);
        }
    };
    drop(child_channel);
    let mut session = Session {
        child,
        channel,
        git: None,
        custody: None,
        intent: Some(intent),
        lease,
        could_have_git: false,
        closed: false,
    };
    invocation.validate().map_err(io::Error::other)?;
    let supervisor = ProcessPin::child(session.child.id(), launch.host.pid, expiry)?;
    if supervisor.image != launch.helper {
        return Err(invalid("Git supervisor executed a different image"));
    }
    let stdout = session
        .child
        .stdout
        .take()
        .ok_or_else(|| invalid("Git stdout pipe is absent"))?;
    let stderr = session
        .child
        .stderr
        .take()
        .ok_or_else(|| invalid("Git stderr pipe is absent"))?;
    process::nonblocking(stdout.as_raw_fd())?;
    process::nonblocking(stderr.as_raw_fd())?;
    Ok(Started {
        session,
        supervisor,
        pipes: Pipes {
            stdout,
            stderr,
            output: Vec::new(),
            diagnostic: Vec::new(),
        },
    })
}
fn collect(
    session: &mut Session,
    pipes: &mut Pipes,
    nonce: [u8; 32],
    expiry: Expiry,
) -> io::Result<ExitStatus> {
    loop {
        expiry.remaining()?;
        pipes.drain()?;
        if process::ready(session.channel.as_raw_fd(), expiry)? {
            match protocol::receive(&mut session.channel, expiry)? {
                Frame::Finished {
                    nonce: received,
                    status,
                    peak_bytes,
                } if received == nonce && peak_bytes <= crate::atlas_worker::MEMORY_BYTES => {
                    return Ok(ExitStatus::from_raw(status));
                }
                Frame::Refused {
                    nonce: received,
                    reason,
                    ..
                } if received == nonce => {
                    if reason.len() > 8192 {
                        return Err(invalid("Git refusal diagnostic exceeds its bound"));
                    }
                    return Err(invalid(&format!("Git contained reader refused: {reason}")));
                }
                _ => {
                    return Err(invalid(
                        "Git final receipt is absent, mismatched or over budget",
                    ));
                }
            }
        }
        if session.child.try_wait()?.is_some() {
            return Err(invalid(
                "Git supervisor exited without its final reap receipt",
            ));
        }
    }
}
pub(super) fn read(
    helper: &Path,
    image: &Path,
    control: &Path,
    objects: &Path,
    roots: [&NativeSourceRoot; 2],
    arguments: Vec<String>,
    deadline: Instant,
) -> io::Result<super::super::GitOutput> {
    let lease = Lease::acquire()?;
    let expiry = Expiry::from_original(deadline)?;
    let (launch, runtime) = authorize(helper, image, control, objects, roots, arguments, expiry)?;
    let nonce = launch.nonce;
    let mut started = start(&launch, lease)?;
    let session = &mut started.session;
    let result = (|| {
        session.could_have_git = true;
        protocol::send(
            &mut session.channel,
            &Frame::Launch(Box::new(launch.clone())),
            expiry,
        )?;
        let git = receive_tree(session, &started.supervisor, nonce, expiry)?;
        session.git = Some(git.clone());
        let custody = Custody::publish(
            control,
            Record {
                schema: 1,
                nonce,
                control_identity: launch.control_identity,
                host: launch.host,
                supervisor: started.supervisor,
                git,
            },
        )?;
        session
            .intent
            .as_ref()
            .ok_or_else(|| invalid("Git creation intent is absent"))?
            .matches(&custody)?;
        session.custody = Some(custody);
        runtime.check()?;
        for root in roots {
            root.check()?
        }
        // Both records are durable and independently reopened before this token.
        protocol::send(&mut session.channel, &Frame::Release { nonce }, expiry)?;
        let status = collect(session, &mut started.pipes, nonce, expiry)?;
        session.close()?;
        if !started.pipes.drain()? {
            return Err(invalid(
                "Git output pipes still have an unobserved writer after tree cleanup",
            ));
        }
        runtime.check()?;
        for root in roots {
            root.check()?
        }
        Ok(status)
    })();
    match result {
        Ok(status) => Ok(super::super::GitOutput {
            status,
            stdout: started.pipes.output,
            stderr: started.pipes.diagnostic,
        }),
        Err(error) => Err(started.pipes.failure(error, session)),
    }
}
