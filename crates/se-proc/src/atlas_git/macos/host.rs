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
        self.channel.shutdown(std::net::Shutdown::Both)?;
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
        if let Some(custody) = self.custody.take() {
            custody.retire(deadline)?
        }
        if let Some(intent) = self.intent.take() {
            intent.retire()?
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
    let Frame::Tree {
        nonce: received,
        supervisor: claimed,
        git,
    } = protocol::receive(&mut session.channel, expiry)?
    else {
        return Err(invalid("Git native tree receipt is absent"));
    };
    if received != nonce {
        return Err(invalid("Git native tree receipt has a different nonce"));
    }
    supervisor.verify(&claimed)?;
    ProcessPin::child(git.pid, supervisor.pid, expiry)?.verify(&git)?;
    Ok(git)
}
struct Pipes {
    stdout: std::process::ChildStdout,
    stderr: std::process::ChildStderr,
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
        pipes: Pipes { stdout, stderr },
    })
}
fn collect(
    session: &mut Session,
    pipes: &mut Pipes,
    nonce: [u8; 32],
    expiry: Expiry,
) -> io::Result<super::super::GitOutput> {
    let (mut output, mut diagnostic) = (Vec::new(), Vec::new());
    let status = loop {
        expiry.remaining()?;
        drain(&mut pipes.stdout, &mut output, super::super::OUTPUT_BYTES)?;
        drain(
            &mut pipes.stderr,
            &mut diagnostic,
            super::super::STDERR_BYTES,
        )?;
        if process::ready(session.channel.as_raw_fd(), expiry)? {
            match protocol::receive(&mut session.channel, expiry)? {
                Frame::Finished {
                    nonce: received,
                    status,
                    peak_bytes,
                } if received == nonce && peak_bytes <= crate::atlas_worker::MEMORY_BYTES => {
                    break ExitStatus::from_raw(status);
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
    };
    Ok(super::super::GitOutput {
        status,
        stdout: output,
        stderr: diagnostic,
    })
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
    session.could_have_git = true;
    protocol::send(
        &mut session.channel,
        &Frame::Launch(Box::new(launch.clone())),
        expiry,
    )?;
    let git = receive_tree(session, &started.supervisor, nonce, expiry)?;
    session.git = Some(git.clone());
    session.custody = Some(Custody::publish(
        control,
        Record {
            schema: 1,
            nonce,
            control_identity: launch.control_identity,
            host: launch.host,
            supervisor: started.supervisor,
            git,
        },
    )?);
    runtime.check()?;
    for root in roots {
        root.check()?
    }
    // Both records are durable and independently reopened before this token.
    protocol::send(&mut session.channel, &Frame::Release { nonce }, expiry)?;
    let mut output = collect(session, &mut started.pipes, nonce, expiry)?;
    session.close()?;
    if !drain(
        &mut started.pipes.stdout,
        &mut output.stdout,
        super::super::OUTPUT_BYTES,
    )? || !drain(
        &mut started.pipes.stderr,
        &mut output.stderr,
        super::super::STDERR_BYTES,
    )? {
        return Err(invalid(
            "Git output pipes still have an unobserved writer after tree cleanup",
        ));
    }
    runtime.check()?;
    for root in roots {
        root.check()?
    }
    Ok(output)
}
