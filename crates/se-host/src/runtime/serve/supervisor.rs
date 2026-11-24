//! The serve loop's own state: accepted tasks, accept pacing and the single
//! custody catch-up. Each event either keeps serving or names how serving ends.
use super::*;
use std::time::Duration;

/// The failure and authorized stop an ended loop hands to shutdown.
pub(super) type End = (Option<SeError>, Option<Box<AuthorizedStop>>);
/// A transient accept failure retries after a doubling delay; a fatal one after a minute.
pub(super) struct Backoff {
    delay: Duration,
    pub(super) retry_at: tokio::time::Instant,
}
impl Backoff {
    fn new() -> Self {
        Self {
            delay: Duration::from_millis(1),
            retry_at: tokio::time::Instant::now(),
        }
    }
    fn transient(&mut self) {
        self.retry_at = tokio::time::Instant::now() + self.delay;
        self.delay = (self.delay * 2).min(Duration::from_millis(250));
    }
    fn fatal(&mut self) {
        self.retry_at = tokio::time::Instant::now() + Duration::from_secs(60);
    }
}
pub(super) struct Supervisor {
    router: HostedRouter,
    runtime: tokio::runtime::Handle,
    cancelled: watch::Receiver<Option<Deadline>>,
    port: u16,
    activity: Option<watch::Receiver<u32>>,
    catch_up_running: bool,
    pub(super) tasks: JoinSet<Result<ConnectionEnd>>,
    pub(super) accept: Backoff,
    pub(super) http: Backoff,
}
impl Supervisor {
    pub(super) fn new(
        router: HostedRouter,
        runtime: tokio::runtime::Handle,
        cancelled: watch::Receiver<Option<Deadline>>,
        port: u16,
        activity: Option<watch::Receiver<u32>>,
    ) -> Self {
        Self {
            router,
            runtime,
            cancelled,
            port,
            activity,
            catch_up_running: false,
            tasks: JoinSet::new(),
            accept: Backoff::new(),
            http: Backoff::new(),
        }
    }
    pub(super) fn handle(
        &mut self,
        host: &mut HostedRuntime,
        timers: &mut crate::runtime::live::Timers,
        event: Event,
    ) -> Option<End> {
        match event {
            Event::LocalStop | Event::IdleExpired => return Some((None, None)),
            Event::OwnershipFault => {
                return Some((
                    Some(se_core::scope::unreadable(
                        "writer/native collector ownership",
                        "the writer or shared collector failed; this generation is fenced and retains custody for controlled recovery",
                    )),
                    None,
                ));
            }
            Event::CatchUp => self.catch_up(host, timers),
            Event::Accepted(result) => self.accepted(host, result),
            Event::Http(result) => self.http_accepted(host, result),
            Event::Joined(joined) => return self.joined(host, joined),
        }
        None
    }
    fn catch_up(&mut self, host: &mut HostedRuntime, timers: &mut crate::runtime::live::Timers) {
        timers.catch_up = crate::runtime::live::timer(self.activity.clone());
        if let Err(error) = host.execution.mail_waits.catch_up_native() {
            host.failed_connection(error);
        }
        if !self.catch_up_running
            && let Some(custody) = host.execution.custody.get().cloned()
        {
            self.catch_up_running = true;
            self.tasks.spawn_on(
                async move {
                    let result = match options(CALL_TIMEOUT) {
                        Ok(deadline) => custody.catch_up(&deadline).await,
                        Err(error) => Err(error),
                    };
                    Ok(ConnectionEnd::CatchUp(result))
                },
                &self.runtime,
            );
        }
    }
    fn accepted(&mut self, host: &mut HostedRuntime, result: Result<crate::AcceptedIpcStream>) {
        match result {
            Ok(stream) => {
                if let Err(error) = host.execution.ownership_fault.route("IPC listener", false) {
                    host.failed_connection(error);
                }
                self.accept.delay = Duration::from_millis(1);
                let (router, cancelled) = (self.router.clone(), self.cancelled.clone());
                self.tasks
                    .spawn_on(connection(router, stream, cancelled), &self.runtime);
            }
            Err(error) if transient_accept(&error) => {
                host.failed_connection(error);
                self.accept.transient();
            }
            Err(error) => {
                host.failed_connection(error);
                if let Err(error) = host.execution.ownership_fault.route("IPC listener", true) {
                    host.failed_connection(error);
                }
                self.accept.fatal();
            }
        }
    }
    fn http_accepted(
        &mut self,
        host: &mut HostedRuntime,
        result: Result<(tokio::net::TcpStream, tokio::sync::OwnedSemaphorePermit)>,
    ) {
        match result {
            Ok((stream, permit)) => {
                if let Err(error) = host.execution.ownership_fault.route("HTTP listener", false) {
                    host.failed_connection(error);
                }
                self.http.delay = Duration::from_millis(1);
                let (router, cancelled, port) =
                    (self.router.clone(), self.cancelled.clone(), self.port);
                let served = async move {
                    crate::http::connection(router, stream, port, permit, cancelled)
                        .await
                        .map(|()| ConnectionEnd::Closed)
                };
                self.tasks.spawn_on(served, &self.runtime);
            }
            Err(error) if transient_accept(&error) => {
                host.failed_connection(error);
                self.http.transient();
            }
            Err(error) => {
                host.failed_connection(error);
                if let Err(error) = host.execution.ownership_fault.route("HTTP listener", true) {
                    host.failed_connection(error);
                }
                self.http.fatal();
            }
        }
    }
    fn joined(
        &mut self,
        host: &mut HostedRuntime,
        joined: std::result::Result<Result<ConnectionEnd>, tokio::task::JoinError>,
    ) -> Option<End> {
        match joined {
            Ok(Ok(ConnectionEnd::Stop(stop))) => return Some((None, Some(stop))),
            #[cfg(any(target_os = "linux", target_os = "macos", windows))]
            Ok(Ok(ConnectionEnd::Atlas(result))) => {
                if let Err(error) = result {
                    eprintln!("Code index owner paused: {error}");
                }
            }
            Ok(Ok(ConnectionEnd::CatchUp(result))) => {
                self.catch_up_running = false;
                if let Err(error) = result {
                    host.failed_connection(error);
                }
            }
            Ok(Ok(ConnectionEnd::Closed | ConnectionEnd::Cancelled)) => {
                #[cfg(all(target_os = "linux", target_env = "gnu"))]
                if let Some(memory) = &host.memory_reclaim {
                    memory.completed();
                }
            }
            Ok(Err(error)) => host.failed_connection(error),
            Err(error) => {
                host.failed_connection(
                    se_core::scope::unreadable("host connection task", &error.to_string())
                        .with_cause(error),
                );
                self.catch_up_running = false;
            }
        }
        None
    }
}
