//! Native poll readiness; no fake process observations or custody implementation.
use super::*;
use std::{
    fs::File,
    os::fd::AsRawFd,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
pub struct Reactor;
struct Registration {
    stopped: Arc<AtomicBool>,
    armed: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl NativeRegistration for Registration {
    fn rearm(&self) {
        self.armed.store(true, Ordering::Release);
        if let Some(worker) = &self.worker {
            worker.thread().unpark();
        }
    }
    fn cancel(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            if let Err(e) = worker.join() {
                eprintln!("native readiness thread failed: {e:?}");
            }
        }
    }
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.cancel();
    }
}
impl NativeReactor for Reactor {
    fn register(
        &self,
        source: File,
        interest: NativeInterest,
        sink: Arc<dyn NativeReadiness>,
    ) -> ProcResult<Box<dyn NativeRegistration>> {
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        let armed = Arc::new(AtomicBool::new(true));
        let arm = armed.clone();
        let worker = std::thread::spawn(move || {
            let mut event = libc::pollfd {
                fd: source.as_raw_fd(),
                events: match interest {
                    NativeInterest::Readable => libc::POLLIN,
                    NativeInterest::Priority => libc::POLLPRI,
                },
                revents: 0,
            };
            while !stop.load(Ordering::Acquire) {
                if !arm.load(Ordering::Acquire) {
                    std::thread::park_timeout(Duration::from_millis(20));
                    continue;
                }
                // SAFETY: source retains the descriptor; event is one writable pollfd.
                let ready = unsafe { libc::poll(&mut event, 1, 20) };
                if ready != 0 && arm.swap(false, Ordering::AcqRel) && !stop.load(Ordering::Acquire)
                {
                    sink.ready();
                }
            }
        });
        Ok(Box::new(Registration {
            stopped,
            armed,
            worker: Some(worker),
        }))
    }
}
