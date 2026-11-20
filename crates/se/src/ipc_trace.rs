//! Temporary IPC measurement markers written only for public sends.
use std::{cell::Cell, ffi::OsString};

#[repr(usize)]
pub enum Point {
    Enter,
    FileOwner,
    Bootstrap,
    PhaseOpened,
    CallerObserved,
    ProjectSelected,
    RestoreStart,
    RestoreEnd,
    ConnectStart,
    ConnectEnd,
    ExchangeStart,
    ExchangeEnd,
    MainDone,
}

const POINTS: usize = Point::MainDone as usize + 1;

thread_local! {
    static TIMES: Cell<[u64; POINTS]> = const { Cell::new([0; POINTS]) };
}

pub struct Trace(bool);

impl Trace {
    pub fn start(args: &[OsString], entered: Option<u64>) -> Self {
        let active = std::env::var_os("IPC_PHASE_TRACE").is_some()
            && args.get(1).is_some_and(|arg| arg == "msg")
            && args.get(2).is_some_and(|arg| arg == "send");
        if active {
            TIMES.set({
                let mut times = [0; POINTS];
                times[Point::Enter as usize] = entered.unwrap_or_default();
                times
            });
        }
        Self(active)
    }
}

pub fn stamp(point: Point) {
    let mut times = TIMES.get();
    if times[Point::Enter as usize] != 0 {
        times[point as usize] = se_proc::monotonic_micros().unwrap_or_default();
        TIMES.set(times);
    }
}

impl Drop for Trace {
    fn drop(&mut self) {
        if self.0 {
            stamp(Point::MainDone);
            #[cfg(any(target_os = "linux", windows, target_os = "macos"))]
            let cpu = se_proc::atlas_worker::current_cpu_time()
                .ok()
                .and_then(|time| u64::try_from(time.as_micros()).ok());
            #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
            let cpu: Option<u64> = None;
            eprintln!(
                "IPC_CLI {:?} {}",
                TIMES.get(),
                cpu.map_or(-1, |value| value as i64)
            );
            #[cfg(windows)]
            if let Ok((user, kernel, thread)) =
                se_proc::atlas_worker::current_cpu_parts_and_thread()
            {
                eprintln!("IPC_CPU {thread} {user} {kernel}");
            }
        }
    }
}
