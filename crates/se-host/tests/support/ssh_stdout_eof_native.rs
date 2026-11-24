//! Native fixture for qualifying the closed-stdout deadline refusal.
//!
//! Client mode writes its pid to a marker, writes five stdout bytes and four
//! stderr bytes, closes both standard handles, and stays alive. It spawns no
//! children, so its own handles are the only write ends; closing them is what
//! an independent reader must witness as EOF, not a call assumed to be one.
//! Census mode opens one pid from a separate process and reports whether that
//! exact child is still running: a terminated child is gone once it stops,
//! even while its process object outlives termination on a loaded machine.
use std::io::Write;

unsafe extern "system" {
    fn CloseHandle(handle: isize) -> i32;
    fn GetExitCodeProcess(hprocess: isize, lpxitcode: *mut u32) -> i32;
    fn GetStdHandle(nstdhandle: i32) -> isize;
    fn OpenProcess(dwdesiredaccess: u32, binherithandle: i32, dwprocessid: u32) -> isize;
    fn GetLastError() -> u32;
}

const STD_OUTPUT_HANDLE: i32 = -11;
const STD_ERROR_HANDLE: i32 = -12;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const PROCESS_SYNCHRONIZE: u32 = 0x0010;
const ERROR_INVALID_PARAMETER: u32 = 87;
/// A live process reports this exit code until it terminates.
const STILL_ACTIVE: u32 = 0x103;

fn main() -> std::process::ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if args.iter().any(|arg| arg == "--census") {
        return census(&args);
    }
    client(&args)
}

fn client(args: &[std::ffi::OsString]) -> std::process::ExitCode {
    let marker = match args.last() {
        Some(marker) => marker,
        None => return std::process::ExitCode::from(3),
    };
    if std::fs::write(marker, std::process::id().to_string()).is_err() {
        return std::process::ExitCode::from(4);
    }
    let mut out = std::io::stdout().lock();
    if out.write_all(b"hello").is_err() || out.flush().is_err() {
        return std::process::ExitCode::from(5);
    }
    drop(out);
    let mut err = std::io::stderr().lock();
    if err.write_all(b"err\n").is_err() || err.flush().is_err() {
        return std::process::ExitCode::from(6);
    }
    drop(err);
    close_standard_handles();
    // Stay alive after closing the pipes; the owner must kill this process.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn close_standard_handles() {
    // SAFETY: standard-handle selectors are native constants; no state is read.
    let out = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    let err = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
    if out > 0 {
        // SAFETY: the raw standard handle is owned by this process; closing it
        // is the fixture's whole point, so no later write is attempted.
        unsafe { CloseHandle(out) };
    }
    if err > 0 {
        // SAFETY: the raw standard handle is owned by this process.
        unsafe { CloseHandle(err) };
    }
}

fn census(args: &[std::ffi::OsString]) -> std::process::ExitCode {
    let pid = match arg_after(args, "--census") {
        Some(text) => match text.parse::<u32>() {
            Ok(pid) => pid,
            Err(_) => return std::process::ExitCode::from(3),
        },
        None => return std::process::ExitCode::from(3),
    };
    // SAFETY: a numeric pid selector with query/synchronize rights only; no
    // mutation and no inheritance.
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if handle == -1 {
        // SAFETY: GetLastError reads this thread's immediately preceding
        // OpenProcess failure, with no intervening native call.
        let code = unsafe { GetLastError() };
        return if code == ERROR_INVALID_PARAMETER {
            // The exact child is absent.
            std::process::ExitCode::from(0)
        } else {
            std::process::ExitCode::from(2)
        };
    }
    if handle == 0 {
        return std::process::ExitCode::from(2);
    }
    let mut exit_code = 0u32;
    // SAFETY: a live process handle from the OpenProcess above; the query is
    // read-only and the exit-code buffer is owned by this call.
    let queried = unsafe { GetExitCodeProcess(handle, &mut exit_code) };
    unsafe { CloseHandle(handle) };
    if queried == 0 {
        return std::process::ExitCode::from(2);
    }
    if exit_code == STILL_ACTIVE {
        // The exact child is still running.
        std::process::ExitCode::from(1)
    } else {
        // Terminated: once the child stops, cleanup is done, even while its
        // process object lingers for teardown on a loaded machine.
        std::process::ExitCode::from(0)
    }
}

fn arg_after(args: &[std::ffi::OsString], flag: &str) -> Option<String> {
    let mut seen = false;
    for arg in args {
        if seen {
            return Some(arg.to_string_lossy().into_owned());
        }
        if arg == flag {
            seen = true;
        }
    }
    None
}
