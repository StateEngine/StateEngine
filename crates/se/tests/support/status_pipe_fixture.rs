use std::{
    env, fs,
    io::{self, Write},
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

const HEADER: &str =
    "# branch.oid 1234567890123456789012345678901234567890\n# branch.head review\n";

fn main() {
    let home = PathBuf::from(env::var_os("STATUS_PIPE_HOME").unwrap());
    let args = env::args().collect::<Vec<_>>();
    if args.iter().any(|a| a == "--hold-open") {
        fs::write(home.join("descendant.pid"), std::process::id().to_string()).unwrap();
        std::thread::sleep(Duration::from_millis(3000));
        fs::write(home.join("descendant.closed"), b"natural exit").unwrap();
        return;
    }
    let case = env::var("STATUS_PIPE_CASE").unwrap();
    let status = args.iter().any(|a| a == "status");
    let count = args.iter().any(|a| a == "rev-list");
    assert!(status || count, "unexpected Git call: {args:?}");
    fs::write(
        home.join(if status {
            "status.started"
        } else {
            "count.started"
        }),
        std::process::id().to_string(),
    )
    .unwrap();
    if status && case != "silent-held" {
        print!("{HEADER}");
        if case == "dirty" {
            println!("? changed.txt");
        }
    }
    if count {
        println!("7");
    }
    io::stdout().flush().unwrap();
    let hold = (status && matches!(case.as_str(), "silent-held" | "header-held" | "stderr-held"))
        || (count && case == "count-held");
    if hold {
        if case == "stderr-held" {
            // Redirecting a standard handle does not remove other inheritable
            // handles from Windows CreateProcess. Remove inheritance from this
            // root's stdout writer before creating the stderr-only descendant.
            isolate_stderr();
        }
        let mut command = Command::new(env::current_exe().unwrap());
        command
            .arg("--hold-open")
            .stdin(Stdio::null())
            .stderr(Stdio::inherit());
        command.stdout(if case == "stderr-held" {
            Stdio::null()
        } else {
            Stdio::inherit()
        });
        let child = command.spawn().unwrap();
        // The observer owns only this Git root. Its finite descendant intentionally
        // retains output handles after the root has exited successfully.
        drop(child);
    }
}

// This standalone fixture is compiled by rustc, outside the product crate.
// It changes only its own stdout inheritance flag; it never closes or signals
// another process's handle.
fn isolate_stderr() {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetStdHandle(which: u32) -> *mut std::ffi::c_void;
        fn SetHandleInformation(handle: *mut std::ffi::c_void, mask: u32, flags: u32) -> i32;
    }
    // SAFETY: GetStdHandle selects this process's stdout. SetHandleInformation
    // clears only HANDLE_FLAG_INHERIT and neither transfers nor closes custody.
    unsafe {
        let stdout = GetStdHandle(-11i32 as u32);
        assert!(!stdout.is_null() && stdout as isize != -1);
        assert_ne!(SetHandleInformation(stdout, 1, 0), 0);
    }
}
