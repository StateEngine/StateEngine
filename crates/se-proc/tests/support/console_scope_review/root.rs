//! Standalone fixture root with uncontaminated stdin, stdout and stderr.
use std::{
    ffi::c_void,
    fs::{self, File},
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, Instant},
};

static EVENT: AtomicU32 = AtomicU32::new(u32::MAX);
#[link(name = "kernel32")]
unsafe extern "system" {
    fn SetConsoleCtrlHandler(
        handler: Option<unsafe extern "system" fn(u32) -> i32>,
        add: i32,
    ) -> i32;
    fn GetConsoleWindow() -> *mut c_void;
}
#[link(name = "user32")]
unsafe extern "system" {
    fn IsWindowVisible(window: *mut c_void) -> i32;
}
unsafe extern "system" fn receive(event: u32) -> i32 {
    EVENT.store(event, Ordering::Release);
    1
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let home = PathBuf::from(std::env::var_os("BINDING_SCOPE_HOME").ok_or("fixture home missing")?);
    // SAFETY: the handler is static and only records the supplied event code.
    if unsafe { SetConsoleCtrlHandler(Some(receive), 1) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: the query returns a borrowed HWND, used only for visibility readback.
    let visible = unsafe {
        let window = GetConsoleWindow();
        !window.is_null() && IsWindowVisible(window) != 0
    };
    fs::write(
        home.join("root.visible"),
        if visible { "True" } else { "False" },
    )?;
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    assert_eq!(input, b"owned input marker");
    std::io::stdout().write_all(b"PROTOCOL-OUT:0\x00\xff\n")?;
    std::io::stdout().flush()?;
    std::io::stderr().write_all(b"PROTOCOL-ERR:0\x00\xfe\n")?;
    std::io::stderr().flush()?;

    let mut children = Vec::new();
    for (program, argument, file, label) in [
        ("powershell.exe", "-File", "tool.ps1", "powershell"),
        ("python.exe", "-B", "tool.py", "python"),
    ] {
        let mut command = Command::new(program);
        if label == "powershell" {
            command.args(["-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass"]);
        }
        let child = command
            .arg(argument)
            .arg(home.join(file))
            .current_dir(&home)
            .stdin(Stdio::null())
            .stdout(File::create(home.join(format!("{label}.stdout")))?)
            .stderr(File::create(home.join(format!("{label}.stderr")))?)
            .spawn()?;
        fs::write(home.join(format!("{label}.pid")), child.id().to_string())?;
        children.push(child);
    }
    fs::write(home.join("root.ready"), b"ready")?;
    let until = Instant::now() + Duration::from_secs(70);
    while Instant::now() < until {
        let event = EVENT.load(Ordering::Acquire);
        if event != u32::MAX {
            fs::write(home.join("root.interrupt"), event.to_string())?;
            return Ok(());
        }
        if home.join("normal-exit").is_file() {
            for child in &mut children {
                assert!(
                    child.wait()?.success(),
                    "guard tool failed its ordinary exit"
                );
            }
            return Ok(());
        }
        std::thread::park_timeout(Duration::from_millis(25));
    }
    Err("fixture root did not receive a stop condition".into())
}
