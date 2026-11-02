use std::{fs, path::PathBuf, process::Command};
pub type Check = Result<(), Box<dyn std::error::Error>>;
pub struct Home(pub PathBuf);
impl Home {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "se-entropy-fill-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        drop(se_proc::NativeStateFiles::create(&path)?);
        Ok(Self(path))
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("owned entropy judge cleanup: {error}");
        }
    }
}
pub fn run_child(name: &str) -> Check {
    let home = Home::new()?;
    let library = home.0.join("fault.so");
    let output = Command::new("cc")
        .args(["-shared", "-fPIC", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(&library)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/entropy_fill_fault.c"
        ))
        .arg("-ldl")
        .output()?;
    assert!(
        output.status.success(),
        "fault fixture compile: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            name,
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ])
        .env("LD_PRELOAD", &library)
        .output()?;
    assert!(
        output.status.success(),
        "native entropy child {} failed: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
pub fn arm(count: usize) -> Check {
    // SAFETY: the child loads our process-bound fixture with LD_PRELOAD; the
    // exact exported C function has this signature and remains loaded until exit.
    let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"se_entropy_fault_arm".as_ptr()) };
    if symbol.is_null() {
        return Err("entropy fault interposer is not loaded".into());
    }
    // SAFETY: the checked symbol is se_entropy_fault_arm(size_t) in our fixture.
    let call: unsafe extern "C" fn(usize) = unsafe { std::mem::transmute(symbol) };
    // SAFETY: this child has one test thread, and count is the intended native request size.
    unsafe { call(count) };
    Ok(())
}
pub fn assert_partial_then_eio() -> Check {
    // SAFETY: the exact exported fixture function remains loaded for the child lifetime.
    let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"se_entropy_fault_phase".as_ptr()) };
    if symbol.is_null() {
        return Err("entropy fault phase observer absent".into());
    }
    // SAFETY: the checked symbol is se_entropy_fault_phase(void) in our fixture.
    let call: unsafe extern "C" fn() -> libc::c_int = unsafe { std::mem::transmute(symbol) };
    assert_eq!(
        // SAFETY: this reads the fixture state after the synchronous native calls have completed.
        unsafe { call() },
        2,
        "partial fill/EIO native calls were not both observed"
    );
    Ok(())
}
