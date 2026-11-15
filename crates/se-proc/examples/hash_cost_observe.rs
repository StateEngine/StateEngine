//! Compare full-byte SHA-256 backends on one retained shipping image.
#[cfg(windows)]
#[path = "hash_cost/windows.rs"]
mod windows;

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    windows::run()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("This observation requires native Windows.");
    std::process::exit(2);
}
