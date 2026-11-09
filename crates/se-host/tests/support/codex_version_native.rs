//! A native version-only fixture. Never reads provider homes or account state.
use std::{fs::OpenOptions, io::Write};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args();
    let selected = args.next().ok_or("selected invocation absent")?;
    if args.next().as_deref() != Some("--version") {
        return Err("only a version probe is admitted by this fixture".into());
    }
    let image = std::env::current_exe()?;
    let root = image.parent().ok_or("image parent absent")?;
    writeln!(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("version-children.log"))?,
        "{}",
        std::process::id()
    )?;
    if root.join("probe-fails").exists() {
        std::process::exit(7);
    }
    let name = std::path::Path::new(&selected)
        .file_name()
        .ok_or("selected name absent")?;
    let version = if name.to_string_lossy().starts_with("unsupported-alias") {
        "codex-cli 0.151.0"
    } else {
        "codex-cli 0.152.0"
    };
    println!("{}", std::hint::black_box(version));
    Ok(())
}
