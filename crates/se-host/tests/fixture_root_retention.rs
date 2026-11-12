//! A panicking fixture keeps exactly one named root for each shared fixture.
//!
//! Both halves run in a child process, because the evidence is what a panic
//! leaves behind and a panic may not be caught twice in one process.
use std::path::{Path, PathBuf};
#[path = "support/ipc_fixture.rs"]
mod fixture;
use fixture::*;

const CHILD_ENV: &str = "SE_PANIC_ROOT_CHILD";

/// Prints and then panics with the fixture still live, so its drop unwinds.
#[test]
#[ignore = "owned panic probe, run only by the retaining consumer"]
fn panic_with_fixture_live() -> Check {
    match std::env::var_os(CHILD_ENV).as_deref() {
        Some(value) if value == "store" => {
            let f = StoreFixture::new()?;
            std::fs::write(f.home.join("retained-evidence"), b"store")?;
            println!("retained-root:{}", f.home.display());
            panic!("owned store fixture panic probe");
        }
        Some(value) if value == "ipc" => {
            let home = Home::new()?;
            std::fs::write(home.0.join("retained-evidence"), b"ipc")?;
            println!("retained-root:{}", home.0.display());
            panic!("owned ipc fixture panic probe");
        }
        _ => Err("panic probe child selected without a fixture".into()),
    }
}

/// Runs the panic probe and returns the root it named.
fn probe(kind: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let output = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "panic_with_fixture_live",
            "--ignored",
            "--nocapture",
        ])
        .env(CHILD_ENV, kind)
        .output()?;
    assert!(
        !output.status.success(),
        "{kind} probe did not panic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    let mut roots = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("retained-root:"))
        .map(PathBuf::from);
    let root = roots.next().ok_or("probe named no root")?;
    assert!(roots.next().is_none(), "probe named more than one root");
    Ok(root)
}

fn assert_exactly_one_root(kind: &str, root: &Path) -> Check {
    assert!(root.is_dir(), "{kind} root was removed by its panic");
    let retained = std::fs::read_dir(root)?.collect::<Result<Vec<_>, _>>()?;
    assert!(
        !retained.is_empty(),
        "{kind} root was kept but left empty, so it proves nothing about the fixture tree"
    );
    println!("{kind} kept one root with {} entries", retained.len());
    Ok(())
}

#[test]
fn a_panicking_store_fixture_keeps_exactly_one_root() -> Check {
    let root = probe("store")?;
    let outcome = assert_exactly_one_root("store", &root);
    std::fs::remove_dir_all(&root)?;
    outcome
}

#[test]
fn a_panicking_ipc_home_keeps_exactly_one_root() -> Check {
    let root = probe("ipc")?;
    let outcome = assert_exactly_one_root("ipc", &root);
    std::fs::remove_dir_all(&root)?;
    outcome
}

/// The store fixture's `Fixture` type, used only through its public fields.
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod store_fixture;
use store_fixture::Fixture as StoreFixture;
