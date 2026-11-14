use super::*;
use std::{error::Error, os::unix::ffi::OsStrExt, os::unix::fs::symlink};
#[path = "../../../test-support/directory.rs"]
mod directory;
fn case() -> Result<directory::PrivateDirectory, Box<dyn Error>> {
    directory::private_case_directory()
}
#[test]
fn resolve_returns_a_relative_path_unchanged() -> Result<(), Box<dyn Error>> {
    let path = Path::new("state/db.sqlite");
    assert_eq!(resolve(path)?, path);
    Ok(())
}
#[test]
fn resolve_keeps_an_unlinked_absolute_path_canonical() -> Result<(), Box<dyn Error>> {
    let root = case()?;
    let dir = root.join("a/b/c");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("state.db");
    assert_eq!(resolve(&path)?, path);
    root.finish(Ok(()) as Result<(), Box<dyn Error>>)?;
    Ok(())
}
#[test]
fn resolve_follows_a_trusted_ancestor_link() -> Result<(), Box<dyn Error>> {
    let root = case()?;
    let real = root.join("real");
    std::fs::create_dir(&real)?;
    let link = root.join("alias");
    symlink(&real, &link)?;
    let path = link.join("state.db");
    assert_eq!(resolve(&path)?, real.join("state.db"));
    root.finish(Ok(()) as Result<(), Box<dyn Error>>)?;
    Ok(())
}
#[test]
fn resolve_follows_a_chain_of_trusted_links() -> Result<(), Box<dyn Error>> {
    let root = case()?;
    let real = root.join("real");
    std::fs::create_dir(&real)?;
    std::fs::create_dir(real.join("deep"))?;
    let outer = root.join("outer");
    let inner = root.join("inner");
    symlink(&inner, &outer)?;
    symlink(&real, &inner)?;
    let path = outer.join("deep/state.db");
    assert_eq!(resolve(&path)?, real.join("deep/state.db"));
    root.finish(Ok(()) as Result<(), Box<dyn Error>>)?;
    Ok(())
}
#[test]
fn resolve_normalizes_dot_and_dotdot() -> Result<(), Box<dyn Error>> {
    let root = case()?;
    let dir = root.join("a/b/c");
    std::fs::create_dir_all(&dir)?;
    // a/b/.. lands on a, so the walk needs a/c to exist as a directory.
    std::fs::create_dir(root.join("a/c"))?;
    assert_eq!(
        resolve(&root.join("a/b/../c/db.sqlite"))?,
        root.join("a/c/db.sqlite")
    );
    assert_eq!(
        resolve(&root.join("a/./b/db.sqlite"))?,
        root.join("a/b/db.sqlite")
    );
    root.finish(Ok(()) as Result<(), Box<dyn Error>>)?;
    Ok(())
}
#[test]
fn resolve_leaves_the_final_component_unfollowed() -> Result<(), Box<dyn Error>> {
    let root = case()?;
    let real = root.join("real");
    std::fs::create_dir(&real)?;
    let link = root.join("db.sqlite");
    symlink(&real, &link)?;
    let path = root.join("db.sqlite");
    // The link keeps its name: NOFOLLOW at open time is what refuses it.
    assert_eq!(resolve(&path)?, path);
    root.finish(Ok(()) as Result<(), Box<dyn Error>>)?;
    Ok(())
}
#[test]
fn resolve_refuses_a_file_among_the_ancestors() -> Result<(), Box<dyn Error>> {
    let root = case()?;
    let file = root.join("file");
    std::fs::write(&file, b"not a directory")?;
    let path = file.join("state.db");
    let error = resolve(&path)
        .err()
        .ok_or("a file among the ancestors resolved")?;
    assert!(
        error.to_string().contains("not a directory"),
        "verdict: {error}"
    );
    root.finish(Ok(()) as Result<(), Box<dyn Error>>)?;
    Ok(())
}
#[test]
fn resolve_refuses_a_missing_ancestor() -> Result<(), Box<dyn Error>> {
    let root = case()?;
    let path = root.join("absent/state.db");
    let error = resolve(&path).err().ok_or("a missing ancestor resolved")?;
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    root.finish(Ok(()) as Result<(), Box<dyn Error>>)?;
    Ok(())
}
#[test]
fn resolve_refuses_a_symlink_loop() -> Result<(), Box<dyn Error>> {
    let root = case()?;
    let a = root.join("loop-a");
    let b = root.join("loop-b");
    symlink(&b, &a)?;
    symlink(&a, &b)?;
    let error = resolve(&a.join("state.db"))
        .err()
        .ok_or("a symlink loop resolved")?;
    assert!(
        error.to_string().contains("too many levels"),
        "verdict: {error}"
    );
    root.finish(Ok(()) as Result<(), Box<dyn Error>>)?;
    Ok(())
}
#[test]
fn resolve_refuses_a_foreign_owned_link() -> Result<(), Box<dyn Error>> {
    // SAFETY: geteuid has no pointers and no process-wide mutation.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        eprintln!("skipped: making a foreign-owned entry requires privilege (euid {euid})");
        return Ok(());
    }
    let root = case()?;
    let real = root.join("real");
    std::fs::create_dir(&real)?;
    let link = root.join("foreign");
    symlink(&real, &link)?;
    let mut cpath = link.as_os_str().as_bytes().to_vec();
    cpath.push(0);
    // SAFETY: lchown takes a NUL-terminated path; the bytes are a copy of
    // the entry name with a NUL appended, and the entry is owned by this
    // test and named for its refusal.
    if unsafe { libc::lchown(cpath.as_ptr() as *const i8, 12345u32, 12345u32) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let error = resolve(&link.join("state.db"))
        .err()
        .ok_or("a foreign-owned link resolved")?;
    assert!(
        error
            .to_string()
            .contains("untrusted or private-directory symlink"),
        "verdict: {error}"
    );
    root.finish(Ok(()) as Result<(), Box<dyn Error>>)?;
    Ok(())
}
