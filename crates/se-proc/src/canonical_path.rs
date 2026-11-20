//! Canonical filesystem paths that ordinary Windows consumers can also read.
use std::path::{Path, PathBuf};

/// Resolves an existing path. On Windows, prefers a plain drive or UNC path
/// only when independently resolving it gives the same canonical destination.
/// Names that require verbatim semantics keep their original representation.
/// For ancestry comparisons, resolve both sides with `std::fs::canonicalize`
/// so a verbatim-only child and its ordinary parent use the same prefix form.
pub fn canonicalize_path(path: impl AsRef<Path>) -> std::io::Result<PathBuf> {
    let canonical = std::fs::canonicalize(path)?;
    #[cfg(windows)]
    if let Some(plain) = plain_candidate(&canonical)
        && std::fs::canonicalize(&plain).is_ok_and(|resolved| resolved == canonical)
    {
        return Ok(plain);
    }
    Ok(canonical)
}

/// Whether `home` may be saved into `destination`: a home under a temp root (TMP, or the
/// Windows profile's LocalAppData\Temp) only into one under that root. Unresolved: refuse.
pub fn home_outlives(home: &Path, destination: &Path) -> bool {
    let (Some(home), Some(destination)) = (physical(home), physical(destination)) else {
        return false;
    };
    #[cfg(windows)]
    let local = std::env::var_os("LOCALAPPDATA").map(|local| PathBuf::from(local).join("Temp"));
    #[cfg(not(windows))]
    let local = None;
    let roots = std::iter::once(std::env::temp_dir()).chain(local);
    let mut roots = roots.filter_map(|root| physical(&root));
    roots.all(|root| !home.starts_with(&root) || destination.starts_with(&root))
}
/// Resolved by `std::fs::canonicalize`, or a proven-absent leaf under a resolved parent.
fn physical(path: &Path) -> Option<PathBuf> {
    match std::fs::canonicalize(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = std::fs::canonicalize(path.parent()?).ok()?;
            Some(parent.join(path.file_name()?))
        }
        resolved => resolved.ok(),
    }
}
#[cfg(windows)]
fn plain_candidate(path: &Path) -> Option<PathBuf> {
    use std::{
        ffi::OsString,
        path::{Component, Prefix},
    };
    let mut components = path.components();
    let Component::Prefix(prefix) = components.next()? else {
        return None;
    };
    let mut plain = match prefix.kind() {
        Prefix::VerbatimDisk(drive) => PathBuf::from(format!("{}:", char::from(drive))),
        Prefix::VerbatimUNC(server, share) => {
            let mut unc = OsString::from(r"\\");
            unc.push(server);
            unc.push(r"\");
            unc.push(share);
            PathBuf::from(unc)
        }
        _ => return None,
    };
    plain.push(components.as_path());
    Some(plain)
}
