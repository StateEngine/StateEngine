//! Finite macOS Git reader with a deny-default native filesystem boundary.
use super::*;
mod clock;
mod custody;
mod entry;
mod host;
mod identity;
mod macho;
mod policy;
mod process;
mod protocol;
mod runtime;

/// Dispatch before configuration or environment-derived work in a native helper.
pub fn private_entry(args: &[std::ffi::OsString]) -> Option<io::Result<()>> {
    entry::private_entry(args)
}
/// The caller explicitly supplies the native helper containing private_entry.
/// Embedders must not substitute their embedding executable implicitly.
pub fn read_with_helper(
    helper: &Path,
    image: &Path,
    control: &Path,
    objects: &Path,
    command: GitRead<'_>,
    deadline: Instant,
) -> io::Result<GitOutput> {
    let control_root = crate::NativeSourceRoot::open(control)?;
    let object_root = crate::NativeSourceRoot::open(objects)?;
    read_pinned(
        helper,
        image,
        control,
        objects,
        [&control_root, &object_root],
        command,
        deadline,
    )
}
pub(super) fn read_pinned(
    helper: &Path,
    image: &Path,
    control: &Path,
    objects: &Path,
    roots: [&crate::NativeSourceRoot; 2],
    command: GitRead<'_>,
    deadline: Instant,
) -> io::Result<GitOutput> {
    if [helper, image, control, objects]
        .into_iter()
        .any(|p| !p.is_absolute())
    {
        return Err(invalid(
            "absolute qualified Git helper, image and root paths required",
        ));
    }
    clock::Expiry::from_original(deadline)?;
    host::read(
        helper,
        image,
        control,
        objects,
        roots,
        command.arguments()?,
        deadline,
    )
}
/// A replacement host calls this before admitting any cold parser or Git phase.
/// Unknown custody is a refusal; filenames alone grant no signalling authority.
pub fn reconcile_pending(parent: &Path) -> io::Result<()> {
    crate::NativeStateFiles::open(parent).map_err(io::Error::other)?;
    let parent_pin = crate::NativeSourceRoot::open(parent)?;
    for (index, entry) in std::fs::read_dir(parent)?.enumerate() {
        if index >= 4096 {
            return Err(invalid(
                "cold recovery directory exceeds its inventory bound",
            ));
        }
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(".se-atlas-git-") {
            continue;
        }
        if !entry.file_type()?.is_dir() {
            return Err(invalid("Git recovery control is not a physical directory"));
        }
        let control = entry.path();
        crate::NativeStateFiles::open(&control).map_err(io::Error::other)?;
        let intent = custody::Intent::open(&control)?;
        if let Some(record) = custody::Custody::open(&control)? {
            let intent = intent.ok_or_else(|| invalid("Git custody has no creation intent"))?;
            intent.matches(&record)?;
            record.reconcile()?;
            intent.retire()?;
        } else if intent.is_some() {
            return Err(invalid(
                "Git creation intent has no complete native child receipt; allocation remains unresolved",
            ));
        }
        super::control::Control::recover(&control)?;
        parent_pin.check()?;
    }
    parent_pin.check()
}
