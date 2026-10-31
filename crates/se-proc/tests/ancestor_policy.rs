//! Actual native account/group and filesystem consumer; serial because umask is process-wide.
#[cfg(target_os = "linux")]
mod linux {
    use se_proc::{NativeStateFiles, StateFileErrorCode};
    use std::{
        fs,
        io::Write,
        os::unix::fs::{MetadataExt, PermissionsExt, chown},
        path::PathBuf,
    };
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    type Case = (&'static str, fn() -> Result);
    struct Fixture {
        root: PathBuf,
        parent: PathBuf,
    }
    impl Fixture {
        fn new(mode: u32, group: Option<u32>) -> Result<Self> {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
            let root = std::env::temp_dir().join(format!(
                "se-ancestor-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::create_dir(&root)?;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
            let parent = root.join("existing-ancestor");
            fs::create_dir(&parent)?;
            if let Some(group) = group {
                chown(&parent, None, Some(group))?;
            }
            fs::set_permissions(&parent, fs::Permissions::from_mode(mode))?;
            Ok(Self { root, parent })
        }
        fn accepted(&self, expected_mode: u32) -> Result {
            let state = self.parent.join("state");
            let files = NativeStateFiles::create(&state)?;
            assert_eq!(
                fs::metadata(&self.parent)?.mode() & 0o7777,
                expected_mode,
                "preexisting ancestor permissions changed"
            );
            assert_eq!(fs::metadata(&state)?.mode() & 0o777, 0o700);
            let mut staged = files.create_staging(&state)?;
            staged.file.write_all(b"native guarded publication")?;
            staged.file.sync_all()?;
            assert_eq!(staged.file.metadata()?.mode() & 0o777, 0o600);
            drop(staged.file);
            let path = state.join("reader-probe");
            files.publish_no_replace(&staged.path, &path)?;
            drop(files);
            let reopened = NativeStateFiles::open(&state)?;
            let mut reader = reopened.readback(&path)?.ok_or("native readback absent")?;
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut reader, &mut bytes)?;
            assert_eq!(bytes, b"native guarded publication");
            Ok(())
        }
        fn refused(&self, reason: &str) -> Result {
            let state = self.parent.join("state");
            let failure = match NativeStateFiles::create(&state) {
                Ok(_) => return Err("unsafe ancestor accepted".into()),
                Err(error) => error,
            };
            assert_eq!(failure.code, StateFileErrorCode::LocationUnsafe);
            assert_eq!(
                failure.path, self.parent,
                "refusal must name the offending ancestor"
            );
            assert!(failure.to_string().contains(reason), "{failure}");
            assert!(!state.exists(), "unsafe ancestor was used before refusal");
            Ok(())
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    struct Umask(libc::mode_t);
    impl Drop for Umask {
        fn drop(&mut self) {
            // SAFETY: custom entry is serial; restore only its own process mask.
            unsafe {
                libc::umask(self.0);
            }
        }
    }
    fn under_umask(mask: libc::mode_t, run: impl FnOnce() -> Result) -> Result {
        // SAFETY: custom entry has no workers or parallel test harness.
        let original = unsafe { libc::umask(mask) };
        let _restore = Umask(original);
        run()
    }
    fn foreign_group() -> Result<u32> {
        // SAFETY: immutable count query for this actual process's groups.
        let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        if count < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut groups = vec![0; count as usize];
        // SAFETY: writable group array has the exact native-reported capacity.
        if unsafe { libc::getgroups(count, groups.as_mut_ptr()) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: immutable actual primary-group query.
        let primary = unsafe { libc::getgid() };
        groups
            .into_iter()
            .find(|group| *group != primary)
            .ok_or_else(|| {
                "NOT GRADED: supplementary group needed to construct the foreign-group fixture"
                    .into()
            })
    }
    fn ordinary_parent() -> Result {
        Fixture::new(0o755, None)?.accepted(0o755)
    }
    fn private_group_parent() -> Result {
        under_umask(0o002, || Fixture::new(0o775, None)?.accepted(0o775))
    }
    fn foreign_group_parent() -> Result {
        let group = foreign_group()?;
        let fixture = Fixture::new(0o775, Some(group))?;
        fixture.refused("private primary group")?;
        assert_eq!(fs::metadata(&fixture.parent)?.gid(), group);
        assert_eq!(fs::metadata(&fixture.parent)?.mode() & 0o777, 0o775);
        Ok(())
    }
    fn world_writable_parent() -> Result {
        Fixture::new(0o777, None)?.refused("world-writable without sticky protection")
    }
    fn sticky_parent() -> Result {
        Fixture::new(0o1777, None)?.accepted(0o1777)
    }
    fn private_root_stays_private() -> Result {
        let fixture = Fixture::new(0o755, None)?;
        let state = fixture.parent.join("state");
        fs::create_dir(&state)?;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o775))?;
        let failure = match NativeStateFiles::open(&state) {
            Ok(_) => return Err("private state root accepted group write".into()),
            Err(error) => error,
        };
        assert_eq!(failure.code, StateFileErrorCode::LocationUnsafe);
        assert_eq!(failure.path, state);
        assert_eq!(
            fs::metadata(&state)?.mode() & 0o777,
            0o775,
            "unsafe root was silently chmodded"
        );
        Ok(())
    }
    pub fn run() -> Result {
        let cases: &[Case] = &[
            (
                "explicit 0755 ancestor and protected publication/reopen",
                ordinary_parent,
            ),
            (
                "Ubuntu 0775 private primary group under umask 0002",
                private_group_parent,
            ),
            (
                "foreign group write refuses before creation and preserves ancestor",
                foreign_group_parent,
            ),
            (
                "world write refuses with its exact path",
                world_writable_parent,
            ),
            ("sticky shared ancestor remains supported", sticky_parent),
            (
                "UPG exception never weakens the owned state root",
                private_root_stays_private,
            ),
        ];
        let mut failures = 0;
        for (name, case) in cases {
            match case() {
                Ok(()) => println!("PASS: {name}"),
                Err(error) => {
                    failures += 1;
                    eprintln!("FAIL: {name}: {error}");
                }
            }
        }
        println!(
            "native ancestor policy: {} passed, {failures} failed; installer/init join NOT GRADED",
            cases.len() - failures
        );
        if failures != 0 {
            return Err("native ancestor consumer failed".into());
        }
        Ok(())
    }
}
fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    if let Err(error) = linux::run() {
        eprintln!("{error}");
        return std::process::ExitCode::FAILURE;
    }
    #[cfg(not(target_os = "linux"))]
    println!("NOT GRADED: real Linux account/group ancestor fixtures");
    std::process::ExitCode::SUCCESS
}
