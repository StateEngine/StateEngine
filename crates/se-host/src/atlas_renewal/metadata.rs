//! Only registered Git metadata supplies subscriptions. One reference spelling
//! and compact offsets cover its ancestor watches; objects/config are never read.
use super::*;
use se_proc::NativeWatchEvent;
use std::io::Read;
const GIT: u8 = 1;
const COMMON: u8 = 2;
const EXCLUDE: u8 = 4;
struct Entry {
    descriptor: u32,
    flags: u8,
    component: Option<(u16, u16)>,
}
pub(super) struct Watches {
    git: NativeSourceRoot,
    common: NativeSourceRoot,
    reference: String,
    entries: Vec<Entry>,
    pub complete: bool,
    pub diagnostic: Option<String>,
    pub unwatched: u64,
    pub discovery_complete: bool,
}
impl Watches {
    pub fn install(
        registration: &GitMetadataRegistration,
        watch: &NativeSourceWatch,
        cap: usize,
        deadline: Instant,
    ) -> AtlasResult<Self> {
        timely(deadline)?;
        let git = NativeSourceRoot::open(&registration.physical_git_directory)
            .map_err(|e| source_error("registered Git directory", e))?;
        let common = NativeSourceRoot::open(&registration.physical_common_directory)
            .map_err(|e| source_error("registered Git common directory", e))?;
        if git
            .physical_identity()
            .map_err(|e| source_error("registered Git directory", e))?
            != registration.git_directory_identity
            || common
                .physical_identity()
                .map_err(|e| source_error("registered Git common directory", e))?
                != registration.common_directory_identity
        {
            return Err(source_error(
                "registered Git metadata",
                "physical identity changed; rebind required",
            ));
        }
        let mut result = Self {
            git,
            common,
            reference: String::new(),
            entries: Vec::new(),
            complete: true,
            diagnostic: None,
            unwatched: 0,
            discovery_complete: true,
        };
        let same = registration.git_directory_identity == registration.common_directory_identity;
        result.add(
            watch,
            true,
            "",
            GIT | if same { COMMON } else { 0 },
            None,
            cap,
        );
        if !same {
            result.add(watch, false, "", COMMON, None, cap);
        }
        result.add(watch, false, "info", EXCLUDE, None, cap);
        result.reference = match reference(&result.git) {
            Ok(reference) => reference,
            Err(error) => {
                result.remove(watch)?;
                return Err(error);
            }
        };
        let mut start = 0;
        let length = result.reference.len();
        while start < length {
            if Instant::now() >= deadline {
                result.failed("registered metadata subscription deadline exhausted");
                break;
            }
            let end = result.reference[start..]
                .find('/')
                .map_or(length, |n| start + n);
            let parent = if start == 0 {
                ""
            } else {
                &result.reference[..start - 1]
            };
            // At most one bounded reference spelling is temporarily copied while
            // adding an ancestor; no collected directory inventory is retained.
            let parent = parent.to_owned();
            let component = Some((start as u16, end as u16));
            result.add(watch, false, &parent, 0, component, cap);
            start = end + 1;
        }
        Ok(result)
    }
    fn add(
        &mut self,
        watch: &NativeSourceWatch,
        git: bool,
        path: &str,
        flags: u8,
        component: Option<(u16, u16)>,
        cap: usize,
    ) -> bool {
        let root = if git { &self.git } else { &self.common };
        match root.open_directory(path) {
            Ok(Some(_)) => (),
            Ok(None) => return false, // The subscribed ancestor observes creation.
            Err(error) => {
                self.failed(error);
                return false;
            }
        }
        // The common/git root and first reference ancestor name one inode.
        let existing = self
            .entries
            .iter()
            .position(|entry| path.is_empty() && entry.flags & if git { GIT } else { COMMON } != 0);
        if let Some(index) = existing {
            self.entries[index].flags |= flags;
            if component.is_some() {
                self.entries[index].component = component;
            }
            return true;
        }
        if self.entries.len() >= cap {
            self.unwatched = self.unwatched.saturating_add(1);
            self.complete = false;
            self.diagnostic = Some("registered metadata watch budget exhausted".into());
            return false;
        }
        match watch.subscribe(root, path) {
            Ok(Some(subscription)) => {
                self.entries.reserve_exact(1);
                self.entries.push(Entry {
                    descriptor: subscription.descriptor,
                    flags,
                    component,
                });
                true
            }
            Ok(None) => false,
            Err(error) => {
                self.failed(error);
                false
            }
        }
    }
    fn failed(&mut self, error: impl std::fmt::Display) {
        self.complete = false;
        self.discovery_complete = false;
        self.unwatched = self.unwatched.saturating_add(1);
        self.diagnostic = Some(error.to_string());
    }
    pub fn lock_held(&self) -> AtlasResult<bool> {
        self.common
            .physical_identity()
            .map_err(|e| source_error("registered Git common directory", e))?;
        let mut held = false;
        for path in ["index.lock", "HEAD.lock"] {
            held |= self
                .git
                .open_relative(path)
                .map_err(|e| source_error(path, e))?
                .is_some();
        }
        Ok(held)
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn handles(&self, descriptor: Option<u32>) -> bool {
        self.entries
            .iter()
            .any(|entry| Some(entry.descriptor) == descriptor)
    }
    pub fn hint(&self, event: &NativeWatchEvent<'_>) -> AtlasResult<Option<SourceHint>> {
        // These methods revalidate the retained native names, including root
        // replacement. An event from an old inode never authorizes new metadata.
        self.git
            .physical_identity()
            .map_err(|e| source_error("registered Git directory", e))?;
        self.common
            .physical_identity()
            .map_err(|e| source_error("registered Git common directory", e))?;
        if event.action == NativeWatchAction::Invalidated {
            return Ok(Some(SourceHint::Reconcile(ReconcileReason::WatchFailure)));
        }
        let Some(name) = event.name.to_str() else {
            return Ok(None);
        };
        let Some(entry) = self
            .entries
            .iter()
            .find(|entry| Some(entry.descriptor) == event.descriptor)
        else {
            return Ok(None);
        };
        let reason = if entry.flags & EXCLUDE != 0 && name == "exclude"
            || entry.flags & COMMON != 0 && name == "info"
        {
            Some(ReconcileReason::IgnoreRulesChanged)
        } else if entry.flags & GIT != 0 && matches!(name, "HEAD" | "HEAD.lock" | "index.lock")
            || entry.flags & COMMON != 0 && name == "packed-refs"
            || entry.component.is_some_and(|(start, end)| {
                name == &self.reference[usize::from(start)..usize::from(end)]
            })
        {
            Some(ReconcileReason::GitHeadChanged)
        } else {
            None
        };
        Ok(reason.map(SourceHint::Reconcile))
    }
    pub fn remove(self, watch: &NativeSourceWatch) -> AtlasResult<()> {
        for entry in self.entries {
            watch
                .remove(entry.descriptor)
                .map_err(|e| source_error("metadata watch removal", e))?;
        }
        Ok(())
    }
}
fn reference(root: &NativeSourceRoot) -> AtlasResult<String> {
    let Some(mut file) = root
        .open_relative("HEAD")
        .map_err(|e| source_error("HEAD", e))?
    else {
        return Ok(String::new());
    };
    let before = file.revision().map_err(|e| source_error("HEAD", e))?;
    let mut text = String::new();
    (&mut file)
        .take(4097)
        .read_to_string(&mut text)
        .map_err(|e| source_error("HEAD", e))?;
    if text.len() > 4096 {
        return Err(limit("registered HEAD", text.len() as u64, 4096));
    }
    if before != file.revision().map_err(|e| source_error("HEAD", e))?
        || !file.validate_name().map_err(|e| source_error("HEAD", e))?
    {
        return Err(source_error("HEAD", "changed during observation"));
    }
    let text = text.trim_end_matches(['\r', '\n']);
    if let Some(reference) = text.strip_prefix("ref: ") {
        if !reference.starts_with("refs/") || reference.split('/').count() > 32 {
            return Err(source_error(
                "HEAD",
                "a bounded registered refs path is required",
            ));
        }
        return Ok(RelativePath::new(reference.to_owned())?.as_str().to_owned());
    }
    if matches!(text.len(), 40 | 64) && text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(String::new());
    }
    Err(source_error("HEAD", "invalid registered HEAD contents"))
}
