//! The in-memory set of paths the watcher reported but the writer has not
//! committed yet. Queries overlay it so an edit is visible before its batch
//! lands; the writer settles each path once its batch commits.
//!
//! The set is bounded. Past [`MAX_DIRTY`] paths it stops listing and marks
//! itself overflowed: queries then report the index as updating, and the
//! writer reconciles the whole tree by file stats instead of path by path.
use std::collections::BTreeMap;

/// Paths listed before the set overflows.
pub const MAX_DIRTY: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// Created or modified; the file should be read again.
    Modified,
    /// Deleted or moved away; its indexed rows are stale.
    Removed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirtyPath {
    pub path: String,
    pub change: Change,
    /// Bumped on every mark, so a commit settles only the version it read.
    pub serial: u64,
}

/// A token from [`DirtySet::begin_reconcile`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconcileToken(u64);

#[derive(Debug, Default)]
pub struct DirtySet {
    entries: BTreeMap<String, (Change, u64)>,
    serial: u64,
    /// Marks dropped since the set overflowed; zero when it has not.
    dropped: u64,
}

impl DirtySet {
    /// Record a change. Returns false when the set is overflowed and the
    /// path was counted instead of listed.
    pub fn mark(&mut self, path: &str, change: Change) -> bool {
        self.serial += 1;
        if let Some(entry) = self.entries.get_mut(path) {
            *entry = (change, self.serial);
            return true;
        }
        if self.dropped > 0 || self.entries.len() >= MAX_DIRTY {
            self.dropped += 1;
            return false;
        }
        self.entries.insert(path.to_owned(), (change, self.serial));
        true
    }

    /// Note that changes were lost (a watch overflow or failure), so only a
    /// full reconcile can tell what changed.
    pub fn lose(&mut self) {
        self.dropped += 1;
    }

    pub fn overflowed(&self) -> bool {
        self.dropped > 0
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.dropped == 0
    }

    pub fn change(&self, path: &str) -> Option<Change> {
        self.entries.get(path).map(|(change, _)| *change)
    }

    /// Every listed path, sorted, for one writer batch or one query.
    pub fn snapshot(&self) -> Vec<DirtyPath> {
        self.entries
            .iter()
            .map(|(path, (change, serial))| DirtyPath {
                path: path.clone(),
                change: *change,
                serial: *serial,
            })
            .collect()
    }

    /// Drop a path whose batch committed, unless it was marked again since
    /// the writer read it.
    pub fn settle(&mut self, path: &str, serial: u64) {
        if self
            .entries
            .get(path)
            .is_some_and(|(_, current)| *current == serial)
        {
            self.entries.remove(path);
        }
    }

    /// Start a full reconcile of an overflowed set.
    pub fn begin_reconcile(&self) -> ReconcileToken {
        ReconcileToken(self.dropped)
    }

    /// Finish a reconcile: the overflow clears only when no change was lost
    /// while it ran, so a lost change always earns another reconcile.
    pub fn end_reconcile(&mut self, token: ReconcileToken) {
        if self.dropped == token.0 {
            self.dropped = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_commit_settles_only_the_version_it_read() {
        let mut set = DirtySet::default();
        assert!(set.mark("src/a.rs", Change::Modified));
        let read = set.snapshot();
        assert!(set.mark("src/a.rs", Change::Removed));
        set.settle("src/a.rs", read[0].serial);
        assert_eq!(set.change("src/a.rs"), Some(Change::Removed));
        let again = set.snapshot();
        set.settle("src/a.rs", again[0].serial);
        assert!(set.is_empty());
    }

    #[test]
    fn past_the_cap_it_overflows_and_reconcile_clears_only_a_quiet_run() {
        let mut set = DirtySet::default();
        for n in 0..MAX_DIRTY {
            assert!(set.mark(&format!("f{n}"), Change::Modified));
        }
        assert!(!set.overflowed());
        assert!(!set.mark("one-more", Change::Modified));
        assert!(set.overflowed());
        assert_eq!(set.len(), MAX_DIRTY);
        // A listed path still updates in place.
        assert!(set.mark("f0", Change::Removed));
        let token = set.begin_reconcile();
        set.lose();
        set.end_reconcile(token);
        assert!(set.overflowed(), "a change lost mid-reconcile was dropped");
        let token = set.begin_reconcile();
        set.end_reconcile(token);
        assert!(!set.overflowed());
        assert!(!set.is_empty(), "listed paths still await their commit");
    }
}
