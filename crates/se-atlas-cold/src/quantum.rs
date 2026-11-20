//! Fit a first-parent Git window into the writer quantum on native paths.
use se_atlas::history::HistoryLimit;
use se_atlas::policy::{WRITER_QUANTUM_PATHS, writer_quantum_allowed};
/// A bounded first-parent commit whose changed paths are still native
/// strings, so the writer quantum fits before portability validation.
pub(crate) trait WriterQuantumCommit {
    fn quantum_oid(&self) -> &str;
    fn quantum_native_paths(&self) -> &[String];
    /// Withhold the changed paths behind the omission note and count.
    fn quantum_withhold(&mut self, note: &str, allowed: u32);
}
/// Fit a first-parent Git window into the writer quantum on native paths,
/// dropping oldest commits until the path budget holds, then degrading a
/// final oversized commit. Portability validation then runs once, on
/// retained paths only, and a degraded commit counts proven allowed paths.
pub(crate) fn fit_writer_quantum<C: WriterQuantumCommit>(
    mut commits: Vec<C>,
    mut next: Option<String>,
    mut limit: HistoryLimit,
) -> (Vec<C>, Option<String>, HistoryLimit) {
    let mut paths = commits
        .iter()
        .map(|c| c.quantum_native_paths().len())
        .sum::<usize>();
    while paths > WRITER_QUANTUM_PATHS && commits.len() > 1 {
        let removed = commits.remove(commits.len() - 1);
        paths -= removed.quantum_native_paths().len();
        next = Some(removed.quantum_oid().to_owned());
        limit = HistoryLimit::CommitCount;
    }
    if paths > WRITER_QUANTUM_PATHS {
        let allowed = writer_quantum_allowed(commits[0].quantum_native_paths());
        let tail = if allowed > 0 {
            "paths omitted"
        } else {
            "commit entry withheld for size"
        };
        let note = format!(
            "changed paths exceed the {}-path writer quantum; {tail}",
            WRITER_QUANTUM_PATHS
        );
        commits[0].quantum_withhold(&note, allowed);
    }
    (commits, next, limit)
}
