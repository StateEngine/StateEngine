//! Broad search stages compact hits until window-local document frequencies are
//! known. Admission stops before a whole file, so continuations lose no matches.
use super::*;
use crate::text::lexical::{Corpus, Document};
pub(super) struct Hit {
    pub value: SearchHit,
    pub key: Key,
    pub bytes: usize,
}
pub(super) struct RankedWindow {
    hits: Vec<(Hit, Option<Document>)>,
    corpus: Corpus,
    broad: bool,
    retained: usize,
    /// Staged bytes: the page byte budget, never below the historic 32 KiB.
    cap: usize,
    limit: usize,
    more: bool,
    after: Option<Key>,
}
impl RankedWindow {
    pub fn new(broad: bool, budget: QueryBudget, after: Option<Key>) -> Self {
        Self {
            hits: Vec::new(),
            corpus: Corpus::default(),
            broad,
            retained: 0,
            cap: (budget.max_bytes as usize).max(32 * 1024),
            limit: usize::from(budget.max_results),
            more: false,
            after,
        }
    }
    pub fn observe(&mut self, document: Option<Document>) {
        if let Some(document) = document {
            self.corpus.observe(document);
        }
    }
    pub fn push_file(&mut self, hits: Vec<Hit>, document: Option<Document>) -> bool {
        // Include keys and lexical counters in the staging allowance, in
        // addition to the serialized hit. No bodies are kept outside this cap.
        let cost = |hit: &Hit| hit.bytes + hit.key.bytes.len() + 192;
        if self.broad {
            let additional: usize = hits.iter().map(cost).sum();
            if self.retained + additional > self.cap {
                return false;
            }
            self.retained += additional;
            self.hits
                .extend(hits.into_iter().map(|hit| (hit, document)));
        } else {
            for hit in hits {
                if self
                    .after
                    .as_ref()
                    .is_some_and(|key| super::find::compare(&hit.key, key).is_le())
                {
                    continue;
                }
                let position = self
                    .hits
                    .partition_point(|(old, _)| super::find::compare(&old.key, &hit.key).is_lt());
                if position < self.limit && cost(&hit) <= self.cap {
                    self.retained += cost(&hit);
                    self.hits.insert(position, (hit, None));
                    while self.retained > self.cap || self.hits.len() > self.limit {
                        if let Some((old, _)) = self.hits.pop() {
                            self.retained -= cost(&old);
                            self.more = true;
                        }
                    }
                } else {
                    self.more = true;
                }
            }
        }
        self.observe(document);
        true
    }
    pub fn finish(mut self, after: Option<&Key>) -> (Vec<Hit>, bool) {
        if self.broad {
            for (hit, document) in &mut self.hits {
                // Preserve metadata BM25 and stronger symbol/path tiers. Source
                // BM25 breaks ties after activity, using the same key layout.
                if hit.value.reason.match_tier == 5
                    && let Some(document) = document
                {
                    hit.key.bytes[..8].copy_from_slice(
                        &(u64::MAX - self.corpus.score(*document).to_bits()).to_be_bytes(),
                    );
                }
            }
        }
        self.hits
            .sort_by(|(a, _), (b, _)| super::find::compare(&a.key, &b.key));
        self.hits
            .retain(|(hit, _)| after.is_none_or(|key| super::find::compare(&hit.key, key).is_gt()));
        // One hit per source line; symbol tiers sort before text, so they win.
        let mut seen = std::collections::HashSet::new();
        self.hits.retain(|(hit, _)| match &hit.value.target {
            HitTarget::Code(c) => c
                .pointer
                .span
                .is_none_or(|s| seen.insert((c.pointer.file, s.start.line))),
            _ => true,
        });
        self.more |= self.hits.len() > self.limit;
        self.hits.truncate(self.limit);
        (
            self.hits.into_iter().map(|(hit, _)| hit).collect(),
            self.more,
        )
    }
}
