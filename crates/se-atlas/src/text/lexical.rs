//! Query-local BM25 statistics. No source text or vocabulary survives the scan.
pub(crate) const MAX_TERMS: usize = 32;
pub(crate) struct Terms {
    values: Vec<String>,
    sensitive: bool,
    longest: usize,
}
impl Terms {
    pub fn new(words: &[&str], sensitive: bool) -> Self {
        let mut values = Vec::new();
        for word in words.iter().take(MAX_TERMS) {
            let word = if sensitive {
                (*word).to_owned()
            } else {
                word.to_lowercase()
            };
            if !values.contains(&word) {
                values.push(word);
            }
        }
        let longest = values.iter().map(String::len).max().unwrap_or(0);
        Self {
            values,
            sensitive,
            longest,
        }
    }
}
#[derive(Clone, Copy, Default)]
pub(crate) struct Document {
    pub tokens: u32,
    frequencies: [u32; MAX_TERMS],
}
pub(super) struct Counter<'a> {
    terms: &'a Terms,
    token: String,
    oversized: bool,
    document: Document,
}
impl<'a> Counter<'a> {
    pub fn new(terms: &'a Terms) -> Self {
        Self {
            terms,
            token: String::with_capacity(terms.longest),
            oversized: false,
            document: Document::default(),
        }
    }
    pub fn observe(&mut self, text: &str) {
        for c in text.chars() {
            if c.is_alphanumeric() || c == '_' {
                if self.oversized {
                    continue;
                }
                if self.terms.sensitive {
                    self.token.push(c);
                } else {
                    self.token.extend(c.to_lowercase());
                }
                if self.token.len() > self.terms.longest {
                    self.oversized = true;
                    self.token.clear();
                }
            } else {
                self.finish_token();
            }
        }
    }
    fn finish_token(&mut self) {
        if self.oversized || !self.token.is_empty() {
            self.document.tokens += 1;
            if !self.oversized {
                for (i, term) in self.terms.values.iter().enumerate() {
                    if term == &self.token {
                        self.document.frequencies[i] += 1;
                    }
                }
            }
        }
        self.token.clear();
        self.oversized = false;
    }
    pub fn finish(mut self) -> Document {
        self.finish_token();
        self.document
    }
}
#[derive(Default)]
pub(crate) struct Corpus {
    documents: u32,
    tokens: u64,
    frequencies: [u32; MAX_TERMS],
}
impl Corpus {
    pub fn observe(&mut self, document: Document) {
        self.documents += 1;
        self.tokens += u64::from(document.tokens);
        for (count, tf) in self.frequencies.iter_mut().zip(document.frequencies) {
            *count += u32::from(tf > 0);
        }
    }
    pub fn score(&self, document: Document) -> f64 {
        if self.documents == 0 || self.tokens == 0 {
            return 0.0;
        }
        let average = self.tokens as f64 / f64::from(self.documents);
        document
            .frequencies
            .iter()
            .zip(self.frequencies)
            .map(|(tf, df)| {
                if *tf == 0 {
                    return 0.0;
                }
                let idf =
                    (1.0 + (f64::from(self.documents - df) + 0.5) / (f64::from(df) + 0.5)).ln();
                let tf = f64::from(*tf);
                idf * tf * 2.2 / (tf + 1.2 * (0.25 + 0.75 * f64::from(document.tokens) / average))
            })
            .sum()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn streaming_tokens_and_rarity_use_the_whole_observed_corpus() {
        let terms = Terms::new(&["rare", "common", "界限"], false);
        let mut split = Counter::new(&terms);
        split.observe("RA");
        split.observe("RE common 界");
        split.observe("限");
        let rare = split.finish();
        assert_eq!(rare.tokens, 3);
        assert_eq!(&rare.frequencies[..3], &[1, 1, 1]);
        let mut corpus = Corpus::default();
        corpus.observe(rare);
        let mut common = Counter::new(&terms);
        common.observe("common common common");
        let common = common.finish();
        for _ in 0..20 {
            corpus.observe(common);
        }
        assert!(corpus.score(rare) > corpus.score(common));
        let mut long = Counter::new(&terms);
        long.observe(&"x".repeat(100_000));
        long.observe(" rare");
        let long = long.finish();
        assert_eq!(long.tokens, 2);
        assert_eq!(long.frequencies[0], 1);
    }
}
