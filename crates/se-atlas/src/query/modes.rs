use super::*;
pub(super) fn automatic(text: &str) -> SearchMode {
    if text.chars().any(char::is_whitespace) {
        SearchMode::Phrase
    } else {
        SearchMode::Exact
    }
}
pub(super) fn fts(text: &str, mode: SearchMode) -> String {
    let quote = |text: &str| format!("\"{}\"", text.replace('"', "\"\""));
    if matches!(mode, SearchMode::Broad | SearchMode::Related) {
        words(text)
            .into_iter()
            .map(quote)
            .collect::<Vec<_>>()
            .join(" OR ")
    } else {
        quote(text)
    }
}

/// The same terms drive FTS and live-source broad matching.
pub(super) fn words(text: &str) -> Vec<&str> {
    text.split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|s| !s.is_empty())
        .filter(|s| {
            !matches!(
                s.to_ascii_lowercase().as_str(),
                "a" | "an"
                    | "the"
                    | "is"
                    | "are"
                    | "why"
                    | "what"
                    | "who"
                    | "how"
                    | "to"
                    | "of"
                    | "in"
                    | "and"
                    | "or"
                    | "was"
                    | "were"
                    | "does"
                    | "do"
            )
        })
        .take(32)
        .collect()
}
fn regex_literal(text: &str) -> String {
    let mut output = String::new();
    for c in text.chars() {
        if ".+*?()|[]{}^$\\".contains(c) {
            output.push('\\');
        }
        output.push(c);
    }
    output
}
pub(super) fn text_pattern(text: &str, mode: SearchMode, regex: bool) -> (String, bool) {
    if regex || mode == SearchMode::Literal {
        return (text.into(), regex);
    }
    let expression = match mode {
        SearchMode::Exact => format!(r"\b{}\b", regex_literal(text)),
        SearchMode::Phrase => text
            .split_whitespace()
            .map(regex_literal)
            .collect::<Vec<_>>()
            .join(r"[\s\p{P}]+"),
        SearchMode::Broad | SearchMode::Related => {
            let terms = words(text);
            if terms.is_empty() {
                r"[^\s\S]".into()
            } else {
                terms
                    .into_iter()
                    .map(|s| format!(r"\b{}\b", regex_literal(s)))
                    .collect::<Vec<_>>()
                    .join("|")
            }
        }
        SearchMode::Literal => unreachable!(),
    };
    (expression, true)
}

pub(super) fn key(mode: SearchMode) -> u64 {
    match mode {
        SearchMode::Exact => 0,
        SearchMode::Literal => 1,
        SearchMode::Phrase => 2,
        SearchMode::Broad => 3,
        SearchMode::Related => 4,
    }
}
pub(super) fn from_key(key: Option<&u64>) -> AtlasResult<SearchMode> {
    match key {
        Some(0) => Ok(SearchMode::Exact),
        Some(1) => Ok(SearchMode::Literal),
        Some(2) => Ok(SearchMode::Phrase),
        Some(3) => Ok(SearchMode::Broad),
        Some(4) => Ok(SearchMode::Related),
        _ => Err(cursor::invalid("invalid search mode in continuation")),
    }
}
