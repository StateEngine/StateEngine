//! Deterministic Unicode camel/snake/digit boundaries, versioned with extraction.
/// Borrow complete tokens; byte offsets always lie on UTF-8 boundaries.
pub fn identifier_tokens(name: &str) -> Vec<&str> {
    let chars: Vec<_> = name.char_indices().collect();
    let mut tokens = Vec::new();
    let mut start = None;
    for (at, &(byte, c)) in chars.iter().enumerate() {
        if !c.is_alphanumeric() {
            if let Some(start) = start.take() {
                tokens.push(&name[start..byte]);
            }
            continue;
        }
        if let Some(from) = start {
            let previous = chars[at - 1].1;
            let next = chars.get(at + 1).map(|v| v.1);
            if previous.is_lowercase() && c.is_uppercase()
                || previous.is_numeric() != c.is_numeric()
                || previous.is_uppercase()
                    && c.is_uppercase()
                    && next.is_some_and(char::is_lowercase)
            {
                tokens.push(&name[from..byte]);
                start = Some(byte);
            }
        } else {
            start = Some(byte);
        }
    }
    if let Some(start) = start {
        tokens.push(&name[start..]);
    }
    tokens
}
/// The writer indexes this in symbol_fts.split_name, including the acronym.
pub fn identifier_index(name: &str) -> String {
    let tokens = identifier_tokens(name);
    let acronym: String = tokens.iter().filter_map(|s| s.chars().next()).collect();
    format!("{} {acronym}", tokens.join(" "))
}
pub(crate) fn split_matches(name: &str, query: &str) -> bool {
    let smart = query.chars().any(char::is_uppercase);
    let matches = |left: &str, right: &str| {
        if smart {
            left.starts_with(right)
        } else {
            left.to_lowercase().starts_with(&right.to_lowercase())
        }
    };
    if matches(name, query) {
        return true;
    }
    let tokens = identifier_tokens(name);
    let acronym: String = tokens.iter().filter_map(|s| s.chars().next()).collect();
    if matches(&acronym, query) {
        return true;
    }
    let wanted = identifier_tokens(query);
    !wanted.is_empty()
        && wanted.len() <= tokens.len()
        && tokens.windows(wanted.len()).any(|window| {
            window
                .iter()
                .zip(&wanted)
                .all(|(left, right)| matches(left, right))
        })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn camel_snake_acronym_and_unicode_are_stable() {
        assert_eq!(
            identifier_tokens("getHTTPResponse2_id"),
            vec!["get", "HTTP", "Response", "2", "id"]
        );
        assert_eq!(identifier_tokens("δείγμαΣήμα"), vec!["δείγμα", "Σήμα"]);
        assert!(split_matches("getHTTPResponse", "ghr"));
        assert!(split_matches("get_http_response", "http_res"));
        assert!(!split_matches("Server", "ver"));
    }
}
