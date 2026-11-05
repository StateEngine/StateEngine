use se_types::code::{AtlasText, QueryText};
fn best(text: &str, query: Option<&QueryText>) -> usize {
    let Some(query) = query else {
        return 0;
    };
    let query = query.as_str();
    let smart = query.chars().any(char::is_uppercase);
    let words = query.split_whitespace().take(32).collect::<Vec<_>>();
    let mut best = (0, 0);
    let mut start = 0;
    for line in text.split_inclusive('\n') {
        let folded = if smart {
            line.to_owned()
        } else {
            line.to_lowercase()
        };
        let score = words.iter().filter(|word| folded.contains(**word)).count();
        if score > best.0 {
            best = (score, start);
        }
        start += line.len();
    }
    best.1
}
fn end(text: &str, max: usize) -> usize {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}
pub(super) fn line(text: &str, query: Option<&QueryText>) -> String {
    let start = best(text, query);
    let line = text[start..].lines().next().unwrap_or("");
    // Center a long matching line on an actual query term rather than returning
    // its unrelated first 160 bytes. ASCII folding preserves byte positions.
    let found = query.and_then(|q| {
        q.as_str().split_whitespace().find_map(|word| {
            if q.as_str().chars().any(char::is_uppercase) {
                line.find(word)
            } else {
                line.as_bytes()
                    .windows(word.len())
                    .position(|part| part.eq_ignore_ascii_case(word.as_bytes()))
            }
        })
    });
    let mut left = found.unwrap_or(0).saturating_sub(40);
    while !line.is_char_boundary(left) {
        left -= 1;
    }
    let line = &line[left..];
    let mut output = String::with_capacity(160);
    for c in line.chars() {
        let size = if c.is_control() { 1 } else { c.len_utf8() };
        if output.len() + size > 160 {
            break;
        }
        output.push(if c.is_control() { ' ' } else { c });
    }
    output
}
pub(super) fn body(text: &str, query: Option<&QueryText>) -> (String, bool) {
    let start = best(text, query);
    let tail = &text[start..];
    let mut stop = 0;
    for line in tail.split_inclusive('\n').take(40) {
        if stop + line.len() > 12 * 1024 {
            stop += end(line, 12 * 1024 - stop);
            break;
        }
        stop += line.len();
    }
    (tail[..stop].to_owned(), start == 0 && stop == text.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn excerpts_show_matches_late_in_long_unicode_lines() -> se_types::Result<()> {
        let text = "λ".repeat(300) + " packet budget belongs here";
        let query = QueryText::new("packet budget")?;
        let line = line(&text, Some(&query));
        assert!(line.contains("packet budget"));
        assert!(line.len() <= 160);
        Ok(())
    }
}
