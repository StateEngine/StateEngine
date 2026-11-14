//! Bounded Git-style byte globs. Two path-sized rows replace recursive wildcard
//! backtracking; every token checks the caller's finite work deadline.
use super::*;
#[derive(Clone, Copy)]
enum Token<'a> {
    Literal(u8),
    One,
    Star(bool),
    Directories,
    Class(&'a [u8]),
}
pub(super) fn matches(pattern: &str, text: &str, deadline: Instant) -> AtlasResult<bool> {
    let p = pattern.as_bytes();
    let text = text.as_bytes();
    if text.len() > 4096 {
        return Err(limit("ignore path", text.len() as u64, 4096));
    }
    let mut before = vec![false; text.len() + 1];
    let mut after = vec![false; text.len() + 1];
    before[0] = true;
    let mut at = 0;
    while at < p.len() {
        timely(deadline)?;
        let token = match p[at] {
            b'\\' => {
                at += 1;
                if at == p.len() {
                    return Ok(false);
                }
                Token::Literal(p[at])
            }
            b'?' => Token::One,
            b'*' => {
                let start = at;
                while at + 1 < p.len() && p[at + 1] == b'*' {
                    at += 1;
                }
                let recursive = at - start == 1
                    && (start == 0 || p[start - 1] == b'/')
                    && (at + 1 == p.len() || p[at + 1] == b'/');
                if recursive && p.get(at + 1) == Some(&b'/') {
                    at += 1;
                    Token::Directories
                } else {
                    Token::Star(recursive)
                }
            }
            b'[' => {
                let start = at + 1;
                let mut end = start;
                if p.get(end).is_some_and(|b| *b == b'!' || *b == b'^') {
                    end += 1;
                }
                if p.get(end) == Some(&b']') {
                    end += 1;
                }
                while end < p.len() && p[end] != b']' {
                    if p[end] == b'\\' {
                        end += 1;
                    } else if p[end..].starts_with(b"[:") {
                        let Some(close) = p[end + 2..].windows(2).position(|w| w == b":]") else {
                            return Ok(false);
                        };
                        end += close + 3;
                    }
                    end += 1;
                }
                if end >= p.len() {
                    Token::Literal(b'[')
                } else {
                    at = end;
                    Token::Class(&p[start..end])
                }
            }
            value => Token::Literal(value),
        };
        at += 1;
        after.fill(false);
        match token {
            Token::Star(cross) => {
                after[0] = before[0];
                for n in 1..after.len() {
                    after[n] = before[n] || (after[n - 1] && (cross || text[n - 1] != b'/'));
                }
            }
            Token::Directories => {
                let mut reachable = false;
                for n in 0..after.len() {
                    reachable |= before[n];
                    after[n] = before[n] || (reachable && n > 0 && text[n - 1] == b'/');
                }
            }
            other => {
                for n in 1..after.len() {
                    after[n] = before[n - 1]
                        && match other {
                            Token::Literal(v) => text[n - 1] == v,
                            Token::One => text[n - 1] != b'/',
                            Token::Class(class) => {
                                text[n - 1] != b'/' && in_class(class, text[n - 1]) == Some(true)
                            }
                            _ => false,
                        }
                }
            }
        }
        std::mem::swap(&mut before, &mut after);
    }
    Ok(before[text.len()])
}
fn in_class(mut class: &[u8], value: u8) -> Option<bool> {
    let negate = class.first().is_some_and(|v| *v == b'!' || *v == b'^');
    if negate {
        class = &class[1..];
    }
    let mut found = false;
    let mut at = 0;
    while at < class.len() {
        if class[at..].starts_with(b"[:")
            && let Some(close) = class[at + 2..].windows(2).position(|w| w == b":]")
        {
            found |= named_class(&class[at + 2..at + 2 + close], value)?;
            at += close + 4;
            continue;
        }
        let first = class_byte(class, &mut at);
        if class.get(at) == Some(&b'-') && at + 1 < class.len() {
            at += 1;
            let last = class_byte(class, &mut at);
            found |= first <= value && value <= last;
        } else {
            found |= first == value;
        }
    }
    Some(found != negate)
}
fn class_byte(class: &[u8], at: &mut usize) -> u8 {
    if class[*at] == b'\\' && *at + 1 < class.len() {
        *at += 1;
    }
    let byte = class[*at];
    *at += 1;
    byte
}
fn named_class(name: &[u8], value: u8) -> Option<bool> {
    Some(match name {
        b"alnum" => value.is_ascii_alphanumeric(),
        b"alpha" => value.is_ascii_alphabetic(),
        b"blank" => matches!(value, b' ' | b'\t'),
        b"cntrl" => value.is_ascii_control(),
        b"digit" => value.is_ascii_digit(),
        b"graph" => value.is_ascii_graphic(),
        b"lower" => value.is_ascii_lowercase(),
        b"print" => value.is_ascii_graphic() || value == b' ',
        b"punct" => value.is_ascii_punctuation(),
        b"space" => value.is_ascii_whitespace(),
        b"upper" => value.is_ascii_uppercase(),
        b"xdigit" => value.is_ascii_hexdigit(),
        _ => return None,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn git_directory_wildcards_and_escaped_literals() -> AtlasResult<()> {
        let deadline = se_atlas::clock::now() + Duration::from_secs(2);
        for (pattern, path, want) in [
            ("a/**/b", "a/b", true),
            ("a/**/b", "a/x/y/b", true),
            ("**/foo", "foo", true),
            ("**/foo", "a/foo", true),
            ("a/*/b", "a/x/y/b", false),
            ("a/**", "a/x/y", true),
            ("a[0-9].rs", "a4.rs", true),
            ("[a\\", "a", false),
            ("[[:alpha", "a", false),
            ("[![:unknown:]]", "a", false),
            ("[[:alpha:]][[:digit:]].rs", "a4.rs", true),
            ("[[:alpha:]][[:digit:]].rs", "44.rs", false),
            ("[![:digit:]].rs", "a.rs", true),
            ("[![:digit:]].rs", "4.rs", false),
            ("[[:upper:]0-9]", "A", true),
            ("[[:upper:]0-9]", "4", true),
            ("[[:upper:]0-9]", "a", false),
            ("[]a]", "]", true),
            ("[a-\\c]", "b", true),
            ("[\\]]", "]", true),
            ("[[:punct:]]", "/", false),
            ("a[!0-9].rs", "az.rs", true),
            ("a[!0-9].rs", "a4.rs", false),
            ("\\!hi", "!hi", true),
            ("a\\*", "a*", true),
            ("a\\", "a", false),
        ] {
            assert_eq!(matches(pattern, path, deadline)?, want, "{pattern} {path}");
        }
        Ok(())
    }
}
