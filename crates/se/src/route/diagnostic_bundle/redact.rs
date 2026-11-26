//! A single pre-publication redaction pass for every exported string, including errors.
use crate::bootstrap::Bootstrap;
use regex::Regex;
use se_core::scope;
use se_types::Result;
use serde_json::Value;

// Includes both ordinary JSON nesting and JSON encoded inside string values.
const MAX_DEPTH: usize = 32;
const OMITTED: &str = "[redacted unparseable or deeply nested structured text]";
const OPAQUE_REPLACEMENT: &str = "[redacted opaque value]";

const SENSITIVE_LABEL: &str = r"token|secret|password|passwd|passphrase|credential|api[ _-]?key|access[ _-]?key|private[ _-]?key|authorization|cookie";

pub(super) struct Redactor {
    sensitive_key: Regex,
    sensitive_prefix: Regex,
    replacements: Vec<(Regex, &'static str)>,
    paths: Vec<Regex>,
    remotes: Vec<Regex>,
}
impl Redactor {
    pub(super) fn new(
        cx: &Bootstrap,
        project_roots: &[String],
        remotes: &[String],
    ) -> Result<Self> {
        // One vocabulary covers structured fields, assignments and CLI flags.
        let assignment = format!(
            r#"(?is)(["']?[a-z0-9_-]*(?:{SENSITIVE_LABEL})[a-z0-9_-]*["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;\]}}]+)"#
        );
        let flag = format!(
            r#"(?i)(--[a-z0-9_-]*(?:{SENSITIVE_LABEL})[a-z0-9_-]*\s+)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s]+)"#
        );
        let prefix = format!(
            r#"(?is)(?:["']?[a-z0-9_-]*(?:{SENSITIVE_LABEL})[a-z0-9_-]*["']?\s*[:=]\s*|--[a-z0-9_-]*(?:{SENSITIVE_LABEL})[a-z0-9_-]*\s+)"#
        );
        let mut replacements = Vec::new();
        for (pattern, replacement) in [
            (
                r"(?is)-----BEGIN [A-Z0-9 ]*(?:PRIVATE|SECRET) KEY(?: BLOCK)?-----.*?(?:-----END [A-Z0-9 ]*(?:PRIVATE|SECRET) KEY(?: BLOCK)?-----|\z)",
                "[redacted private key]",
            ),
            (
                r#"(?im)(\b(?:authorization|(?:set-)?cookie)["']?\s*:\s*)[^\r\n]+"#,
                "$1[redacted authorization]",
            ),
            (
                r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+",
                "[redacted authorization]",
            ),
            (
                r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/@]+@",
                "[redacted URL credentials]@",
            ),
            (r#"([?&][^=\s?&#"'<>]+=)[^\s&#"']+"#, "$1[redacted]"),
            (assignment.as_str(), "$1[redacted]"),
            (flag.as_str(), "$1[redacted]"),
            (
                r"\b(?:sk-[A-Za-z0-9_-]+|gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|AKIA[A-Z0-9]{16})\b",
                "[redacted token]",
            ),
            (
                r"(?i)(\b(?:ssh|scp|sftp)\s+(?:-[A-Za-z0-9]+(?:\s+[^\s]+)?\s+)*)[A-Za-z0-9._-]+@[A-Za-z0-9.-]+",
                "$1[redacted ssh destination]",
            ),
            // Long opaque values are conservatively removed even without labels.
            (r"\b[A-Za-z0-9_+/=-]{32,}\b", OPAQUE_REPLACEMENT),
            (
                r#"(?i)(?:[A-Z]:[\\/]+(?:Users|Documents and Settings)[\\/]+|/(?:home|Users)/)[^\r\n"'<>]+"#,
                "[redacted home path]",
            ),
            (r#"/root\b(?:/[^\r\n"'<>]*)?"#, "[redacted home path]"),
        ] {
            replacements.push((compile_pattern(pattern)?, replacement));
        }
        Ok(Self {
            sensitive_key: compile_pattern(&format!("(?i)({SENSITIVE_LABEL})"))?,
            sensitive_prefix: compile_pattern(&prefix)?,
            replacements,
            paths: compile_paths(cx, project_roots)?,
            remotes: compile_remotes(remotes)?,
        })
    }
    fn text(&self, text: &str, depth: usize) -> String {
        if depth >= MAX_DEPTH {
            return OMITTED.into();
        }
        // Find complete JSON fragments before applying prose patterns. Decoding
        // first exposes escaped keys/paths and lets sensitive object-valued
        // fields be removed as a whole. String values may themselves encode JSON.
        let mut prefixes = self.sensitive_prefix.find_iter(text).peekable();
        let mut remaining = text;
        let mut decoded = String::new();
        loop {
            let offset = text.len() - remaining.len();
            // JSON consumed on the previous iteration owns its internal labels;
            // its decoded value walk has already redacted those fields.
            while prefixes.peek().is_some_and(|prefix| prefix.end() < offset) {
                prefixes.next();
            }
            let fragment = remaining.find(['{', '[', '"']).map(|at| offset + at);
            let assigned = prefixes
                .peek()
                .filter(|prefix| fragment.is_none_or(|at| prefix.start() <= at))
                .map(|prefix| prefix.end());
            if let Some(start) = assigned {
                prefixes.next();
                // Lex the whole value, not just a JSON fragment in it. A prefix
                // and suffix can belong to the same unquoted credential value.
                let end = start + assigned_end(&text[start..]);
                decoded.push_str(&text[offset..start]);
                decoded.push_str("[redacted]");
                remaining = &text[end..];
                continue;
            }
            let Some(start) = fragment else { break };
            decoded.push_str(&text[offset..start]);
            let fragment = &text[start..];
            if let Some(tag_end) = benign_bracket_tag_end(fragment) {
                // Ordinary flat log tags like `[INFO]` or `[2026-11-26T00:00:00Z]`
                // contain no nested structured delimiters or escapes; keep them
                // verbatim in O(tag_len) without withholding the line.
                decoded.push_str(&fragment[..tag_end]);
                remaining = &fragment[tag_end..];
                continue;
            }
            let Some(end) = structured_end(fragment) else {
                // Never export an undecodable suffix or re-scan it quadratically:
                // it may contain an escaped credential label that prose patterns
                // cannot recognize.
                decoded.push_str(OMITTED);
                remaining = "";
                break;
            };
            let balanced = &fragment[..end];
            match serde_json::from_str::<Value>(balanced) {
                Ok(mut value) => {
                    self.value_at(&mut value, depth + 1);
                    decoded.push_str(
                        &serde_json::to_string(&value).unwrap_or_else(|_| OMITTED.into()),
                    );
                }
                // Balanced structured fragment that is not valid JSON: withhold
                // it rather than copying it verbatim so mixed prose + escaped
                // JSON cannot leak credentials past prose patterns.
                Err(_) => decoded.push_str(OMITTED),
            }
            remaining = &fragment[end..];
        }
        decoded.push_str(remaining);
        let mut text = decoded;
        // Exact known paths precede generic patterns so even a space-bearing
        // selected home is completely removed from diagnosis prose.
        for path in &self.paths {
            text = path.replace_all(&text, "[redacted path]").into_owned();
        }
        for remote in &self.remotes {
            text = remote
                .replace_all(&text, "[redacted remote destination]")
                .into_owned();
        }
        for (pattern, replacement) in &self.replacements {
            if *replacement == OPAQUE_REPLACEMENT {
                // Known identifier shapes (commit SHAs, digests, UUIDs) keep
                // their correlation value; other long opaque tokens stay removed.
                text = pattern
                    .replace_all(&text, |caps: &regex::Captures<'_>| {
                        let token = &caps[0];
                        if keeps_opaque(token) {
                            token.to_owned()
                        } else {
                            OPAQUE_REPLACEMENT.to_owned()
                        }
                    })
                    .into_owned();
            } else {
                text = pattern.replace_all(&text, *replacement).into_owned();
            }
        }
        text
    }
    pub(super) fn value(&self, value: &mut Value) {
        self.value_at(value, 0);
    }
    fn value_at(&self, value: &mut Value, depth: usize) {
        if depth >= MAX_DEPTH {
            *value = Value::String(OMITTED.into());
            return;
        }
        match value {
            Value::String(text) => *text = self.text(text, depth),
            Value::Array(values) => values
                .iter_mut()
                .for_each(|value| self.value_at(value, depth + 1)),
            Value::Object(values) => {
                let original = std::mem::take(values);
                for (key, mut value) in original {
                    if self.sensitive_key.is_match(&key) && !value.is_null() {
                        value = Value::String("[redacted]".into());
                    } else if !(key == "name"
                        && value
                            .as_str()
                            .is_some_and(|name| super::logs::log_name(name.as_ref())))
                    {
                        // Validated runtime log filenames are generated metadata,
                        // not opaque credential values; retain their correlation.
                        self.value_at(&mut value, depth + 1);
                    }
                    values.insert(self.text(&key, depth + 1), value);
                }
            }
            _ => (),
        }
    }
}

/// Matches a short flat log tag like `[INFO]` or `[2026-11-26T00:00:00Z]`
/// containing no nested structured delimiters, quotes, escapes, or assignments.
fn benign_bracket_tag_end(text: &str) -> Option<usize> {
    if !text.starts_with('[') {
        return None;
    }
    let limit = text.floor_char_boundary(64);
    for (index, ch) in text[1..limit].char_indices() {
        match ch {
            ']' => return Some(index + 2),
            '[' | '{' | '}' | '"' | '\'' | '\\' | '=' | '\r' | '\n' => return None,
            _ => {}
        }
    }
    None
}

// A single linear scan isolates each candidate, including quoted scalar strings.
// Do not repeatedly parse overlapping suffixes of malformed text. The JSON
// parser validates delimiter types and has its own finite parsing depth bound.
fn structured_end(text: &str) -> Option<usize> {
    let mut depth = 0usize;
    let quote = if text.starts_with('\'') { '\'' } else { '"' };
    let mut quoted = false;
    let mut escaped = false;
    for (index, ch) in text.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote {
                quoted = false;
                if depth == 0 {
                    return Some(index + 1);
                }
            }
        } else {
            match ch {
                ch if ch == quote => quoted = true,
                '{' | '[' => depth += 1,
                '}' | ']' => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(index + 1);
                    }
                }
                _ => (),
            }
        }
    }
    None
}

// Top-level whitespace and prose separators end an assigned value; separators
// inside balanced containers or quoted segments do not. An unclosed segment
// consumes the suffix rather than publishing an uncertain partial credential.
fn assigned_end(text: &str) -> usize {
    let mut remaining = text;
    while let Some(ch) = remaining.chars().next() {
        if ch.is_whitespace() || matches!(ch, ',' | ';' | ']' | '}') {
            break;
        }
        if matches!(ch, '{' | '[' | '"' | '\'') {
            let Some(end) = structured_end(remaining) else {
                return text.len();
            };
            remaining = &remaining[end..];
        } else {
            remaining = &remaining[ch.len_utf8()..];
        }
    }
    text.len() - remaining.len()
}

fn compile_pattern(pattern: &str) -> Result<Regex> {
    Regex::new(pattern).map_err(|_| {
        scope::unreadable(
            "diagnostic redaction",
            "built-in redaction pattern is invalid; no export was written",
        )
    })
}

fn compile_paths(cx: &Bootstrap, project_roots: &[String]) -> Result<Vec<Regex>> {
    let mut roots = vec![cx.home.clone(), cx.cwd.clone()];
    for root in project_roots {
        roots.push(root.into());
    }
    for key in ["HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"] {
        if let Some(value) = std::env::var_os(key).filter(|value| !value.is_empty()) {
            roots.push(value.into());
        }
    }
    let mut roots: Vec<String> = roots
        .into_iter()
        // Compare only the displayed diagnostic text, never a native path.
        // This also removes replacement-character renderings of non-UTF-8 homes.
        .map(|path| path.to_string_lossy().into_owned())
        .filter(|path| path.len() > 1)
        .collect();
    roots.sort_by_key(|path| std::cmp::Reverse(path.len()));
    roots.dedup();
    let mut paths = Vec::new();
    for root in roots {
        for variant in [
            root.clone(),
            root.replace('\\', "/"),
            root.replace('\\', "\\\\"),
        ] {
            paths.push(compile_pattern(&format!(
                r#"(?i){}(?:[\\/]+[^\r\n"'<>]*)?"#,
                regex::escape(&variant)
            ))?);
        }
    }
    Ok(paths)
}

fn compile_remotes(remotes: &[String]) -> Result<Vec<Regex>> {
    let mut remote_values = Vec::new();
    for remote in remotes {
        if !remote.is_empty() {
            remote_values.push(remote.clone());
            if let Some((_, host)) = remote.split_once('@')
                && !host.is_empty()
                && !matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
            {
                remote_values.push(host.to_owned());
            }
        }
    }
    remote_values.sort_by_key(|value| std::cmp::Reverse(value.len()));
    remote_values.dedup();
    let mut remote_patterns = Vec::new();
    for remote in remote_values {
        remote_patterns.push(compile_pattern(&format!("(?i){}", regex::escape(&remote)))?);
    }
    Ok(remote_patterns)
}

fn is_uuid(bytes: &[u8]) -> bool {
    bytes.len() == 36
        && [8usize, 13, 18, 23].iter().all(|at| bytes[*at] == b'-')
        && (0..8).all(|at| bytes[at].is_ascii_hexdigit())
        && (9..13).all(|at| bytes[at].is_ascii_hexdigit())
        && (14..18).all(|at| bytes[at].is_ascii_hexdigit())
        && (19..23).all(|at| bytes[at].is_ascii_hexdigit())
        && (24..36).all(|at| bytes[at].is_ascii_hexdigit())
}

// A long token keeps its value only in known identifier shapes: a 40-char
// commit SHA or 64-char SHA-256 digest in hex, a hyphenated 36-char UUID, or a
// StateEngine typed ID (`<prefix>_<uuid>`). Anything else stays removed.
fn keeps_opaque(token: &str) -> bool {
    let bytes = token.as_bytes();
    if matches!(bytes.len(), 40 | 64) && bytes.iter().all(u8::is_ascii_hexdigit) {
        return true;
    }
    if is_uuid(bytes) {
        return true;
    }
    token.split_once('_').is_some_and(|(prefix, rest)| {
        (2..=6).contains(&prefix.len())
            && prefix.bytes().all(|byte| byte.is_ascii_lowercase())
            && is_uuid(rest.as_bytes())
    })
}
