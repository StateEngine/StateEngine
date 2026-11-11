//! A single pre-publication redaction pass for every exported string, including errors.
use crate::bootstrap::Bootstrap;
use regex::Regex;
use se_core::scope;
use se_types::Result;
use serde_json::Value;

const SENSITIVE_LABEL: &str = r"token|secret|password|passwd|passphrase|credential|api[ _-]?key|access[ _-]?key|private[ _-]?key|authorization|cookie";

pub(super) struct Redactor {
    sensitive_key: Regex,
    replacements: Vec<(Regex, &'static str)>,
    paths: Vec<Regex>,
}
impl Redactor {
    pub(super) fn new(cx: &Bootstrap) -> Result<Self> {
        let compile = |pattern: &str| {
            Regex::new(pattern).map_err(|_| {
                scope::unreadable(
                    "diagnostic redaction",
                    "built-in redaction pattern is invalid; no export was written",
                )
            })
        };
        // One vocabulary covers structured fields, assignments and CLI flags.
        let assignment = format!(
            r#"(?is)(["']?[a-z0-9_-]*(?:{SENSITIVE_LABEL})[a-z0-9_-]*["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;\]}}]+)"#
        );
        let flag = format!(
            r#"(?i)(--[a-z0-9_-]*(?:{SENSITIVE_LABEL})[a-z0-9_-]*\s+)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s]+)"#
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
            // Long opaque values are conservatively removed even without labels.
            (r"\b[A-Za-z0-9_+/=-]{32,}\b", "[redacted opaque value]"),
            (
                r#"(?i)(?:[A-Z]:[\\/]+(?:Users|Documents and Settings)[\\/]+|/(?:home|Users)/)[^\r\n"'<>]+"#,
                "[redacted home path]",
            ),
            (r#"/root\b(?:/[^\r\n"'<>]*)?"#, "[redacted home path]"),
        ] {
            replacements.push((compile(pattern)?, replacement));
        }
        let mut roots = vec![cx.home.clone(), cx.cwd.clone()];
        for key in ["HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"] {
            if let Some(value) = std::env::var_os(key).filter(|value| !value.is_empty()) {
                roots.push(value.into());
            }
        }
        let mut roots: Vec<String> = roots
            .into_iter()
            .filter_map(|path| path.to_str().map(str::to_owned))
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
                paths.push(compile(&format!("(?i){}", regex::escape(&variant)))?);
            }
        }
        Ok(Self {
            sensitive_key: compile(&format!("(?i)({SENSITIVE_LABEL})"))?,
            replacements,
            paths,
        })
    }
    fn text(&self, text: &str) -> String {
        let mut text = text.to_owned();
        // Exact known paths precede generic patterns so even a space-bearing
        // selected home is completely removed from diagnosis prose.
        for path in &self.paths {
            text = path.replace_all(&text, "[redacted path]").into_owned();
        }
        for (pattern, replacement) in &self.replacements {
            text = pattern.replace_all(&text, *replacement).into_owned();
        }
        text
    }
    pub(super) fn value(&self, value: &mut Value) {
        match value {
            Value::String(text) => *text = self.text(text),
            Value::Array(values) => values.iter_mut().for_each(|value| self.value(value)),
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
                        self.value(&mut value);
                    }
                    values.insert(self.text(&key), value);
                }
            }
            _ => (),
        }
    }
}
