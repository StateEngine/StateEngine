//! Explicit loaded policy and retained .gitignore inputs only. No ambient Git
//! configuration, environment filename, subprocess or unbounded compiled regex.
use super::*;
use std::io::Read;
struct Rule {
    base: String,
    pattern: String,
    negated: bool,
    directory: bool,
    anchored: bool,
}
pub(super) struct Rules {
    rules: Vec<Rule>,
    used: usize,
}
impl Rules {
    pub(super) fn load(
        source: &Source,
        policy: &AtlasPolicy,
        parent: &str,
        deadline: Instant,
    ) -> AtlasResult<Self> {
        let mut rules = Self {
            rules: Vec::new(),
            used: policy
                .ignore
                .generated_prefixes
                .iter()
                .map(|p| p.as_str().len())
                .sum(),
        };
        rules.used += policy
            .ignore
            .global_patterns
            .iter()
            .map(String::len)
            .sum::<usize>();
        if !parent.is_empty()
            && se_atlas::policy::built_in_denied(&RelativePath::new(parent.to_owned())?)
        {
            return Ok(rules);
        }
        if let Some(metadata) = &source.scope.registration.git_metadata {
            let root = se_proc::NativeSourceRoot::open(&metadata.physical_common_directory)
                .map_err(|e| source_error("registered Git metadata", e))?;
            if root
                .physical_identity()
                .map_err(|e| source_error("registered Git metadata", e))?
                != metadata.common_directory_identity
            {
                return Err(source_error(
                    "registered Git metadata",
                    "physical root changed; rebind",
                ));
            }
            if let Some(mut file) = root
                .open_relative("info/exclude")
                .map_err(|e| source_error("info/exclude", e))?
            {
                let before = file
                    .revision()
                    .map_err(|e| source_error("info/exclude", e))?;
                let text = rules.read(&mut file, "info/exclude")?;
                if file
                    .revision()
                    .map_err(|e| source_error("info/exclude", e))?
                    != before
                    || !file
                        .validate_name()
                        .map_err(|e| source_error("info/exclude", e))?
                {
                    return Err(source_error("info/exclude", "changed during read"));
                }
                rules.append_text("", &text)?;
            }
        }
        rules.load_file(source, "", deadline)?;
        let mut end = 0;
        for component in parent.split('/').filter(|s| !s.is_empty()) {
            if end > 0 {
                end += 1;
            }
            end += component.len();
            let directory = &parent[..end];
            if !rules.eligible(directory, true, policy, deadline)? {
                break;
            }
            rules.load_file(source, directory, deadline)?;
        }
        Ok(rules)
    }
    fn read(&self, file: &mut dyn Read, path: &str) -> AtlasResult<String> {
        let remaining = 32768usize.saturating_sub(self.used);
        let mut text = String::new();
        file.take(remaining as u64 + 1)
            .read_to_string(&mut text)
            .map_err(|e| source_error(path, e))?;
        if text.len() > remaining {
            return Err(limit(
                "ignore policy",
                (self.used + text.len()) as u64,
                32768,
            ));
        }
        Ok(text)
    }
    fn load_file(&mut self, source: &Source, base: &str, deadline: Instant) -> AtlasResult<()> {
        timely(deadline)?;
        let path = RelativePath::new(if base.is_empty() {
            ".gitignore".into()
        } else {
            format!("{base}/.gitignore")
        })?;
        if let Some(mut file) = source.open(&path)? {
            let before = file.identity()?;
            let text = self.read(&mut *file, path.as_str())?;
            if file.identity()? != before || !file.validate_path()? {
                return Err(source_error(
                    path.as_str(),
                    "ignore input changed during read",
                ));
            }
            self.append_text(base, &text)?;
        }
        Ok(())
    }
    fn append_text(&mut self, base: &str, text: &str) -> AtlasResult<()> {
        for line in text.lines() {
            self.append(base, line)?;
        }
        Ok(())
    }
    fn append(&mut self, base: &str, pattern: &str) -> AtlasResult<()> {
        let Some(view) = parse(base, pattern) else {
            return Ok(());
        };
        let cost = std::mem::size_of::<Rule>() + view.base.len() + view.pattern.len();
        if self.used + cost > 32768 {
            return Err(limit("ignore policy", (self.used + cost) as u64, 32768));
        }
        self.rules.reserve_exact(1);
        self.rules.push(Rule {
            base: view.base.into(),
            pattern: view.pattern.into(),
            negated: view.negated,
            directory: view.directory,
            anchored: view.anchored,
        });
        self.used += cost;
        Ok(())
    }
    pub(super) fn eligible(
        &self,
        path: &str,
        directory: bool,
        policy: &AtlasPolicy,
        deadline: Instant,
    ) -> AtlasResult<bool> {
        if !path.is_empty()
            && se_atlas::policy::built_in_denied(&RelativePath::new(path.to_owned())?)
        {
            return Ok(false);
        }
        if policy.ignore.generated_prefixes.iter().any(|p| {
            path == p.as_str()
                || path
                    .strip_prefix(p.as_str())
                    .is_some_and(|s| s.starts_with('/'))
        }) {
            return Ok(false);
        }
        for end in path
            .match_indices('/')
            .map(|(at, _)| at)
            .chain(std::iter::once(path.len()))
        {
            let prefix = &path[..end];
            let dir = end < path.len() || directory;
            let mut ignored = false;
            for rule in policy
                .ignore
                .global_patterns
                .iter()
                .filter_map(|p| parse("", p))
                .chain(self.rules.iter().map(|r| RuleView {
                    base: &r.base,
                    pattern: &r.pattern,
                    negated: r.negated,
                    directory: r.directory,
                    anchored: r.anchored,
                }))
            {
                timely(deadline)?;
                if rule.directory && !dir {
                    continue;
                }
                let relative = if rule.base.is_empty() {
                    prefix
                } else if let Some(s) = prefix
                    .strip_prefix(rule.base)
                    .and_then(|s| s.strip_prefix('/'))
                {
                    s
                } else {
                    continue;
                };
                let name = if rule.anchored {
                    relative
                } else {
                    relative.rsplit('/').next().unwrap_or(relative)
                };
                if glob::matches(rule.pattern, name, deadline)? {
                    ignored = !rule.negated;
                }
            }
            // A negation cannot resurrect an excluded parent's descendants.
            if ignored {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

struct RuleView<'a> {
    base: &'a str,
    pattern: &'a str,
    negated: bool,
    directory: bool,
    anchored: bool,
}
fn parse<'a>(base: &'a str, mut pattern: &'a str) -> Option<RuleView<'a>> {
    pattern = pattern.strip_suffix('\r').unwrap_or(pattern);
    while pattern.ends_with(' ') {
        let slashes = pattern[..pattern.len() - 1]
            .bytes()
            .rev()
            .take_while(|b| *b == b'\\')
            .count();
        if slashes % 2 == 1 {
            break;
        }
        pattern = &pattern[..pattern.len() - 1];
    }
    if pattern.is_empty() || pattern.starts_with('#') {
        return None;
    }
    let negated = pattern.starts_with('!');
    if negated {
        pattern = &pattern[1..];
    }
    let directory = pattern.ends_with('/');
    if directory {
        pattern = &pattern[..pattern.len() - 1];
    }
    let anchored = pattern.contains('/');
    pattern = pattern.strip_prefix('/').unwrap_or(pattern);
    if pattern.is_empty() {
        return None;
    }
    Some(RuleView {
        base,
        pattern,
        negated,
        directory,
        anchored,
    })
}
