//! Syntactic outlines for structured text: Markdown headings, TOML tables and
//! keys, YAML keys (including CI `jobs.*` and `steps[].name`), JSON keys, SQL
//! `CREATE` statements, Makefile targets, Dockerfile stages and shell
//! functions. Unknown text gets a heading scan.
use super::{
    Grammar,
    outline::{Builder, Decl, Scope, SymbolKind},
};

/// Nested keys deeper than this are not outlined.
const MAX_KEY_DEPTH: usize = 4;

pub(crate) fn outline(grammar: Grammar, text: &str, masked: &str, builder: &mut Builder<'_>) {
    match grammar {
        Grammar::Markdown => headings(text, true, builder),
        Grammar::Toml => toml(text, masked, builder),
        Grammar::Yaml => yaml(text, masked, builder),
        Grammar::Json => json(text, masked, builder),
        Grammar::Sql => sql(text, masked, builder),
        Grammar::Makefile => makefile(masked, builder),
        Grammar::Dockerfile => dockerfile(text, masked, builder),
        _ => headings(text, false, builder),
    }
}

/// Lines with their starting byte offsets, newline removed.
fn lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut offset = 0;
    text.split_inclusive('\n').map(move |line| {
        let start = offset;
        offset += line.len();
        (start, line.trim_end_matches(['\n', '\r']))
    })
}

/// Open sections closed when a sibling or an ancestor starts.
struct Sections {
    stack: Vec<(usize, usize, usize)>,
    last_end: usize,
}

impl Sections {
    fn new() -> Self {
        Self {
            stack: Vec::new(),
            last_end: 0,
        }
    }

    fn close_from(&mut self, level: usize, builder: &mut Builder<'_>) {
        while self.stack.last().is_some_and(|(open, ..)| *open >= level) {
            if let Some((_, index, start)) = self.stack.pop() {
                builder.close(index, (start, self.last_end));
            }
        }
    }

    fn parent(&self) -> Option<usize> {
        self.stack.last().map(|(_, index, _)| *index)
    }

    fn open(
        &mut self,
        level: usize,
        decl: Option<Decl>,
        header: (usize, usize),
        builder: &mut Builder<'_>,
    ) {
        let parent = self.parent();
        if let Some(index) = decl.and_then(|decl| builder.open(decl, header, parent)) {
            self.stack.push((level, index, header.0));
        }
    }

    fn seen(&mut self, end: usize) {
        self.last_end = end;
    }

    fn finish(mut self, builder: &mut Builder<'_>) {
        self.close_from(0, builder);
    }
}

fn section(name: &str, kind: SymbolKind) -> Option<Decl> {
    Decl::new(name.trim(), kind, true)
}

fn headings(text: &str, fences: bool, builder: &mut Builder<'_>) {
    let mut sections = Sections::new();
    let mut fenced = false;
    for (start, line) in lines(text) {
        let trimmed = line.trim_start();
        if fences && (trimmed.starts_with("```") || trimmed.starts_with("~~~")) {
            fenced = !fenced;
        } else if !fenced && let Some((level, title)) = heading(line) {
            sections.close_from(level, builder);
            let decl = section(title, SymbolKind::Section);
            sections.open(level, decl, (start, start + line.len()), builder);
        }
        if !line.trim().is_empty() {
            sections.seen(start + line.len());
        }
    }
    sections.finish(builder);
}

fn heading(line: &str) -> Option<(usize, &str)> {
    let level = line.bytes().take_while(|b| *b == b'#').count();
    let rest = &line[level..];
    let valid = (1..=6).contains(&level) && (rest.is_empty() || rest.starts_with([' ', '\t']));
    let title = rest.trim().trim_end_matches('#').trim();
    (valid && !title.is_empty()).then_some((level, title))
}

fn toml(text: &str, masked: &str, builder: &mut Builder<'_>) {
    let mut sections = Sections::new();
    let mut depth = 0i32;
    for ((start, line), (_, raw)) in lines(masked).zip(lines(text)) {
        let trimmed = line.trim();
        if depth > 0 {
            depth += balance(line);
        } else if trimmed.starts_with('[') {
            sections.close_from(0, builder);
            let name = raw.trim().trim_matches(['[', ']']).trim();
            sections.open(
                0,
                section(name, SymbolKind::Table),
                (start, start + line.len()),
                builder,
            );
        } else if let Some(eq) = line.find('=').filter(|eq| !line[..*eq].trim().is_empty()) {
            let key = raw[..eq].trim().trim_matches(['"', '\'']);
            sections.close_from(1, builder);
            sections.open(
                1,
                section(key, SymbolKind::Key),
                (start, start + line.len()),
                builder,
            );
            depth = balance(&line[eq..]).max(0);
        }
        if !trimmed.is_empty() {
            sections.seen(start + line.len());
        }
    }
    sections.finish(builder);
}

fn balance(text: &str) -> i32 {
    text.bytes().fold(0, |sum, b| match b {
        b'[' | b'{' => sum + 1,
        b']' | b'}' => sum - 1,
        _ => sum,
    })
}

fn yaml(text: &str, masked: &str, builder: &mut Builder<'_>) {
    let mut sections = Sections::new();
    let mut block: Option<usize> = None;
    for ((start, line), (_, raw)) in lines(masked).zip(lines(text)) {
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if block.is_some_and(|key_indent| indent > key_indent) {
            sections.seen(start + line.len());
            continue;
        }
        block = None;
        let trimmed = line.trim_start();
        if trimmed == "---" || trimmed == "..." {
            sections.close_from(0, builder);
            continue;
        }
        // A list item sits one level inside a key at its own indent, which
        // keeps indentless sequences under their key.
        let item = trimmed.starts_with("- ") || trimmed == "-";
        let level = indent + usize::from(item);
        sections.close_from(level, builder);
        if let Some((decl, block_scalar)) = yaml_entry(trimmed, raw.get(indent..).unwrap_or("")) {
            if block_scalar {
                block = Some(indent);
            }
            if sections.stack.len() < MAX_KEY_DEPTH {
                sections.open(level, Some(decl), (start, start + line.len()), builder);
            }
        }
        sections.seen(start + line.len());
    }
    sections.finish(builder);
}

/// One YAML line: a mapping key, or a list item named by its `name:` key.
fn yaml_entry(masked: &str, raw: &str) -> Option<(Decl, bool)> {
    let item = masked.starts_with("- ") || masked == "-";
    let skip = if item {
        masked.len() - masked[1..].trim_start().len()
    } else {
        0
    };
    let body = &masked[skip..];
    let raw_body = raw.get(skip..).unwrap_or("");
    let colon = body
        .match_indices(':')
        .map(|(at, _)| at)
        .find(|at| body[at + 1..].is_empty() || body[at + 1..].starts_with([' ', '\t']))?;
    let key = raw_body.get(..colon)?.trim().trim_matches(['"', '\'']);
    let value = raw_body.get(colon + 1..).unwrap_or("").trim();
    let block_scalar = value.starts_with('|') || value.starts_with('>');
    if key.is_empty() || key.starts_with(['{', '[', '#']) {
        return None;
    }
    let decl = if item && key == "name" && !value.is_empty() {
        section(value.trim_matches(['"', '\'']), SymbolKind::Item)
    } else {
        section(key, SymbolKind::Key)
    }?;
    Some((decl, block_scalar))
}

fn json(text: &str, masked: &str, builder: &mut Builder<'_>) {
    // (is_object, symbol opened by the key that owns this container)
    let mut stack: Vec<(bool, Option<(usize, usize)>)> = Vec::new();
    let mut last_string: Option<(usize, usize)> = None;
    let mut pending: Option<(usize, usize)> = None;
    let bytes = masked.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                let close = masked[i + 1..]
                    .find('"')
                    .map_or(bytes.len(), |at| i + 1 + at);
                last_string = Some((i, close));
                i = close + 1;
                continue;
            }
            b':' => {
                pending = json_key(text, last_string.take(), &stack, builder);
            }
            b'{' | b'[' => stack.push((bytes[i] == b'{', pending.take())),
            b'}' | b']' => {
                if let Some((_, Some((index, start)))) = stack.pop() {
                    builder.close(index, (start, i + 1));
                }
            }
            b',' => pending = None,
            b if !b.is_ascii_whitespace() => last_string = None,
            _ => {}
        }
        i += 1;
    }
}

fn json_key(
    text: &str,
    key: Option<(usize, usize)>,
    stack: &[(bool, Option<(usize, usize)>)],
    builder: &mut Builder<'_>,
) -> Option<(usize, usize)> {
    let (open, close) = key?;
    let in_object = stack.last().is_some_and(|(object, _)| *object);
    if !in_object || stack.len() > MAX_KEY_DEPTH - 1 {
        return None;
    }
    let name = text.get(open + 1..close)?;
    let parent = stack.iter().rev().find_map(|(_, owner)| owner.map(|o| o.0));
    let index = builder.open(section(name, SymbolKind::Key)?, (open, close + 1), parent)?;
    builder.close(index, (open, close + 1));
    Some((index, open))
}

fn sql(text: &str, masked: &str, builder: &mut Builder<'_>) {
    let mut start = 0;
    for (end, _) in masked.match_indices(';').chain([(masked.len(), "")]) {
        if let Some((decl, header)) = sql_create(text, masked, start, end)
            && let Some(index) = builder.open(decl, header, None)
        {
            builder.close(index, (header.0, (end + 1).min(masked.len())));
        }
        start = end + 1;
    }
}

const SQL_FILLER: &[&str] = &[
    "OR",
    "REPLACE",
    "TEMP",
    "TEMPORARY",
    "UNIQUE",
    "MATERIALIZED",
    "VIRTUAL",
    "GLOBAL",
    "LOCAL",
    "RECURSIVE",
    "IF",
    "NOT",
    "EXISTS",
    "UNLOGGED",
];

fn sql_create(
    text: &str,
    masked: &str,
    start: usize,
    end: usize,
) -> Option<(Decl, (usize, usize))> {
    let statement = masked.get(start..end)?;
    let mut words = statement
        .split_whitespace()
        .map(|word| (word.as_ptr() as usize - masked.as_ptr() as usize, word));
    let (create_at, create) = words.next()?;
    if !create.eq_ignore_ascii_case("create") {
        return None;
    }
    let mut kind = None;
    for (at, word) in words {
        let upper = word.to_ascii_uppercase();
        if kind.is_none() {
            if SQL_FILLER.contains(&upper.as_str()) {
                continue;
            }
            kind = Some(sql_kind(&upper)?);
            continue;
        }
        if SQL_FILLER.contains(&upper.as_str()) {
            continue;
        }
        let raw = text.get(at..at + word.len())?;
        let name = raw
            .split('(')
            .next()
            .unwrap_or(raw)
            .trim_matches(['"', '`', '[', ']', '\'']);
        return Some((section(name, kind?)?, (create_at, at + word.len())));
    }
    None
}

fn sql_kind(word: &str) -> Option<SymbolKind> {
    Some(match word {
        "TABLE" | "VIEW" => SymbolKind::Table,
        "INDEX" => SymbolKind::Key,
        "FUNCTION" | "PROCEDURE" | "TRIGGER" => SymbolKind::Function,
        "TYPE" | "DOMAIN" => SymbolKind::Type,
        "SCHEMA" => SymbolKind::Namespace,
        "SEQUENCE" => SymbolKind::Variable,
        _ => return None,
    })
}

fn makefile(masked: &str, builder: &mut Builder<'_>) {
    let mut sections = Sections::new();
    for (start, line) in lines(masked) {
        if line.starts_with('\t') {
            sections.seen(start + line.len());
            continue;
        }
        if line.trim().is_empty() || line.starts_with([' ', '#']) {
            continue;
        }
        sections.close_from(0, builder);
        let header = (start, start + line.len());
        if let Some(name) = make_variable(line) {
            sections.open(0, section(name, SymbolKind::Variable), header, builder);
        } else if let Some((targets, _)) = line.split_once(':') {
            let target = targets
                .split_whitespace()
                .find(|t| !t.starts_with('.') && !t.contains(['%', '$']));
            if let Some(target) = target {
                sections.open(0, section(target, SymbolKind::Target), header, builder);
            }
        }
        sections.seen(start + line.len());
    }
    sections.finish(builder);
}

fn make_variable(line: &str) -> Option<&str> {
    let eq = line.find('=')?;
    let colon = line.find(':');
    let assignment = colon.is_none_or(|colon| colon + 1 >= eq);
    let name = line[..eq].trim_end_matches([':', '?', '+', '!']).trim();
    let name = name.strip_prefix("export ").unwrap_or(name);
    let name = name.strip_prefix("override ").unwrap_or(name).trim();
    (assignment && !name.is_empty() && !name.contains(char::is_whitespace)).then_some(name)
}

fn dockerfile(text: &str, masked: &str, builder: &mut Builder<'_>) {
    let mut sections = Sections::new();
    let mut continued = false;
    for ((start, line), (_, raw)) in lines(masked).zip(lines(text)) {
        let was_continued = continued;
        continued = line.trim_end().ends_with('\\');
        if was_continued || line.trim().is_empty() {
            continue;
        }
        let (instruction, rest) = raw
            .trim_start()
            .split_once(char::is_whitespace)
            .unwrap_or((raw, ""));
        let header = (start, start + line.len());
        match instruction.to_ascii_uppercase().as_str() {
            "FROM" => {
                sections.close_from(0, builder);
                let words: Vec<&str> = rest
                    .split_whitespace()
                    .filter(|w| !w.starts_with("--"))
                    .collect();
                let alias = words
                    .iter()
                    .position(|w| w.eq_ignore_ascii_case("as"))
                    .and_then(|at| words.get(at + 1));
                let name = alias.or(words.first()).copied().unwrap_or("");
                sections.open(0, section(name, SymbolKind::Stage), header, builder);
            }
            "ARG" | "ENV" => {
                let name = rest
                    .trim_start()
                    .split(['=', ' ', '\t'])
                    .next()
                    .unwrap_or("");
                let parent = sections.parent();
                if let Some(decl) = section(name, SymbolKind::Variable)
                    && let Some(index) = builder.open(decl, header, parent)
                {
                    builder.close(index, header);
                }
            }
            _ => {}
        }
        sections.seen(start + line.len());
    }
    sections.finish(builder);
}

/// Shell functions: `name() {` and `function name {`.
pub(crate) fn classify_shell(header: &str, _raw: &str, scope: Scope) -> Option<Decl> {
    if scope.statement {
        return None;
    }
    let line = header.lines().last().unwrap_or(header).trim();
    let name = if let Some(rest) = line.strip_prefix("function ") {
        shell_name(rest.trim_start())
    } else {
        let before = line
            .strip_suffix("()")
            .or_else(|| line.split_once("()").map(|(n, _)| n))?;
        let name = shell_name(before.trim());
        if name.len() != before.trim().len() {
            return None;
        }
        name
    };
    Decl::new(name, SymbolKind::Function, true)
}

fn shell_name(text: &str) -> &str {
    let end = text
        .find(|c: char| !(c.is_alphanumeric() || matches!(c, '_' | '-' | ':' | '.')))
        .unwrap_or(text.len());
    &text[..end]
}
