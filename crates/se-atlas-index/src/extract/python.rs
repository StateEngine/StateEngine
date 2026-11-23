//! Python outline by indentation: classes, functions and methods, and
//! top-level assignments. Bracketed and backslash-continued lines belong to
//! the logical line that opened them.
use super::outline::{Builder, Decl, SymbolKind, ident};

struct Open {
    index: usize,
    indent: usize,
    start: usize,
}

pub(crate) fn outline(text: &str, masked: &str, builder: &mut Builder<'_>) {
    let mut stack: Vec<Open> = Vec::new();
    let mut depth = 0i32;
    let mut continued = false;
    let mut last_end = 0usize;
    let mut offset = 0usize;
    for (line, raw) in masked.split_inclusive('\n').zip(text.split_inclusive('\n')) {
        let start = offset;
        offset += line.len();
        let content = line.trim_end();
        let continuation = depth > 0 || continued;
        depth = (depth + bracket_balance(content)).max(0);
        continued = content.ends_with('\\');
        if content.trim().is_empty() {
            // String lines still belong to the body; comments do not.
            let raw = raw.trim();
            if !raw.is_empty() && !raw.starts_with('#') {
                last_end = start + line.trim_end_matches(['\n', '\r']).len();
            }
            continue;
        }
        if !continuation {
            let indent = indent_width(content);
            while stack.last().is_some_and(|open| open.indent >= indent) {
                if let Some(open) = stack.pop() {
                    builder.close(open.index, (open.start, last_end));
                }
            }
            let parent = stack.last().map(|open| open.index);
            let header = (
                start + content.len() - content.trim_start().len(),
                start + content.len(),
            );
            let parent_kind = parent
                .and_then(|index| builder.symbols.get(index))
                .map(|s| s.kind);
            if let Some(decl) = classify(content.trim_start(), indent, parent_kind)
                && let Some(index) = builder.open(decl, header, parent)
            {
                stack.push(Open {
                    index,
                    indent,
                    start: header.0,
                });
            }
        }
        last_end = start + content.len();
    }
    while let Some(open) = stack.pop() {
        builder.close(open.index, (open.start, last_end));
    }
}

fn classify(line: &str, indent: usize, parent: Option<SymbolKind>) -> Option<Decl> {
    let line = line.strip_prefix("async ").unwrap_or(line).trim_start();
    if let Some(rest) = line.strip_prefix("def ") {
        let name = ident(rest.trim_start());
        let kind = if parent == Some(SymbolKind::Class) {
            SymbolKind::Method
        } else {
            SymbolKind::Function
        };
        return Decl::new(name, kind, !name.starts_with('_'));
    }
    if let Some(rest) = line.strip_prefix("class ") {
        let name = ident(rest.trim_start());
        return Decl::new(name, SymbolKind::Class, !name.starts_with('_'));
    }
    if indent != 0 {
        return None;
    }
    let name = ident(line);
    let after = line[name.len()..].trim_start();
    let assigns = (after.starts_with('=') && !after.starts_with("=="))
        || (after.starts_with(':') && after.contains('='));
    if name.is_empty() || !assigns || name.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return None;
    }
    let constant = name
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    let kind = if constant {
        SymbolKind::Const
    } else {
        SymbolKind::Variable
    };
    Decl::new(name, kind, !name.starts_with('_'))
}

fn indent_width(line: &str) -> usize {
    line.chars()
        .take_while(|c| *c == ' ' || *c == '\t')
        .map(|c| if c == '\t' { 4 } else { 1 })
        .sum()
}

fn bracket_balance(line: &str) -> i32 {
    line.bytes().fold(0, |balance, b| match b {
        b'(' | b'[' | b'{' => balance + 1,
        b')' | b']' | b'}' => balance - 1,
        _ => balance,
    })
}
