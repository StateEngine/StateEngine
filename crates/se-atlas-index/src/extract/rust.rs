//! Rust outline rules: items, `impl` blocks named by their self type, trait
//! and impl methods, and bodyless `mod`, `struct`, `type`, `const` items.
use super::outline::{Decl, Scope, SymbolKind, ident, skip_group};

pub(crate) fn classify(header: &str, _raw: &str, scope: Scope) -> Option<Decl> {
    let rest = strip_attributes(header);
    let (exported, rest) = visibility(rest);
    let rest = qualifiers(rest);
    let (keyword, after) = split_word(rest);
    let name = ident(after.trim_start());
    let kind = match keyword {
        "fn" if scope.in_type() => SymbolKind::Method,
        "fn" => SymbolKind::Function,
        "struct" | "union" => SymbolKind::Struct,
        "enum" if !scope.statement => SymbolKind::Enum,
        "trait" if !scope.statement => SymbolKind::Interface,
        "mod" => SymbolKind::Module,
        "type" => SymbolKind::Type,
        "const" => SymbolKind::Const,
        "static" => SymbolKind::Variable,
        "macro_rules!" => SymbolKind::Macro,
        "impl" if !scope.statement => {
            return Decl::new(impl_name(after), SymbolKind::Impl, false);
        }
        _ => return None,
    };
    if name == "_" {
        return None;
    }
    Decl::new(name, kind, exported)
}

fn strip_attributes(mut text: &str) -> &str {
    loop {
        text = text.trim_start();
        let Some(rest) = text.strip_prefix('#') else {
            return text;
        };
        let rest = rest.strip_prefix('!').unwrap_or(rest).trim_start();
        if !rest.starts_with('[') {
            return text;
        }
        text = skip_group(rest, b'[', b']');
    }
}

/// `pub` exports; `pub(crate)` and other restricted forms do not.
fn visibility(text: &str) -> (bool, &str) {
    let Some(rest) = text.strip_prefix("pub") else {
        return (false, text);
    };
    let trimmed = rest.trim_start();
    if trimmed.starts_with('(') {
        return (false, skip_group(trimmed, b'(', b')'));
    }
    if rest.starts_with(char::is_whitespace) {
        return (true, trimmed);
    }
    (false, text)
}

/// Drop `const`, `async`, `unsafe`, `default` and `extern "ABI"` when they
/// qualify a following `fn`, `impl` or `trait`.
fn qualifiers(mut text: &str) -> &str {
    loop {
        let (word, rest) = split_word(text);
        let qualifier = matches!(word, "async" | "unsafe" | "default" | "extern")
            || (word == "const" && next_is_item(rest));
        if !qualifier || (word == "extern" && rest.trim_start().starts_with("crate")) {
            return text;
        }
        text = skip_abi(rest.trim_start());
    }
}

fn next_is_item(rest: &str) -> bool {
    let (next, _) = split_word(rest);
    matches!(
        next,
        "fn" | "unsafe" | "async" | "extern" | "impl" | "trait"
    )
}

/// Skip a masked ABI string such as `"C"` (its interior is blank).
fn skip_abi(text: &str) -> &str {
    let Some(rest) = text.strip_prefix('"') else {
        return text;
    };
    rest.find('"')
        .map_or(rest, |close| &rest[close + 1..])
        .trim_start()
}

fn split_word(text: &str) -> (&str, &str) {
    let text = text.trim_start();
    let end = text
        .find(|c: char| c.is_whitespace() || c == '<' || c == '(' || c == '{')
        .unwrap_or(text.len());
    (&text[..end], &text[end..])
}

/// The self type of an `impl` header: `impl<T> Trait for path::Type<T>` names
/// `Type`.
fn impl_name(after: &str) -> &str {
    let mut rest = after.trim_start();
    if rest.starts_with('<') {
        rest = skip_group(rest, b'<', b'>').trim_start();
    }
    let target = top_level_for(rest).map_or(rest, |at| &rest[at + 3..]);
    let target = target
        .trim_start()
        .trim_start_matches(['&', ' '])
        .trim_start_matches("mut ")
        .trim_start_matches("dyn ");
    let path_end = target
        .find(|c: char| c == '<' || c.is_whitespace() || c == '{')
        .unwrap_or(target.len());
    let path = &target[..path_end];
    ident(path.rsplit("::").next().unwrap_or(path))
}

fn top_level_for(text: &str) -> Option<usize> {
    let mut depth = 0i32;
    let bytes = text.as_bytes();
    let space = |at: Option<&u8>| at.is_some_and(u8::is_ascii_whitespace);
    for i in 0..bytes.len() {
        match bytes[i] {
            b'<' => depth += 1,
            b'>' => depth -= 1,
            b'f' if depth == 0
                && text[i..].starts_with("for")
                && i > 0
                && space(bytes.get(i - 1))
                && space(bytes.get(i + 3)) =>
            {
                return Some(i);
            }
            _ => {}
        }
    }
    None
}
