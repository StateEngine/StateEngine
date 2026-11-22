//! JavaScript and TypeScript outline rules: functions, classes and members,
//! interfaces, type aliases, enums, namespaces, and arrow functions bound to
//! `const`/`let`/`var`.
use super::outline::{Decl, Scope, SymbolKind, ident, skip_group};

const MODIFIERS: &[&str] = &[
    "export",
    "default",
    "declare",
    "abstract",
    "async",
    "public",
    "private",
    "protected",
    "static",
    "readonly",
    "override",
    "accessor",
];

const NOT_MEMBERS: &[&str] = &[
    "if", "for", "while", "switch", "catch", "return", "function", "new", "await", "typeof",
    "with", "do", "else", "try", "super", "this",
];

pub(crate) fn classify(header: &str, _raw: &str, scope: Scope) -> Option<Decl> {
    let text = strip_decorators(header);
    let exported = text.starts_with("export") && scope.top_level;
    let mut rest = text;
    loop {
        let (word, after) = split_word(rest);
        if !MODIFIERS.contains(&word) {
            break;
        }
        rest = after;
    }
    let (word, after) = split_word(rest);
    let named = |kind| Decl::new(ident(after.trim_start()), kind, exported);
    match word {
        "function" | "function*" => {
            let name = ident(after.trim_start().trim_start_matches('*').trim_start());
            Decl::new(or_default(name), SymbolKind::Function, exported)
        }
        "class" => {
            let name = ident(after.trim_start());
            let name = if matches!(name, "extends" | "implements") {
                ""
            } else {
                name
            };
            Decl::new(or_default(name), SymbolKind::Class, exported)
        }
        "interface" => named(SymbolKind::Interface),
        "enum" => named(SymbolKind::Enum),
        "namespace" | "module" => named(SymbolKind::Namespace),
        "type" if after.contains('=') => named(SymbolKind::Type),
        "const" | "let" | "var" => binding(word, after, scope, exported),
        _ if scope.in_type() => member(rest),
        _ => None,
    }
}

fn or_default(name: &str) -> &str {
    if name.is_empty() { "default" } else { name }
}

fn binding(word: &str, after: &str, scope: Scope, exported: bool) -> Option<Decl> {
    let after = after.trim_start();
    if let Some(rest) = after.strip_prefix("enum") {
        return Decl::new(ident(rest.trim_start()), SymbolKind::Enum, exported);
    }
    let name = ident(after);
    let value = after.find('=').map(|at| after[at + 1..].trim_start());
    let function = value.is_some_and(|value| {
        value.starts_with("function") || value.starts_with("async") || after.contains("=>")
    });
    let kind = if function {
        SymbolKind::Function
    } else if !scope.top_level {
        return None;
    } else if word == "const" {
        SymbolKind::Const
    } else {
        SymbolKind::Variable
    };
    Decl::new(name, kind, exported)
}

fn member(rest: &str) -> Option<Decl> {
    let rest = rest.trim_start();
    let (word, after) = split_word(rest);
    let candidate = if matches!(word, "get" | "set") && !ident(after.trim_start()).is_empty() {
        after.trim_start()
    } else {
        rest
    };
    let name = ident(candidate.trim_start_matches(['*', '#']));
    if name.is_empty() || NOT_MEMBERS.contains(&name) {
        return None;
    }
    let tail = candidate.trim_start_matches(['*', '#'])[name.len()..]
        .trim_start()
        .trim_start_matches(['?', '!'])
        .trim_start();
    let tail = if tail.starts_with('<') {
        skip_group(tail, b'<', b'>').trim_start()
    } else {
        tail
    };
    let method = tail.starts_with('(') || (tail.starts_with('=') && tail.contains("=>"));
    method
        .then(|| Decl::new(name, SymbolKind::Method, false))
        .flatten()
}

fn strip_decorators(mut text: &str) -> &str {
    loop {
        text = text.trim_start();
        let Some(rest) = text.strip_prefix('@') else {
            return text;
        };
        let name_len = rest
            .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.' || c == '$'))
            .unwrap_or(rest.len());
        let after = rest[name_len..].trim_start();
        text = if after.starts_with('(') {
            skip_group(after, b'(', b')')
        } else {
            after
        };
    }
}

fn split_word(text: &str) -> (&str, &str) {
    let text = text.trim_start();
    let end = text
        .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$' || c == '*'))
        .unwrap_or(text.len());
    (&text[..end], &text[end..])
}
