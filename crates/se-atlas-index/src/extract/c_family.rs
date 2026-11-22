//! Outline rules for C, C++, Java, C#, Kotlin and Zig: type declarations,
//! namespaces, functions and methods recognized by their parameter list.
use super::outline::{Decl, Scope, SymbolKind, before_paren, ident, keyword, skip_group};

const MODIFIERS: &[&str] = &[
    "public",
    "private",
    "protected",
    "internal",
    "static",
    "final",
    "abstract",
    "sealed",
    "open",
    "data",
    "inline",
    "virtual",
    "override",
    "extern",
    "constexpr",
    "consteval",
    "friend",
    "explicit",
    "export",
    "partial",
    "readonly",
    "async",
    "unsafe",
    "synchronized",
    "native",
    "transient",
    "volatile",
    "strictfp",
    "suspend",
    "operator",
    "infix",
    "tailrec",
    "lateinit",
    "annotation",
    "value",
    "inner",
    "default",
    "typedef",
    "pub",
    "noinline",
    "crossinline",
];

/// Words that start a statement, never a declaration.
const CONTROL: &[&str] = &[
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "return",
    "using",
    "lock",
    "foreach",
    "else",
    "do",
    "new",
    "throw",
    "case",
    "try",
    "when",
    "defer",
    "fixed",
    "checked",
    "unchecked",
    "assert",
    "delete",
    "goto",
    "await",
    "yield",
];

/// Words that look like a called name but never name a function.
const NOT_NAMES: &[&str] = &[
    "void",
    "sizeof",
    "typeof",
    "nameof",
    "alignof",
    "decltype",
    "static_assert",
    "synchronized",
];

pub(crate) fn classify_c(header: &str, _raw: &str, scope: Scope) -> Option<Decl> {
    let text = strip_preamble(header, true);
    let exported = scope.top_level && !text.split_whitespace().any(|w| w == "static");
    let rest = skip_modifiers(text);
    if let Some(decl) = type_decl(rest, scope, exported, false) {
        return Some(decl);
    }
    let prototype_scope = !scope.statement || scope.top_level || scope.in_type();
    prototype_scope
        .then(|| function(rest, scope, exported))
        .flatten()
}

pub(crate) fn classify_managed(header: &str, _raw: &str, scope: Scope) -> Option<Decl> {
    let text = strip_preamble(header, false);
    let exported = text.split_whitespace().any(|w| w == "public");
    let rest = skip_modifiers(text);
    if let Some(decl) = type_decl(rest, scope, exported, false) {
        return Some(decl);
    }
    (!scope.statement || scope.in_type())
        .then(|| function(rest, scope, exported))
        .flatten()
}

pub(crate) fn classify_kotlin(header: &str, _raw: &str, scope: Scope) -> Option<Decl> {
    let text = strip_preamble(header, false);
    let exported = !text
        .split_whitespace()
        .any(|w| w == "private" || w == "internal");
    let rest = skip_modifiers(text);
    if let Some(after) = keyword(rest, "fun") {
        let signature = before_paren(after)?;
        let signature = signature.trim();
        let signature = if signature.starts_with('<') {
            skip_group(signature, b'<', b'>').trim_start()
        } else {
            signature
        };
        let name = ident(signature.rsplit('.').next().unwrap_or(signature));
        let kind = method_or_function(scope);
        return Decl::new(name, kind, exported);
    }
    if let Some(after) = keyword(rest, "companion") {
        let rest = after.trim_start();
        let name = ident(keyword(rest, "object").unwrap_or(rest).trim_start());
        let name = if name.is_empty() { "Companion" } else { name };
        return Decl::new(name, SymbolKind::Class, exported);
    }
    type_decl(rest, scope, exported, true)
}

pub(crate) fn classify_zig(header: &str, raw: &str, scope: Scope) -> Option<Decl> {
    let exported = header.trim_start().starts_with("pub ");
    let rest = skip_modifiers(header.trim_start());
    if let Some(after) = rest.strip_prefix("fn ") {
        return Decl::new(
            ident(after.trim_start()),
            method_or_function(scope),
            exported,
        );
    }
    if keyword(rest, "test").is_some() && !scope.statement {
        let name = raw.split('"').nth(1).unwrap_or("test");
        return Decl::new(name, SymbolKind::Test, false);
    }
    let after = rest
        .strip_prefix("const ")
        .or_else(|| rest.strip_prefix("var "))?;
    let name = ident(after.trim_start());
    let value = after.split_once('=').map_or("", |(_, value)| value).trim();
    if value.starts_with("@import") {
        return None;
    }
    let value = value
        .trim_start_matches("extern ")
        .trim_start_matches("packed ");
    let kind = match ident(value) {
        "struct" | "union" => SymbolKind::Struct,
        "enum" => SymbolKind::Enum,
        "opaque" => SymbolKind::Type,
        _ if scope.statement && scope.top_level => SymbolKind::Const,
        _ => return None,
    };
    Decl::new(name, kind, exported)
}

fn method_or_function(scope: Scope) -> SymbolKind {
    if scope.in_type() {
        SymbolKind::Method
    } else {
        SymbolKind::Function
    }
}

/// Drop preprocessor lines, annotations, attributes and `template<...>`.
fn strip_preamble(header: &str, preprocessor: bool) -> &str {
    let mut text = header.trim_start();
    loop {
        if preprocessor && text.starts_with('#') {
            text = text
                .split_once('\n')
                .map_or("", |(_, rest)| rest)
                .trim_start();
        } else if let Some(rest) = text.strip_prefix('@') {
            let name = rest
                .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.'))
                .unwrap_or(rest.len());
            if &rest[..name] == "interface" {
                return text;
            }
            let after = rest[name..].trim_start();
            text = if after.starts_with('(') {
                skip_group(after, b'(', b')').trim_start()
            } else {
                after
            };
        } else if text.starts_with('[') {
            text = skip_group(text, b'[', b']').trim_start();
        } else if let Some(rest) = keyword(text, "template") {
            text = skip_group(rest.trim_start(), b'<', b'>').trim_start();
        } else {
            return text;
        }
    }
}

fn skip_modifiers(mut text: &str) -> &str {
    loop {
        let word_end = text
            .find(|c: char| !(c.is_alphanumeric() || c == '_'))
            .unwrap_or(text.len());
        let word = &text[..word_end];
        if word.is_empty() || !MODIFIERS.contains(&word) {
            return text;
        }
        let rest = &text[word_end..];
        if !rest.starts_with(char::is_whitespace) {
            return text;
        }
        text = rest.trim_start();
    }
}

fn type_decl(rest: &str, scope: Scope, exported: bool, kotlin: bool) -> Option<Decl> {
    let (word, after) = rest.split_once(char::is_whitespace)?;
    let mut after = after.trim_start();
    let kind = match word {
        "class" | "record" | "object" => SymbolKind::Class,
        "struct" | "union" => SymbolKind::Struct,
        "interface" | "@interface" | "trait" => SymbolKind::Interface,
        "namespace" => SymbolKind::Namespace,
        "enum" => {
            after = after
                .strip_prefix("class ")
                .or_else(|| after.strip_prefix("struct "))
                .unwrap_or(after)
                .trim_start();
            SymbolKind::Enum
        }
        _ => return None,
    };
    if scope.statement && !kotlin {
        return None;
    }
    let name = if kind == SymbolKind::Namespace {
        qualified(after)
    } else {
        ident(after)
    };
    Decl::new(name, kind, exported)
}

fn qualified(text: &str) -> &str {
    let end = text
        .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.' || c == ':'))
        .unwrap_or(text.len());
    &text[..end]
}

fn function(rest: &str, scope: Scope, exported: bool) -> Option<Decl> {
    let before = before_paren(rest)?.trim_end();
    if before.contains('=') && !before.contains("operator") {
        return None;
    }
    let mut tokens = before.split_whitespace();
    let last = tokens.next_back()?;
    let has_type = tokens.next().is_some();
    let qualified_member = last.contains("::");
    if !(has_type || qualified_member || scope.in_type()) {
        return None;
    }
    let tail = last
        .rsplit("::")
        .next()
        .unwrap_or(last)
        .rsplit('.')
        .next()
        .unwrap_or(last);
    let name = ident(tail.trim_start_matches(['*', '&', '~']));
    let reserved = NOT_NAMES.contains(&name) || CONTROL.contains(&name);
    if name.is_empty() || reserved || starts_with_control(before) {
        return None;
    }
    let kind = if scope.in_type() || qualified_member {
        SymbolKind::Method
    } else {
        SymbolKind::Function
    };
    Decl::new(name, kind, exported)
}

fn starts_with_control(before: &str) -> bool {
    before
        .split_whitespace()
        .next()
        .is_some_and(|first| CONTROL.contains(&first))
}
